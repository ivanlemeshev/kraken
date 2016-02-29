package krakenapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// URL is a Kraken API URL
	URL = "https://api.kraken.com"
	// Version is a Kraken API version
	Version = "0"
)

var publicMethods = []string{
	"Time",
	"Assets",
	"AssetPairs",
	"Ticker",
	"OHLC",
	"Depth",
	"Trades",
	"Spread",
}

var privateMethods = []string{
	"Balance",
	"TradeBalance",
	"OpenOrders",
	"ClosedOrders",
	"QueryOrders",
	"TradesHistory",
	"QueryTrades",
	"OpenPositions",
	"Ledgers",
	"QueryLedgers",
	"TradeVolume",
	"AddOrder",
	"CancelOrder",
}

// APIClient struct represents Kraken API client
type APIClient struct {
	key    string
	secret string
	client *http.Client
}

// Response struct represents Kraken API response
type Response struct {
	Error  []string    `json:error`
	Result interface{} `json:result`
}

// New creates a new Kraken API struct
func New(key, secret string) *APIClient {
	krakenAPI := new(APIClient)
	krakenAPI.key = key
	krakenAPI.secret = secret
	krakenAPI.client = new(http.Client)
	return krakenAPI
}

// Query sends a query to Kraken API for given method and parameters
func (api *APIClient) Query(method string, data map[string]string) (interface{}, error) {
	values := url.Values{}
	for key, value := range data {
		values.Set(key, value)
	}
	if isStringInSlice(method, publicMethods) {
		return api.queryPublic(method, values)
	} else if isStringInSlice(method, privateMethods) {
		return api.queryPrivate(method, values)
	}
	return nil, fmt.Errorf("Method '%s' is not valid!", method)
}

// queryPublic executes a public method query
func (api *APIClient) queryPublic(method string, values url.Values) (interface{}, error) {
	url := fmt.Sprintf("%s/%s/public/%s", URL, Version, method)
	resp, err := api.doRequest(url, values, nil)
	return resp, err
}

// queryPrivate executes a private method query
func (api *APIClient) queryPrivate(method string, values url.Values) (interface{}, error) {
	urlPath := fmt.Sprintf("/%s/private/%s", Version, method)
	reqURL := fmt.Sprintf("%s%s", URL, urlPath)
	secret, _ := base64.StdEncoding.DecodeString(api.secret)
	values.Set("nonce", fmt.Sprintf("%d", time.Now().UnixNano()))
	signature := createSignature(urlPath, values, secret)
	headers := map[string]string{
		"API-Key":  api.key,
		"API-Sign": signature,
	}
	resp, err := api.doRequest(reqURL, values, headers)
	return resp, err
}

// doRequest executes a HTTP request to the Kraken API and returns the result
func (api *APIClient) doRequest(apiURL string, values url.Values, headers map[string]string) (interface{}, error) {
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, requestError(err.Error())
	}
	setHeaders(req, headers)
	resp, err := api.client.Do(req)
	if err != nil {
		return nil, requestError(err.Error())
	}
	defer resp.Body.Close()
	data, err := parseResponse(resp)
	if err != nil {
		return nil, requestError(err.Error())
	}
	if len(data.Error) > 0 {
		return nil, requestError(data.Error)
	}
	return data.Result, nil
}

// setHeaders sets request headers
func setHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		req.Header.Add(key, value)
	}
}

// parseResponse parses Kraken API response
func parseResponse(resp *http.Response) (Response, error) {
	var data Response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, err
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return data, err
	}
	return data, err
}

// requestError formats request error
func requestError(err interface{}) error {
	return fmt.Errorf("Could not execute request! (%s)", err)
}

// getSha256 creates a sha256 hash
func getSha256(input []byte) []byte {
	sha := sha256.New()
	sha.Write(input)
	return sha.Sum(nil)
}

// getHMacSha512 create a hmac hash with sha512
func getHMacSha512(message, secret []byte) []byte {
	mac := hmac.New(sha512.New, secret)
	mac.Write(message)
	return mac.Sum(nil)
}

// createSignature creates request signature
func createSignature(urlPath string, values url.Values, secret []byte) string {
	shaSum := getSha256([]byte(values.Get("nonce") + values.Encode()))
	macSum := getHMacSha512(append([]byte(urlPath), shaSum...), secret)
	return base64.StdEncoding.EncodeToString(macSum)
}

// isStringInSlice checks if given term is in a list of strings
func isStringInSlice(term string, list []string) bool {
	for _, found := range list {
		if term == found {
			return true
		}
	}
	return false
}
