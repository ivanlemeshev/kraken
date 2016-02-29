# Client for [Kraken API](https://www.kraken.com/help/api)

A simple Kraken API client.

Example of usage:

```go
package main

import (
    "fmt"
    "github.com/ivanlemeshev/kraken"
)

const (
    KrakenAPIKey = "KEY"
    KrakenAPISecret = "SECRET"
)

func main() {
    api := kraken.New(KrakenAPIKey, KrakenAPISecret)
    result, err := api.Query("Ticker", map[string]string{
        "pair": "XXBTZUSD",
    })

    if err != nil {
        fmt.Println("Error:", err.Error())
        return
    }

    fmt.Printf("Result: %+v\n", result)
}
```
