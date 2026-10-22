# sardanioss/http

A fork of `net/http` (via bogdanfinn/fhttp) with HTTP/1.1 and HTTP/2 fingerprinting support for evading bot detection systems.

## Why This Fork?

Modern anti-bot systems fingerprint HTTP connections by analyzing:
- Header order (both HTTP/1.1 and HTTP/2)
- Keep-Alive behavior and timing
- Connection reuse patterns
- Protocol selection behavior

This fork provides full control over these fingerprint vectors, making Go HTTP clients indistinguishable from real browsers.

## Installation

```bash
go get github.com/sardanioss/http
```

## Features

### HTTP/1.1 Header Ordering (from fhttp)

Control the order of headers using magic keys:

```go
import http "github.com/sardanioss/http"

req.Header = http.Header{
    "Accept":          {"*/*"},
    "User-Agent":      {"Mozilla/5.0..."},
    "Accept-Language": {"en-US,en;q=0.9"},
    http.HeaderOrderKey: {
        "accept",
        "user-agent",
        "accept-language",
    },
    http.PHeaderOrderKey: {
        ":method",
        ":authority",
        ":scheme",
        ":path",
    },
}
```

### Keep-Alive Pattern Control (NEW)

Emulate browser keep-alive behavior:

```go
transport := &http.Transport{
    // Use Chrome's keep-alive behavior (timeout=300)
    KeepAliveMode: http.KeepAliveModeChrome,

    // Or Firefox (timeout=115)
    KeepAliveMode: http.KeepAliveModeFirefox,

    // Or custom configuration
    KeepAliveMode:        http.KeepAliveModeCustom,
    KeepAliveTimeout:     300 * time.Second,
    KeepAliveMaxRequests: 100,
    SendKeepAliveHeader:  true,
}
```

Available modes:
| Mode | Description |
|------|-------------|
| `KeepAliveModeDefault` | Standard Go behavior |
| `KeepAliveModeChrome` | Chrome's keep-alive (timeout=300) |
| `KeepAliveModeFirefox` | Firefox's keep-alive (timeout=115) |
| `KeepAliveModeDisabled` | Disable keep-alive (Connection: close) |
| `KeepAliveModeCustom` | Custom timeout/max requests |

### Connection Reuse Control (NEW)

Control connection pooling behavior:

```go
transport := &http.Transport{
    // Use Chrome's connection reuse patterns
    ConnectionReuseMode: http.ConnectionReuseModeChrome,

    // Or Firefox
    ConnectionReuseMode: http.ConnectionReuseModeFirefox,

    // Advanced options
    ConnectionPrewarm: true,              // Pre-establish connections
    MaxConnectionAge:  5 * time.Minute,   // Limit connection lifetime
    ForceHTTP10:       false,             // Force HTTP/1.0
}
```

Available modes:
| Mode | Description |
|------|-------------|
| `ConnectionReuseModeDefault` | Standard Go connection pooling |
| `ConnectionReuseModeChrome` | Chrome's aggressive reuse (6 conns/host) |
| `ConnectionReuseModeFirefox` | Firefox's patterns (6 conns/host) |
| `ConnectionReuseModeSingle` | Single connection per request |
| `ConnectionReuseModeCustom` | Custom via MaxConnectionAge etc. |

### Helper Methods

```go
// Get keep-alive header value based on mode
header := transport.GetKeepAliveHeader() // e.g., "timeout=300"

// Get connection header value
conn := transport.GetConnectionHeader() // e.g., "keep-alive" or "close"

// Check if keep-alives are disabled
disabled := transport.ShouldDisableKeepAlives()

// Get effective idle connection timeout
timeout := transport.GetEffectiveIdleConnTimeout()

// Get effective max idle connections per host
maxConns := transport.GetEffectiveMaxIdleConnsPerHost()
```

## HTTP/2 Support

This package uses `github.com/sardanioss/net/http2` for HTTP/2, which provides:
- Custom SETTINGS frame order and values
- Custom WINDOW_UPDATE (connection flow)
- Custom pseudo-header order
- Header priority in HEADERS frame
- PRIORITY frames
- Stream priority tree
- HPACK indexing control

See [sardanioss/net](https://github.com/sardanioss/net) for HTTP/2 configuration.

## Full Example

```go
package main

import (
    "fmt"
    "time"
    http "github.com/sardanioss/http"
)

func main() {
    // Create transport with Chrome-like fingerprint
    transport := &http.Transport{
        // Keep-alive fingerprinting
        KeepAliveMode:       http.KeepAliveModeChrome,
        SendKeepAliveHeader: true,

        // Connection reuse fingerprinting
        ConnectionReuseMode: http.ConnectionReuseModeChrome,
        ConnectionPrewarm:   true,

        // Standard settings
        MaxIdleConns:        100,
        IdleConnTimeout:     90 * time.Second,
    }

    client := &http.Client{Transport: transport}

    // Create request with header ordering
    req, _ := http.NewRequest("GET", "https://example.com", nil)
    req.Header = http.Header{
        "Accept":          {"text/html,application/xhtml+xml"},
        "Accept-Language": {"en-US,en;q=0.9"},
        "User-Agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."},
        http.HeaderOrderKey: {
            "accept",
            "accept-language",
            "user-agent",
        },
    }

    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Println("Status:", resp.Status)
}
```

## API Reference

### Transport Fields

| Field | Type | Description |
|-------|------|-------------|
| `KeepAliveMode` | `KeepAliveMode` | Keep-alive behavior mode |
| `KeepAliveTimeout` | `time.Duration` | Custom keep-alive timeout |
| `KeepAliveMaxRequests` | `int` | Max requests per connection |
| `SendKeepAliveHeader` | `bool` | Explicitly send Keep-Alive header |
| `ConnectionReuseMode` | `ConnectionReuseMode` | Connection pooling mode |
| `ConnectionPrewarm` | `bool` | Pre-establish connections |
| `MaxConnectionAge` | `time.Duration` | Connection lifetime limit |
| `ForceHTTP10` | `bool` | Force HTTP/1.0 protocol |

### Magic Keys

| Key | Description |
|-----|-------------|
| `HeaderOrderKey` ("Header-Order:") | Order for HTTP/1.1 headers |
| `PHeaderOrderKey` ("PHeader-Order:") | Order for HTTP/2 pseudo-headers |

## Related Projects

- [sardanioss/net](https://github.com/sardanioss/net) - HTTP/2 fingerprinting
- [refraction-networking/utls](https://github.com/refraction-networking/utls) - TLS fingerprinting

## Credits

Based on [bogdanfinn/fhttp](https://github.com/bogdanfinn/fhttp) which forked net/http.

## License

BSD 3-Clause License (same as net/http)
