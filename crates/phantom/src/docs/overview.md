Send HTTP requests with browser connection settings and ordered headers.

Phantom lets you choose a browser profile for TLS, HTTP, and socket settings,
then reuse a [`Client`](crate::Client) across requests. It supports HTTP/1.1,
HTTP/2, and HTTP/3. Request templates select headers for tasks such as loading
a page or making a fetch request.

Phantom does not execute JavaScript or render pages. A profile configures
network behavior; it does not reproduce an entire browser or guarantee that
a server will accept a request.

## First request

```no_run
use phantom::{profile::browser::chrome, Client, HttpProtocol};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder(chrome::v154_windows()).build()?;
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .send()
        .await?;

    println!("{}", response.status());
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    println!("{} bytes", body.len());
    Ok(())
}
```

Run this in a Tokio runtime with I/O and timers enabled. For dependencies and
native build prerequisites, follow [Getting started](crate::guide::getting_started).

Reuse the client to share connection pools and session state. The example
selects HTTP/2 explicitly. Use [`Client::get_negotiated`](crate::Client::get_negotiated)
when the peer should select HTTP/1.1 or HTTP/2 through TLS negotiation.

For a direct server known to support cleartext HTTP/2, select
[`HttpProtocol::Http2`](crate::HttpProtocol::Http2) with an `http://` URL.
This sends the HTTP/2 preface immediately. It does not try HTTP/1.1 Upgrade
or fall back to HTTP/1.1. Negotiated cleartext requests keep using HTTP/1.1.

Built-in profile constructors leave request templates unset; see
[Browser profiles](crate::guide::browser_profiles) to add browser request headers.

Call [`Client::refresh_connections`](crate::Client::refresh_connections) to use
fresh connections for later requests while active work finishes. Clones share
the change. Tickets and session state stay available for the new connections.
[`close_idle_connections`](crate::Client::close_idle_connections) releases idle
connections while active work continues.

For caller-owned persistence, export and import
[cookies](crate::Client::export_cookies), [Alt-Svc](crate::Client::export_alt_svc),
or encrypted [TLS tickets](crate::Client::export_session_tickets). These are
separate snapshots; they do not restore a client's full configuration.
Cookie APIs require `cookies`; ticket snapshots and their keys must stay private.
With `session-snapshot`, [`Client::export_session`](crate::Client::export_session)
combines supported state into one encrypted checkpoint.
[`Client::restore_session`](crate::Client::restore_session) checks the receiving
configuration and returns a separate client.

## Guides

| Read | To |
| --- | --- |
| [Getting started](crate::guide::getting_started) | Install Phantom and send your first request |
| [Browser profiles](crate::guide::browser_profiles) | Choose a browser and apply request templates |
| [Requests and responses](crate::guide::requests_and_responses) | Send bodies, read responses, and handle errors |
| [Proxies](crate::guide::proxies) | Configure routing, authentication, and proxy DNS |

## API reference

- [`Client`](crate::Client) and [`ClientBuilder`](crate::ClientBuilder) hold
  shared connections and client policies.
- [`RequestBuilder`](crate::RequestBuilder) selects the request protocol,
  headers, body, and per-request settings.
- [`ResponseBody`](crate::ResponseBody), [`response_text`](crate::response_text),
  and [`ResponseInfo`](crate::ResponseInfo) provide body reads and response metadata.
- [`profile`](crate::profile) contains browser profiles and their settings.
- [`Route`](crate::Route) chooses a direct connection or proxy.
- [`RequestError`](crate::RequestError) and [`BuildError`](crate::BuildError)
  describe failures while preparing or sending requests.

## Cargo features

No optional feature is enabled by default. Add the features your application
uses to the `phantom` dependency in `Cargo.toml`.

| Feature | Adds |
| --- | --- |
| `charset` | Bounded response text decoding for supported character encodings |
| `cookies` | A client-owned cookie jar |
| `https-records` | HTTPS DNS records, encrypted DNS resolvers, HTTP/3 discovery and Encrypted Client Hello |
| `json` | Prepared JSON request bodies and bounded typed response reads |
| `sse` | Server-sent events and reconnect support |
| `websocket` | WebSocket connections |
| `websocket-deflate` | WebSocket compression; includes `websocket` |
| `serde` | Cookie snapshot serialization, when `cookies` is also enabled |
| `session-snapshot` | Encrypted state checkpoints and caller-owned async storage |
| `fingerprint-import` | Editable JSON profiles and partial TLS, QUIC and HTTP/2 imports |
| `full` | All features above |
| `diagnostics` | TLS key logs and QUIC qlog files; excluded from `full` |
| `danger-disable-verification` | Disabling certificate verification for tests; excluded from `full` |

TLS key logs contain secrets that decrypt traffic. Disabling certificate
verification lets a peer impersonate the server. Keep those features out of
normal application configurations.

These pages describe the version being viewed. For a Git or path dependency,
build the matching reference with `cargo doc -p phantom-http --features full --no-deps --open`.
