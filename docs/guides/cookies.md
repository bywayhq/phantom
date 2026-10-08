# Cookies

Keep cookies between requests, save them to your own storage, and send them
where a browser puts them among the headers. Cookies need the `cookies`
Cargo feature.

## Keep cookies between requests

Turn on the cookie jar. Phantom then stores the cookies that responses set
and sends them back on later requests.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol};

async fn with_cookies() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_cookie_placement(chromium::v154_cookie_placement());
    let client = Client::builder(profile).cookies().build()?;

    if let Some(jar) = client.cookie_jar() {
        jar.set_cookie("https://example.com/", "session=abc; Secure; HttpOnly")?;
    }
    // Sends the cookie, and stores any `Set-Cookie` from the response.
    let response = client.get(HttpProtocol::Http2, "https://example.com/account")?.send().await?;
    drop(response);
    Ok(())
}
```

`ClientBuilder::cookies` turns on an in-memory jar with default size limits.
For other limits, build one with `CookieJar::with_limits` and pass it to
`ClientBuilder::cookie_jar`. `Client::cookie_jar` gives you the jar, so you
can add, read and clear cookies yourself.

The jar follows the browser rules for domain, path, expiry, `Secure`,
`SameSite` and cookie prefixes. [Cookie jar rules](../reference/cookies.md)
has the details.

If you set your own `Cookie` header, Phantom sends yours instead of the
jar's. Cookies from the response still go into the jar.

## Save and restore cookies

Export a client's cookies to copy them into another client or to save them,
and import them later. An export is a `CookieSnapshot`: a list of cookies
with their values and attributes.

```rust
use phantom::{Client, CookieSnapshot, CookieSnapshotEntry, CookieSnapshotError, CookieSourceScheme};

fn copy_cookies(from: &Client, to: &Client) -> Result<(), CookieSnapshotError> {
    // `None` means `from` was built without a cookie jar.
    if let Some(snapshot) = from.export_cookies() {
        to.import_cookies(&snapshot)?;
    }
    Ok(())
}

fn restore_session(client: &Client, value: &str) -> Result<(), CookieSnapshotError> {
    // A cookie your storage kept, as a response from https://example.com set it.
    let entry =
        CookieSnapshotEntry::new(CookieSourceScheme::Https, "session", value, "example.com", "/")
            .with_secure(true)
            .with_http_only(true);
    client.import_cookies(&CookieSnapshot::new(vec![entry]))
}
```

Phantom doesn't pick a file format. Save each `CookieSnapshotEntry`'s values
yourself, or turn on the `serde` feature and serialize the whole snapshot.
Importing adds to what the jar already holds
([merge rules](../reference/cookies.md#merge-rules)).

A snapshot holds cookie values, and these are often login sessions. Store it
as you would a password.

## Place the cookie field where a browser does

Browsers put the `Cookie` header at a fixed spot among the other headers.
The profile's `CookiePlacement` puts the jar's cookies at that same spot.
The first example on this page sets it with `with_cookie_placement`.

By default the header goes last. The browser recipes (the settings Phantom
ships for each browser) put it before the first of these headers that the
request has:

| Recipe | Goes before |
| --- | --- |
| `chromium::v154_cookie_placement` | `priority` |
| `firefox::v157_cookie_placement` | `Upgrade-Insecure-Requests`, `Sec-Fetch-*`, `Priority`, `Pragma`, `Cache-Control`, `te` |

The placement works with your own headers and with a
[request template's](request-templates.md#apply-a-captured-request-template)
headers. On HTTP/2 and HTTP/3, the recipes also split the header into one
`cookie` header per cookie, as the browsers do
([Cookie crumbs](../reference/profiles.md#cookie-crumbs)).

A WebSocket handshake ignores the placement. It puts the jar's cookies at
the `client_cookies` slot of its own template.

## Limits

- The jar treats every request as a page the user opened from the address
  bar. To send what a cross-site request would, set your own `Cookie`
  header.
- On HTTP/2 and HTTP/3, the split cookie headers go into the compression
  table, as in the browsers. Someone who can add headers to your requests
  and watch their size could use this to guess a cookie value.
  `RequestHeader::sensitive` doesn't change it. Set `cookie_crumbs` to
  `Whole` in the profile to avoid it, at the cost of looking less like the
  browser ([why](../explanation/design.md#cookie-crumbs-and-compression)).
- When the jar is full, it drops the least recently used cookies.

## Next

- [Cookie jar rules](../reference/cookies.md): what the jar stores, sends
  and refuses.
- [Defaults and limits](../reference/limits.md#cookies): the jar's size
  limits.
