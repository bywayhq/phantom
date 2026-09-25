# Cookies

Keep cookies between requests, move them through storage you own, and place
the cookie field where a browser does. You need the optional `cookies`
feature.

> For builders who have read [Connections and client state](connections-and-state.md).

## Keep cookies between requests

Store `Set-Cookie` responses and send matching cookies on later requests,
with the `cookies` Cargo feature.

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

- `ClientBuilder::cookies` enables a bounded in-memory jar;
  `ClientBuilder::cookie_jar` installs one you built, for example with
  `CookieJar::with_limits`. `Client::cookie_jar` returns the active jar, and
  its `set_cookie`, `request_value`, `clear`, and `len` act on the state
  requests use.
- The jar applies domain, path, expiry, `Secure`, `HttpOnly`, public-suffix,
  `__Secure-` and `__Host-` prefix, `SameSite`, and `Partitioned` rules, with
  deterministic ordering ([rules](../reference/cookies.md)).
- A `Cookie` field you supply keeps its own position and suppresses the
  jar's field; the response still updates the jar.
- `Client::export_cookies` and `Client::import_cookies` move the jar through
  storage you own ([next task](#save-and-restore-cookies)).

## Save and restore cookies

Copy a client's cookies into another client, or rebuild them from your own
storage, with a [snapshot](../reference/glossary.md#snapshot) (`CookieSnapshot`).

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

- An export holds the jar's unexpired cookies in creation order, session
  cookies included. Phantom picks no file format: persist each
  `CookieSnapshotEntry`'s accessor values, or enable the `serde` Cargo
  feature to serialize the snapshot.
- A snapshot holds cookie values, which are often session credentials. Store
  it as you would a password.
- Import checks each entry as the `Set-Cookie` field a response from its
  scheme and domain would send. One refused entry rejects the whole snapshot
  and leaves the jar unchanged; `CookieSnapshotError::entry_index` names it.
- Import merges with what the jar holds
  ([merge rules](../reference/cookies.md#merge-rules)).

## Place the cookie field where a browser does

Put the jar's cookie field at the position a browser uses, with the profile's
`CookiePlacement`.

The field is named `Cookie` on HTTP/1.1 and `cookie` on H2 and H3. By default
it goes last. `CookiePlacement::before_fields` names the fields it precedes:
it goes before the first of them present, or last if none is. It positions
the field among your fields or a
[request template's](request-templates.md#apply-a-captured-request-template) fields.

| Recipe | Goes before |
| --- | --- |
| `chromium::v154_cookie_placement` | `priority` |
| `firefox::v156_cookie_placement` | `Upgrade-Insecure-Requests`, `Sec-Fetch-*`, `Priority`, `Pragma`, `Cache-Control`, `te` |

- The H1 positions match Chrome 154 and Firefox 156 EventSource reconnect
  captures. No retained H2 or H3 capture carries a cookie; those positions
  come from browser source ([Coverage](../reference/coverage.md#browser-profiles)).
- Chrome's H2 and H3 encoders and Firefox's H2 encoder split `cookie` into
  one field per cookie (quiche `HpackEncoder::CookieToCrumbs` and
  `ValueSplittingHeaderList`, Firefox `Http2Compressor`). Phantom sends one
  field.
- WebSocket openings ignore the placement. They put the jar's value at the
  template's `client_cookies` placeholder (`WebSocketField::client_cookies`
  in a profile, `WebSocketHeader::client_cookies` in a caller template), and
  send no jar cookie without one.


## Limits

- The jar treats every request and redirect hop as a user-initiated
  top-level navigation and ignores the fields you send. To emulate a
  cross-site request, supply your own `Cookie` field.
- The jar rejects insecure `SameSite=None` and `Partitioned` cookies, and
  `Secure` or prefixed cookies from an origin that is not potentially
  trustworthy. Over its count limits it evicts the least recently used
  cookies. The full rules are in [Cookie jar rules](../reference/cookies.md).

## Next

- [Cookie jar rules](../reference/cookies.md): what the jar stores, sends,
  rejects, and evicts.
- [Browser profiles](profiles.md): the request templates the cookie field is
  placed among.
- [Defaults and limits](../reference/limits.md): cookie bounds.
