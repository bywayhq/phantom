# Request templates and client hints

Send the fields a browser sends for a request, in its order, and the client
hints it sends by default or on a server's request.

> For builders who have read [Browser profiles](profiles.md).

A profile shapes connections; the fields of each request, such as
`User-Agent`, come from a request template.

## Apply a captured request template

Send the fields a browser sends for one kind of request, in its order.
`PreparedRequestTemplate::new` validates a template once; pass the result to
`RequestBuilder::template` on each request.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, PreparedRequestTemplate, RequestHeader};

async fn navigate_then_fetch() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;
    // Prepare each template once and reuse it for every request.
    let navigation = PreparedRequestTemplate::new(chromium::v154_windows_navigation_template())?;
    let fetch = PreparedRequestTemplate::new(chromium::v154_windows_fetch_no_store_template())?;

    let page = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .template(&navigation)
        .send()
        .await?;
    page.into_body().collect_with_limit(1 << 20).await?;

    // `Referer` is a caller slot: its value is the page URL.
    let data = client
        .get(HttpProtocol::Http2, "https://example.com/data.json")?
        .template(&fetch)
        .header(RequestHeader::new("referer", "https://example.com/"))
        .send()
        .await?;
    println!("{}", data.status());
    Ok(())
}
```

- Each browser has two templates: an address-bar navigation and a
  same-origin `fetch(url, {cache: "no-store"})` GET
  ([template table](../reference/profiles.md#request-templates)).
- A field you add whose name matches a template entry takes that entry's
  position and keeps your value. Other fields follow the template's last
  field. A caller slot, such as `Referer` or Edge's `User-Agent`, sends
  nothing until you fill it
  ([assembly rules](../reference/profiles.md#template-assembly)).
- The Edge, Brave, and Opera templates require your `User-Agent`, and
  Brave's also require your `Accept-Language`; a request without one fails
  with `RequestErrorKind::RequestTemplate` before any I/O. Phantom does not
  compare your `User-Agent` or `sec-ch-ua` with the template, so use the
  template, client hints, and `User-Agent` of one browser and version
  ([required caller fields](../reference/profiles.md#required-caller-fields)).
- To a named `http://` origin, such as `http://example.com/`, the templates
  leave out the `Sec-Fetch-*` fields and send `Accept-Encoding: gzip,
  deflate`, as the browsers do. HTTPS, loopback, and `localhost` URLs get the
  full captured list ([origin trust](../reference/profiles.md#template-assembly)).

## Send client hints

Send the client hints a browser sends by default, and the ones a server asks
for.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol};

async fn with_hints() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;

    // Sends the default hints. An `Accept-CH` response adds to what the
    // next request to this origin sends.
    let first = client.get(HttpProtocol::Http2, "https://example.com/")?.send().await?;
    drop(first);

    // Forget every origin's requested hints.
    client.clear_client_hints();
    Ok(())
}
```

- `ClientHintSettings` fixes the hint names, their order, their values, and
  whether each is sent by default or only on request.
- Hints go only to a
  [potentially trustworthy](../reference/glossary.md#potentially-trustworthy)
  origin: HTTPS, or `http://` to a loopback address or `localhost`. A named
  `http://` origin gets none, as in Chrome.
- Such an origin's `Accept-CH` response sets the hints requested for its
  exact origin. On H2 and H3, a server can also request hints during the TLS
  handshake with ALPS `ACCEPT_CH`, for that connection only.
- If a `Critical-CH` response names a missing supported hint and the method
  is safe, Phantom retries once, on the same protocol and route. A streaming
  body cannot be retried and fails with `RequestErrorKind::RequestBody`.
- Clones of a client share learned hints; separately built clients do not.
  Rules for each case are in the
  [client-hint reference](../reference/profiles.md#client-hints).

## Limits

- Templates cover only address-bar navigations and same-origin no-store
  `fetch` GETs. Firefox templates have no HTTP/3 list and no hint slots
  ([template limits](../reference/profiles.md#template-limits)).
- A `fetch` or Firefox template refuses to send hints an origin requested,
  because no capture shows where they go
  ([Client hints in templates](../reference/profiles.md#client-hints-in-templates)).
- The client-hint model covers top-level requests from a standalone client
  ([model limits](../reference/profiles.md#client-hint-model-limits)).

## Next

- [Profile reference](../reference/profiles.md#request-templates): template
  and client-hint tables.
- [Cookies](cookies.md#place-the-cookie-field-where-a-browser-does): where
  the cookie field goes among the template's fields.
- [Troubleshooting](troubleshooting.md#a-request-template-rejects-the-request):
  template errors and their fixes.
