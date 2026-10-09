# Request templates and client hints

Send each request with the headers a browser would send, in the browser's
order, including its client hints.

A browser sends one list of headers when it loads a page and a different
list when a script calls `fetch`. A request template is one of those lists,
in the browser's order. Phantom ships templates for each browser, and you
pick one for each request. The profile sets how connections look. The
template sets the headers of each request, such as `User-Agent` and
`Accept`.

## Set a default template

Attach a template to your profile to use it for ordinary HTTP requests.
The client prepares it once when you build it.

```rust,no_run
use phantom::{Client, HttpProtocol};
use phantom::profile::browser::chrome;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let profile = chrome::v154_windows()
    .with_request_template(chrome::v154_windows_navigation_template());
let client = Client::builder(profile).build()?;
let response = client.get(HttpProtocol::Http2, "https://example.com/")?
    .send().await?;
let response_without_template = client
    .get(HttpProtocol::Http2, "https://example.com/")?
    .without_template()
    .send().await?;
# Ok(())
# }
```

`RequestBuilder::template` replaces the default for that request.
`without_template` disables it. Redirects keep the selected template and
still remove credentials when crossing origins. WebSocket openings use their
own profile settings.

## Apply a captured request template

Prepare a template once with `PreparedRequestTemplate::new`, then pass it to
`RequestBuilder::template` on each request.

```rust
use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{Client, HttpProtocol, PreparedRequestTemplate, RequestHeader};

async fn navigate_then_fetch() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_client_hints(chrome::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;
    // Prepare each template once and reuse it for every request.
    let navigation = PreparedRequestTemplate::new(chrome::v154_windows_navigation_template())?;
    let fetch = PreparedRequestTemplate::new(chrome::v154_windows_fetch_no_store_template())?;

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

Each browser has a template for a page load and one for
`fetch(url, {cache: "no-store"})`. Chrome and Firefox also have one for a
plain `fetch(url)`. The [template table](../reference/profiles.md#request-templates)
lists them all.

If you add a header that the template also has, yours takes the template's
place. Other headers you add go after the template's headers. Some template
entries, such as `Referer`, are empty slots. They send nothing until you
fill them, as the example does
([assembly rules](../reference/profiles.md#template-assembly)).

The Edge, Brave and Opera templates need your `User-Agent`, and Brave's
also need your `Accept-Language`. Phantom doesn't check that these match the
template, so take the template, client hints and `User-Agent` from the same
browser and version
([required caller fields](../reference/profiles.md#required-caller-fields)).

## Fill declared caller slots

For reusable caller-header changes, see
[base URLs and header hooks](request-customization.md).

Set the template before calling `fill_slots`. Fill only names the template
declares for every protocol the request may use.

```rust
use phantom::{Client, HttpProtocol, PreparedRequestTemplate, RequestHeader};

async fn fetch(
    client: &Client,
    template: &PreparedRequestTemplate,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.get(HttpProtocol::Http2, "https://example.com/data")?
        .template(template)
        .fill_slots(|slots| {
            slots.fill(RequestHeader::new("referer", "https://example.com/"))
        })?
        .send().await?;
    drop(response);
    Ok(())
}
```

Pass a fetch template with a `Referer` caller slot. The closure runs once
when you call `fill_slots`. Retries reuse its values. Cross-origin redirects
strip credentials without calling it again. You cannot replace literals,
fill a slot twice, or add an undeclared name through this hook.

Later template, route, and retry changes recheck whether each filled name
is still a caller slot on every possible protocol. Replacing all headers
with `headers` clears the recorded fills. See [request bodies](request-bodies.md)
for upload slots and prepared content types.

## Send client hints

Client hints are headers such as `sec-ch-ua` that tell a server about the
browser and the device. Send the hints a browser sends by default, and the
ones a server asks for.

```rust
use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{Client, HttpProtocol};

async fn with_hints() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_client_hints(chrome::v154_windows_client_hints());
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

`ClientHintSettings` holds the hint names, their order and values, and
which ones go out by default. When a site asks for more hints with
`Accept-CH`, Phantom sends them on later requests to that site. When a
`Critical-CH` response asks for a missing hint, Phantom retries safe
methods such as GET once with it. Clones of a client share what sites asked for. The
[client-hint reference](../reference/profiles.md#client-hints) has the full
rules.

Hints go only to HTTPS sites and to `localhost` and loopback addresses. An
`http://` host name gets none, as in Chrome.

## Limits

- Templates cover page loads, same-origin `fetch` GETs, and Windows Chrome
  and Firefox upload POSTs over HTTP/1.1 and HTTP/2
  ([template limits](../reference/profiles.md#template-limits)).
- Firefox and `fetch` templates have no place for hints a site asked for,
  so such a request fails
  ([Client hints in templates](../reference/profiles.md#client-hints-in-templates)).
- Client hints follow the rules for top-level requests from one standalone
  client ([model limits](../reference/profiles.md#client-hint-model-limits)).

## Next

- [Profile reference](../reference/profiles.md#request-templates): template
  and client-hint tables.
- [Cookies](cookies.md#place-the-cookie-field-where-a-browser-does): where
  the cookie header goes among the template's headers.
- [Troubleshooting](troubleshooting.md#a-request-template-rejects-the-request):
  template errors and their fixes.
