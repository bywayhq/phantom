# Browser profiles and request templates

Choose the browser connection settings once, then choose the kind of request
you want to send. This guide shows how to use a built-in profile and switch
between navigation and fetch request templates.

For dependency setup and a complete first program, start with
[Getting started](crate::guide::getting_started).

## Start with a built-in profile

A composed profile groups the available settings for one browser and platform.
Use it instead of assembling TLS, HTTP, and client hints separately:

```rust,no_run
use phantom::{Client, profile::browser::chrome};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let profile = chrome::v154_windows()
    .with_request_template(chrome::v154_windows_navigation_template());
let client = Client::builder(profile).build()?;
# Ok(())
# }
```

The composed constructor selects connection settings and client hints. The
`with_request_template` call adds default browser request headers and their
order. The client prepares that template once and uses it for ordinary requests
unless an individual request overrides it.

The bare `chrome::v154_windows()` constructor leaves the ordinary request
template unset. Select one explicitly rather than assuming a connection profile
also chooses between navigation, fetch, and upload headers.

## Match the browser, version, and platform

The [browser modules](crate::profile::browser) group constructors by browser.
Keep the profile and template from the same browser, version, and platform.
Changing only `User-Agent` does not change TLS, HTTP settings, or client hints.

A profile's platform names the configuration it represents. Check the
constructor's API documentation for the included layers and any limitations:

- [Chrome on Windows](crate::profile::browser::chrome::v154_windows)
- [Chrome on Android](crate::profile::browser::chrome::v154_android)
- [Firefox on Windows](crate::profile::browser::firefox::v157_windows)

These profiles do not all cover the same layers. For example, the Chrome Android
profile leaves HTTP/1.1 connection policy and proxy CONNECT templates at generic
defaults. Its constructor documents those omissions. A browser version in a
function name is not a promise of complete browser behavior.

## Choose the request kind

A profile and a request template answer different questions:

| Setting | What it controls |
| --- | --- |
| [ClientProfile](crate::profile::ClientProfile) | Connection settings, client hints, and the default request template |
| [RequestTemplate](crate::profile::RequestTemplate) | Request fields, their placement, and any required caller values |
| [RequestHeader](crate::RequestHeader) | Values you supply for a particular request |

For Chrome on Windows, choose the template that matches your operation:

| Operation | Template |
| --- | --- |
| Address-bar navigation | [Navigation](crate::profile::browser::chrome::v154_windows_navigation_template) |
| Same-origin fetch GET | [Fetch](crate::profile::browser::chrome::v154_windows_fetch_template) |
| Same-origin fetch GET with `cache: "no-store"` | [No-store fetch](crate::profile::browser::chrome::v154_windows_fetch_no_store_template) |
| Same-origin fetch POST upload | [Fetch upload](crate::profile::browser::chrome::v154_windows_fetch_upload_template) |

A template describes request fields; it does not execute JavaScript or load a
page's resources. Fetch templates describe specific request contexts, not every
possible browser fetch. Read their API documentation before using one for a
different context.

## Override the template for one request

Keep navigation as the client default and prepare a fetch template for requests
that need it. Supply the page URL for the fetch template's `Referer` slot:

```rust,no_run
use phantom::{
    Client, HttpProtocol, PreparedRequestTemplate, RequestHeader,
    profile::browser::chrome,
};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let profile = chrome::v154_windows()
    .with_request_template(chrome::v154_windows_navigation_template());
let client = Client::builder(profile).build()?;
let fetch = PreparedRequestTemplate::new(chrome::v154_windows_fetch_template())?;

let response = client
    .get(HttpProtocol::Http2, "https://example.com/data.json")?
    .template(&fetch)
    .header(RequestHeader::new("referer", "https://example.com/"))
    .send()
    .await?;
println!("{}", response.status());
let _body = response.into_body().collect_with_limit(1 << 20).await?;
# Ok(())
# }
```

`HttpProtocol::Http2` requires HTTP/2; it does not fall back to another protocol.
Prepare a template once and reuse it. Calling `template` replaces the default
for that request, leaving other requests on the client unchanged.

Some templates support fewer protocols than the composed profile. A template
without HTTP/3 fields cannot be used for an exact HTTP/3 request. Missing required
caller values also produce a request error. See
[RequestBuilder::template](crate::RequestBuilder::template) for the checks.

## Change only what your request needs

Supply ordinary header values with [header](crate::RequestBuilder::header).
When a caller header matches a template entry, it keeps the template's position
and spelling but uses your value. Other caller headers follow the template.
Use this for values such as `Accept-Language` rather than rebuilding the entire
template. Keep identity headers consistent with the selected profile; Phantom
does not compare `User-Agent` and client-hint values for consistency.

To send one request without the client's default template, use
[without_template](crate::RequestBuilder::without_template). Automatic client
hints still follow the profile's settings. This is not a switch that disables
every header Phantom supplies.

For changes to connection behavior, start with a built-in profile and replace
only the relevant settings through methods such as
[with_http2](crate::profile::ClientProfile::with_http2). Use
[ClientProfile::new](crate::profile::ClientProfile::new) when you deliberately
want to assemble the configuration yourself. Changed protocol settings describe
your custom client; they no longer reproduce the unchanged built-in recipe.

## Import custom settings

Enable `fingerprint-import` to use `phantom::fingerprint`. You can edit complete
profiles as JSON or name them in a `ProfileRegistry`. For an Akamai HTTP/2 string,
use `import_akamai_profile` with an explicit base profile. The result lists fields
taken from the string and fields retained from your base. Compact descriptions
omit settings and do not establish an exact browser match.

Read [Making requests and handling responses](crate::guide::requests_and_responses)
for bodies, decoding, and errors, or [Using proxies](crate::guide::proxies) for
proxy routes. WebSocket openings and proxy CONNECT requests use their own
templates, separate from the default for ordinary requests.
