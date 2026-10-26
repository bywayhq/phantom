# Browser profiles and request templates

Choose the browser connection settings once, then choose the kind of request
you want to send. This guide shows how to use a built-in profile and switch
between navigation and fetch request templates.

For dependency setup and a complete first program, start with
[Getting started](crate::guide::getting_started).

## Start with a built-in profile

Select the browser and request kind together:

```rust,no_run
use phantom::{Client, profile::catalog::{profile_for, RequestTemplateKind}};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
let client = Client::builder(profile).build()?;
# Ok(())
# }
```

The client prepares the selected headers once and uses them for later requests.
Choose navigation, fetch, or upload for your operation. Individual requests can
override the template.

Composed constructors such as `chrome::v156_windows()` select connection settings
without request headers. Use `with_request_template` when assembling your own
combination.

For selection by name, use [`catalog::profile`](crate::profile::catalog::profile):

```rust
let definition = phantom::profile::catalog::profile("chrome-154-windows")?;
assert_eq!(definition.metadata().build(), Some("154.0.8037.97"));
# Ok::<(), phantom::profile::catalog::CatalogError>(())
```

Short selectors have fixed mappings. The definition's `id()` retains its full
build, platform and revision; full identifiers remain accepted too.

`chrome-155-linux` adapts a pinned external preset for TLS, HTTP/2 and
navigation headers. Its catalog definition lists the available layers.

`chrome-156-linux` provides Chrome 156.0.8078.47 TLS, HTTP/2, HTTP/3, client
hints and request templates from headed Ubuntu 24.04.4 captures on WSL2/WSLg
x86_64. Select it with `chrome::v156_linux()` or the catalog.

`chrome-156-macos` and `chrome-156-macos-intel` provide Chrome 156.0.8078.48
startup settings, client hints and request templates for hosted macOS 26.6.2
arm64 and macOS 15.7.9 x86_64. Their constructors are `chrome::v156_macos()`
and `chrome::v156_macos_intel()`.

## Match the browser, version, and platform

The [browser modules](crate::profile::browser) group constructors by browser.
Keep the profile and template from the same browser, version, and platform.
Changing only `User-Agent` does not change TLS, HTTP settings, or client hints.

A profile's platform names the configuration it represents. Check the
constructor's API documentation for the included layers and any limitations:

- [Chrome on Windows](crate::profile::browser::chrome::v154_windows)
- [Chrome on macOS](crate::profile::browser::chrome::v154_macos)
- [Chrome on Android](crate::profile::browser::chrome::v154_android)
- [Firefox on Windows](crate::profile::browser::firefox::v157_windows)

These profiles do not all cover the same layers. For example, the Chrome Android
profile leaves HTTP/1.1 connection policy and proxy CONNECT templates at generic
defaults. Its constructor documents those omissions.

Built-in profiles leave TCP source-port selection to Windows. Chromium's
randomization option can stall connections under churn. You can explicitly
enable it through [`TcpSettings::port_randomization`](crate::profile::TcpSettings::port_randomization).

With Alt-Svc enabled, Firefox recipes validate advertised HTTP/3 alternatives
in the background. Validation opens a connection without sending a request.
Later requests select the alternative after validation succeeds.

Firefox recipes share eligible HTTP/3 connections across HTTPS origins. They
retry replayable requests after a first-attempt 421 response. Exact HTTP/3
requests keep their selected protocol and endpoint. See
[`Http3MisdirectedRequest`](crate::profile::Http3MisdirectedRequest) for the policy.

## Tune concurrency

The Chrome Windows recipe allows six HTTP/1.1 connections per origin.
Override this when your workload needs more:

```rust,no_run
use std::num::NonZeroUsize;
use phantom::{Client, profile::browser::chrome};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder(chrome::v154_windows())
    .max_concurrent_http1_requests_per_origin(NonZeroUsize::new(32).ok_or("zero limit")?)
    .build()?;
# Ok(())
# }
```

This changes concurrency without changing TLS settings or request headers.
HTTP/2 and HTTP/3 multiplex requests. Their request and connection limits have
separate controls on [`ClientBuilder`](crate::ClientBuilder).

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

Templates supply request fields. Choose one for the request context documented
in its API reference.

The Chrome 156 recipes also offer `Script`, `Stylesheet`, `Image` and `Font`
through [`RequestTemplateKind`](crate::profile::catalog::RequestTemplateKind).
These same-origin templates require a caller-supplied `Referer`. Fonts also
require `Origin`, with the stylesheet URL as `Referer`.

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
    .get_with_protocol(HttpProtocol::Http2, "https://example.com/data.json")?
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
and spelling but uses your value. Other caller headers follow the template,
except `Cookie`: caller cookies follow the profile's per-protocol
[CookiePlacement](crate::profile::CookiePlacement), as jar cookies do.
Use this for values such as `Accept-Language` rather than rebuilding the entire
template. Keep identity headers consistent with the selected profile; Phantom
does not compare `User-Agent` and client-hint values for consistency.

To send one request without the client's default template, use
[without_template](crate::RequestBuilder::without_template). Automatic client
hints still follow the profile's settings.

For changes to connection behavior, start with a built-in profile and replace
only the relevant settings through methods such as
[with_http2](crate::profile::ClientProfile::with_http2). Use
[ClientProfile::new](crate::profile::ClientProfile::new) when you deliberately
want to assemble the configuration yourself.

## Import custom settings

Enable `fingerprint-import` to use [`fingerprint`](crate::fingerprint).
[`describe_profile`](crate::fingerprint::describe_profile) returns editable JSON;
[`export_profile_json`](crate::fingerprint::export_profile_json) returns its bytes.
Edit them and call [`import_profile_json`](crate::fingerprint::import_profile_json)
to restore supported settings and ordering. A
[`ProfileRegistry`](crate::fingerprint::ProfileRegistry) assigns your own names.
Exports include literal header values, so keep documents containing credentials
private. For partial observations, supply a complete base for missing settings:

| Input | Import function |
| --- | --- |
| Raw JA3 string | `import_ja3_profile` |
| Raw JA4_r or JA4_ro | `import_ja4_profile`, with an explicit ordering format |
| TCP ClientHello handshake bytes | `import_client_hello_profile` |
| QUIC transport-parameter payload | `import_quic_transport_profile` |
| Akamai HTTP/2 string | `import_akamai_profile` |

Inspect `ImportedProfile::observed_fields` and `supplemented_fields` before
using the result. JA3 and JA4 hashes cannot recover settings. Sorted JA4 needs
the base's cipher and extension order. ClientHello input excludes TLS record
headers; QUIC input excludes the extension header. Unsupported fields produce
an error with a field path.

TLS imports check their supported fields against a fresh ClientHello generated
in memory. Resumption, destination type and protocol-specific ALPN can change
later handshakes. Imports create custom settings without a browser identity.

## Load an offline bundle

[`ProfileBundle`](crate::fingerprint::ProfileBundle) validates a versioned JSON
bundle before exposing its exact-name registry. Enable `fingerprint-import`,
then load bytes from your own storage:

```rust,no_run
use phantom::{Client, fingerprint::ProfileBundle};
# fn example(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
let bundle = ProfileBundle::from_json(bytes)?;
let settings = bundle.profiles().get("custom/chrome").ok_or("profile absent")?;
let client = Client::builder(settings.clone()).build()?;
# drop(client);
# Ok(())
# }
```

Pin `bundle.sha256()` to identify its exact bytes, including whitespace.
Revision labels and publisher references are unauthenticated metadata.
Entries contain one selected request template.
Loading a different bundle never changes an existing client. The CLI can install
bundle files and select older digests for offline rollback.

Read [Making requests and handling responses](crate::guide::requests_and_responses)
for bodies, decoding, and errors, or [Using proxies](crate::guide::proxies) for
proxy routes. WebSocket openings and proxy CONNECT requests use their own
templates, separate from the default for ordinary requests.
