# Making requests and handling responses

Use the [`Client`](crate::Client) from [Getting started](crate::guide::getting_started)
for the examples below. Keep it for later requests so they can share connections.

Cloning a client shares its connections and shutdown. Use
[`Client::fork`](crate::Client::fork) for independent pools with the same settings.
Select live cookies, DNS, client hints, discovery caches or TLS tickets with
[`SessionSharing`](crate::SessionSharing). Unselected state and learned proxy
authentication start empty. Shared caches reflect later changes
and clearing in both directions; a fork does not enable disabled features.
Shared tickets are consumed once across the independent pools. See
[`SessionSharing::tickets`](crate::SessionSharing::tickets) for retention and
portable export limits while older connections remain active.

With `session-snapshot`, use [`Client::export_session`](crate::Client::export_session)
to save supported cookies, direct-route Alt-Svc entries and TLS tickets together.
HTTPS discovery also saves completed answers and ECH when you set
[`https_record_checkpoint_namespace`](crate::ClientBuilder::https_record_checkpoint_namespace).
Use the same namespace only for equivalent resolver policies and network scopes.
Paired native resolver configurations cannot be restored this way.
Keep its secret key separately. [`Client::restore_session`](crate::Client::restore_session)
returns a new client with independent pools and checks the receiving configuration.
See the API for supported routes, size limits and state that is not saved.

For async storage, implement [`SessionStore`](crate::SessionStore) and call
[`Client::save_session`](crate::Client::save_session) or
[`Client::load_session`](crate::Client::load_session) with a name and deadline.
Storage receives encrypted bytes only. Loading returns a separate client, or
`None` for a missing name. Cancellation cannot undo an external write.

## Add query parameters and headers

[`query_pairs`](crate::RequestBuilder::query_pairs) encodes names and values and
appends them to the URL's query. Repeated names keep their order.
[`ClientBuilder::base_url`](crate::ClientBuilder::base_url) enables relative URLs:
`https://example.com/api/` plus `users` gives `/api/users`; `/users` starts at the
origin root. Absolute URLs override the base, so it is not an origin restriction.

```no_run
# async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
use phantom::{HttpProtocol, RequestHeader};

let response = client
    .get(HttpProtocol::Http2, "https://example.com/search")?
    .query_pairs([("q", "rust http"), ("tag", "client"), ("tag", "async")])?
    .header(RequestHeader::new("accept", "application/json"))
    .send()
    .await?;
let response = phantom::response_bytes(response, 1 << 20).await?;
println!("{}: {} bytes", response.status(), response.body().len());
# Ok(())
# }
```

Without a request template, ordinary headers keep the order you add them.
Caller cookies follow the profile's per-protocol cookie placement.
Supply application headers here;
use [Browser profiles](crate::guide::browser_profiles) for browser templates and
client hints. Phantom derives `Host` from the URL, so do not add it yourself.

To reuse a saved HTTP/1.1 request, call
[`Client::request_from_http1`](crate::Client::request_from_http1) with its absolute
destination and a byte limit. It checks the target, `Host` and body framing,
then returns the same request builder. Templates and cookie placement still
apply; this imports a request rather than replaying its original wire bytes.

## Custom connections

Use [`ClientBuilder::tcp_connector`](crate::ClientBuilder::tcp_connector) when
an application opens its own streams. On Unix,
[`TcpConnector::unix_socket`](crate::TcpConnector) connects through a socket
path. Keep an ordinary HTTP or HTTPS request URL: its authority and TLS server
name remain unchanged. The connector owns DNS and socket configuration.
Custom connectors support direct HTTP/1.1, HTTP/2 and TLS protocol negotiation.
Proxy routes, HTTP/3 and discovery options cannot use these streams.

## Send a body

Use [`Client::request`](crate::Client::request) to select a method other than GET.
For form data, prepare bounded bytes and place their `Content-Type` header:

```no_run
# async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
use phantom::{HttpProtocol, Method, PreparedRequestBody, RequestHeader};

let body = PreparedRequestBody::form([("name", "Ada"), ("topic", "Rust")], 4096)?;
let response = client
    .request(HttpProtocol::Http2, Method::POST, "https://example.com/messages")?
    .header(RequestHeader::new("content-type", body.content_type()))
    .prepared_body(body)
    .send()
    .await?;
let response = phantom::response_bytes(response, 1 << 20).await?;
println!("{}", response.status());
# Ok(())
# }
```

With the `json` feature, `PreparedRequestBody::json(&value, maximum_bytes)`
prepares a JSON upload in the same way. The value must implement
`serde::Serialize`. Keep the matching `Content-Type` header in your chosen
position; a prepared body does not insert it at an arbitrary position.

For existing bytes, use [`RequestBuilder::body`](crate::RequestBuilder::body) and
set their content type yourself. To upload files without collecting them, use
[`StreamingMultipartBody`](crate::StreamingMultipartBody) and
[`RequestBuilder::multipart_body`](crate::RequestBuilder::multipart_body).
Supply a boundary and an encoded-byte limit. The body streams readers in order
and cannot be resent. For other streaming bodies, use
[`RequestBuilder::streaming_body`](crate::RequestBuilder::streaming_body).

## Check the status

A completed request can return `404` or `500`. These are HTTP responses, so
[`send`](crate::RequestBuilder::send) returns them as `Ok(response)`. A connection
failure, timeout, or unsupported route returns a [`RequestError`](crate::RequestError).

Inspect `response.status()` and `response.headers()` before consuming the body.
To treat 4xx and 5xx responses as errors, pass the response through
[`error_for_status`](crate::error_for_status). Its [`StatusError`](crate::StatusError)
retains the unread response, so you can recover it with `into_response()` and
read a bounded error body.

## Read bytes, text, or JSON

[`response_bytes`](crate::response_bytes) collects a bounded body while retaining
its status, headers, and other metadata. [`response_text`](crate::response_text)
does the same and requires valid UTF-8; it does not select a charset from headers.
Enable `charset` and use
[`response_text_with_charset`](crate::response_text_with_charset) for declared
charsets and Unicode byte-order marks. Set separate input and UTF-8 output limits.

```no_run
# async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
let response = client
    .get(phantom::HttpProtocol::Http2, "https://example.com/")?
    .send().await?;
let response = phantom::error_for_status(response)?;
let response = phantom::response_text(response, 1 << 20).await?;
println!("{}", response.body());
# Ok(())
# }
```

Enable `json` in your dependency to read a typed response:

```toml
phantom = { package = "phantom-http", version = "0.3", features = ["json"] }
```

For an endpoint that accepts and returns a JSON array of strings:

```no_run
# #[cfg(feature = "json")]
# async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
use phantom::{HttpProtocol, Method, PreparedRequestBody, RequestHeader};

let body = PreparedRequestBody::json(&["Ada", "Grace"], 4096)?;
let response = client
    .request(HttpProtocol::Http2, Method::POST, "https://example.com/names")?
    .header(RequestHeader::new("content-type", body.content_type()))
    .prepared_body(body)
    .send().await?;
let response = phantom::error_for_status(response)?;
let response = phantom::response_json::<Vec<String>>(response, 1 << 20).await?;
println!("{} names", response.body().len());
# Ok(())
# }
```

Choose an output type that implements `serde::de::DeserializeOwned`; add `serde` with its
`derive` feature to your own dependencies when defining a response struct.
The byte limit bounds the JSON input, not allocations made by deserialization.
Body, UTF-8, and JSON failures return a [`ResponseReadError`](crate::ResponseReadError)
with the original response metadata. Read errors can occur after headers arrive.

Enable `xml` and use [`response_xml`](crate::response_xml) for typed UTF-8 XML.
It accepts one document, rejects DOCTYPE declarations, and limits nesting to
128 levels. The XML declaration must name UTF-8 if it names an encoding.
The input cap does not bound deserializer allocations. Parsing is synchronous
after the bounded body read; cancellation cannot interrupt that parsing.

Content decoding is off by default. To read a compressed response, advertise its
codings with `Accept-Encoding` and enable
[`ContentDecoding::advertised`](crate::ContentDecoding::advertised). Collection
limits then count decoded bytes. The decoder also has its own decoded-byte cap.

## Stream a response

For a large download, process data frames as they arrive. Add
`http-body-util = "0.1"` to your dependencies for its `BodyExt` extension trait.
This example processes data frames without collecting the entire response and stops if
the data exceeds 8 MiB:

```no_run
# async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
use http_body_util::BodyExt;

let response = client
    .get(phantom::HttpProtocol::Http2, "https://example.com/download")?
    .send().await?;
let mut body = phantom::error_for_status(response)?.into_body();
let mut remaining = 8 * 1024 * 1024;
while let Some(frame) = body.frame().await {
    if let Ok(data) = frame?.into_data() {
        if data.len() > remaining {
            return Err("download exceeded 8 MiB".into());
        }
        remaining -= data.len();
        println!("received {} bytes", data.len());
    }
}
# Ok(())
# }
```

A body is consumed once. After streaming it, you cannot collect or decode it
again. Reading to the end helps connection reuse; stopping early drops the body
and lets the protocol cancel the remaining transfer.

## Set policies for your application

Request timeouts are off by default. Set a total deadline when building the
client; it includes attempts, retry delays, and the final body read:

```no_run
use std::time::Duration;
use phantom::{Client, RequestTimeouts, profile::browser::chrome};

# fn example() -> Result<(), phantom::BuildError> {
let client = Client::builder(chrome::v154_windows())
    .request_timeouts(RequestTimeouts::new().total(Duration::from_secs(30)))
    .build()?;
# let _ = client;
# Ok(())
# }
```

[`RequestTimeouts`](crate::RequestTimeouts) also provides phase limits. A timeout
is a `RequestError` with kind [`Timeout`](crate::RequestErrorKind::Timeout);
[`timeout_phase`](crate::RequestError::timeout_phase) tells you which limit expired.
Use [`RequestBuilder::timeouts`](crate::RequestBuilder::timeouts) for overrides.
Response read helpers wrap a body timeout in `ResponseReadError`; use
[`request_error`](crate::ResponseReadError::request_error) to inspect its
underlying request error and timeout phase.
Dropping a pending send or body-read future cancels that operation; it cannot
undo a request the server already received.

Enable only the behavior you need:

- **Redirects:** [`ClientBuilder::redirect_policy`](crate::ClientBuilder::redirect_policy)
  with [`RedirectPolicy::limited`](crate::RedirectPolicy::limited).
  Override one request with
  [`RequestBuilder::redirect_policy`](crate::RequestBuilder::redirect_policy).
  Use `RedirectPolicy::none()` to inspect its redirect response yourself.
  [`RedirectPolicy::custom`](crate::RedirectPolicy::custom) lets you follow,
  stop or reject each resolved URL while retaining a hop limit.
  Enable [`RequestBuilder::redirect_history`](crate::RequestBuilder::redirect_history)
  to keep a bounded list of hops in the final response's extensions.
- **Cookies:** enable the `cookies` feature and call `ClientBuilder::cookies()`.
  The jar is shared by requests and client clones.
- **Extra retries:** [`ClientBuilder::retry_policy`](crate::ClientBuilder::retry_policy).
  Read [`RetryPolicy`](crate::RetryPolicy) before retrying operations with side effects;
  some protocol-driven replays can occur even without an extra retry policy.
  Configure capped exponential delays and full jitter on `RetryPolicy` for
  connection-setup retries, or on [`StatusRetry`](crate::StatusRetry) for
  status retries. An honored `Retry-After` sets a minimum wait. Delays remain
  inside the total deadline and existing retry budgets.
- **Shared attempt allowance:** attach the same
  [`HttpAttemptBudget`](crate::HttpAttemptBudget) to requests with
  [`attempt_budget`](crate::RequestBuilder::attempt_budget). Initial attempts,
  redirects and internal resends spend it atomically. Exhaustion returns
  [`AttemptBudgetExhausted`](crate::RequestErrorKind::AttemptBudgetExhausted)
  before another send. An admitted attempt can fail before sending bytes and
  is not refunded. DNS, TLS and proxy setup keep their separate limits.
- **Proxy routes:** follow [Using proxies](crate::guide::proxies).

## Observe requests and response heads

Implement [`RequestHooks`](crate::RequestHooks) and pass it to
[`ClientBuilder::request_hooks`](crate::ClientBuilder::request_hooks) or
[`RequestBuilder::request_hooks`](crate::RequestBuilder::request_hooks).
Client callbacks run first, then request callbacks.

```
use phantom::{RequestHooks, ResponseHookContext};

struct LogStatus;
impl RequestHooks for LogStatus {
    fn on_response(&self, response: &ResponseHookContext<'_>) {
        println!("{}", response.status());
    }
}
```

Each logical request gets one start callback and a final response-head or
send-error callback. Redirects and retries do not repeat them. Callbacks borrow
metadata and leave bodies with you. Later body errors and cancelled sends have
no terminal callback; use the timeline below to observe those outcomes.
Use [`header_hook`](crate::RequestBuilder::header_hook) to change caller headers.

## Inspect a request timeline

Use [`RequestBuilder::transfer_control`](crate::RequestBuilder::transfer_control)
for shared body-byte caps, upload/download pacing and counters. Its counters
separate reservations, encoded body data and decoded output. They include
resends and exclude headers and transport overhead.

Call [`RequestBuilder::diagnostics`](crate::RequestBuilder::diagnostics) before
`send` to collect a bounded timeline. This API needs no optional feature.
Keep its [`RequestDiagnostics`](crate::RequestDiagnostics) handle to inspect
failures, cancellation, and body completion:

```no_run
# async fn example(client: &phantom::Client) -> Result<(), phantom::RequestError> {
use std::num::NonZeroUsize;

let mut request = client.get(phantom::HttpProtocol::Http2, "https://example.com/")?;
let diagnostics = request.diagnostics(NonZeroUsize::new(128).unwrap());
let response = request.send().await?;
println!("{:?}", diagnostics.snapshot());
response.into_body().collect_with_limit(1 << 20).await?;
println!("{:?}", diagnostics.snapshot());
# Ok(())
# }
```

[`RequestTimeline`](crate::RequestTimeline) reports omitted events when its
capacity is reached. Intervals can overlap; missing phases mean they were not
observed. Body duration includes delays before and between your reads.
See [`RequestTimingPhase`](crate::RequestTimingPhase) for phase meanings and
[`RequestConnection`](crate::RequestConnection) for connection reuse, endpoints,
and TLS details. A [`TlsConnectionState::Pending`](crate::TlsConnectionState::Pending)
value records the state at dispatch; that event does not update after the
handshake. Early-data completion alone does not prove acceptance or resumption.
