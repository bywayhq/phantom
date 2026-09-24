# WebSocket

WebSocket is a two-way message protocol that starts as an HTTP request. Servers
can fingerprint that opening request like any other. When the profile carries
a WebSocket recipe, Phantom sends the opening the way the recorded browser
did, with the differences listed under [Browser recipes](#browser-recipes).
The optional `websocket` feature gives you three entry points:

| Method | Protocol | Use it when |
| --- | --- | --- |
| `Client::websocket` | HTTP/1.1 Upgrade | You want the short form. |
| `Client::websocket_with_protocol` | Exactly HTTP/1.1 Upgrade or HTTP/2 extended CONNECT ([RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html)) | You choose the protocol yourself. There is no fallback. |
| `Client::websocket_with_profile_policy` | Chosen by the profile | You want the browser's own choice between a pooled HTTP/2 session and a new connection. See [Profile connection policy](#profile-connection-policy). |

HTTP/1.1 is abbreviated H1 below, and HTTP/2 is H2.

## Connect over HTTP/1.1

```rust
use futures_util::{SinkExt, StreamExt};
use phantom::{Client, WebSocketMessage};

async fn example(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let socket = client
        .websocket("wss://example.com/events")?
        .connect()
        .await?;
    let (mut sender, mut receiver) = socket.split();

    sender
        .send(WebSocketMessage::Text("hello".into()))
        .await?;
    if let Some(message) = receiver.next().await {
        println!("{:?}", message?);
    }
    Ok(())
}
```

The example uses `futures-util` for `SinkExt` and `StreamExt`. Add it to your
own `Cargo.toml` to call those traits.

## Connect over HTTP/2

H2 accepts `wss://` only. It needs two things:

- The HTTP/2 profile sets `extended_connect_pseudo_header_order`, the order of
  the five pseudo-header fields in the CONNECT request.
  `chromium::v154_http2` and `firefox::v156_http2` carry captured orders;
  older recipes leave it unset.
- The server's initial SETTINGS enables extended CONNECT
  (`SETTINGS_ENABLE_CONNECT_PROTOCOL`).

The custom order below is illustrative, not a browser capture:

```rust
use phantom::profile::{chromium, ClientProfile, Http2PseudoHeader};
use phantom::{Client, HttpProtocol};

async fn h2_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut http2 = chromium::v154_http2();
    http2.extended_connect_pseudo_header_order = Some(vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Path,
        Http2PseudoHeader::Protocol,
    ]);
    let profile = ClientProfile::new(chromium::v154_tls()).with_http2(http2);
    let client = Client::builder(profile).build()?;

    let socket = client
        .websocket_with_protocol(HttpProtocol::Http2, "wss://example.com/events")?
        .connect()
        .await?;
    assert_eq!(socket.handshake_response().version(), http::Version::HTTP_2);
    Ok(())
}
```

`handshake_response` returns an `http::Response`, so comparing its version
needs the `http` crate as a direct dependency of your crate.

If the server's setting is absent or zero, the connect fails with a typed H2
error. Phantom does not send the CONNECT HEADERS frame and does not retry as
H1.

## Routes

WebSocket works over direct connections, HTTP proxies, and SOCKS5 proxies:

| Route | H1 | H2 |
| --- | --- | --- |
| Direct | `ws://` and `wss://` | `wss://` |
| HTTP proxy, HTTP/1.1 transport | `ws://` (forwarded), `wss://` (CONNECT tunnel) | `wss://` (CONNECT tunnel) |
| HTTPS proxy, HTTP/2 transport (`HttpProxy::with_http2_transport`) | `wss://` (CONNECT stream) | `wss://` (CONNECT stream) |
| SOCKS5 (`socks5://` or `socks5h://`) | `ws://` and `wss://` | `wss://` |

Any other combination fails with a typed error before proxy or origin I/O.
The [route matrix](../reference/route-matrix.md) covers every scheme,
protocol, and route.

Route details:

- Forwarded `ws://`: A plaintext `ws://` request through an HTTP proxy
  uses an RFC 6455-compatible `http://` absolute-form target. It never
  changes to CONNECT. The proxy connection itself can be plaintext or use
  its own authenticated TLS. An H2 proxy transport cannot forward plaintext
  requests, so H1 `ws://` through it fails instead of switching to CONNECT or
  HTTP/1.1.
- SOCKS5: After the tunnel is up, `ws://` sends the same origin-form
  Upgrade as a direct connection. `socks5://` resolves the origin locally;
  `socks5h://` sends the canonical DNS name to the proxy. Configured
  username and password authentication applies only to SOCKS negotiation.
- H2 through a proxy: Phantom opens a dedicated tunnel, then runs origin
  TLS, the HTTP/2 preface, and extended CONNECT inside it, as on a direct
  route. The origin must still enable extended CONNECT.
- Proxy credentials: Literal `Proxy-Authorization` fields are rejected.
  With Basic credentials on the proxy, each connection starts anonymously. It
  replays once, on a fresh connection over the same route, only after a
  strict `407` Basic challenge. No challenge state is kept.
- No fallback: A proxy rejection, SOCKS5 failure, or proxy ALPN mismatch
  is a terminal proxy error. Phantom never falls back to a direct connection
  or from H2 to an H1 Upgrade.

Secure connections use Phantom's BoringSSL TLS profile. H1 openings go
through the client's ordered HTTP/1 serializer, and WebSocket shares the
client's ordered response metadata, cookies, runtime errors, and tracing.

## Timeouts and retries

A WebSocket connect uses the client's profile, route, trust roots, and cookie
jar, but none of its request policy. These do not apply to
`WebSocketRequestBuilder::connect`:

- `RequestTimeouts`;
- `RetryPolicy` (connection-setup retries, status retries, and
  reused-connection replay);
- `RedirectPolicy`; and
- client hints and Alt-Svc.

The builder has no timeout or retry setter, so a connect waits as long as the
network and peer allow. To bound it, wrap the `connect` future in
`tokio::time::timeout`. Dropping the future cancels the attempt.

A redirect or any other non-success response is returned through
`WebSocketError::response`. Phantom never follows redirects, reconnects, sends
heartbeats, or switches protocol for you.

Two replays exist, and neither is caller policy. One is the Basic
proxy-authentication retry described under [Routes](#routes). The other is the
profile's refused-stream rule: when a recipe sets
`WebSocketConnectionPolicy::refused_stream_retry` to `SameSessionOnce` and the
peer answers the extended CONNECT with `RST_STREAM(REFUSED_STREAM)`, Phantom
sends the same opening fields once more on that same session and the next
stream. RFC 9113, section 8.7 makes the refusal proof that the peer processed
nothing, and the opening fields are the only bytes written to the stream, so
nothing already sent is replayed. A second refusal is returned, no other
failure is reopened, and no other connection, route, or protocol is tried.

The rule applies only to an extended CONNECT sent on a *pooled* HTTP/2
session, which is the only case the captures cover. A refusal on a connection
opened for this WebSocket, through
`WebSocketNewConnection::Http2ExtendedConnect`, is returned unchanged whatever
the recipe sets, because no capture shows a client reopening there. A
`GOAWAY`, a locally initiated reset, and every other stream failure are
returned unchanged too: only a peer `RST_STREAM` carrying `REFUSED_STREAM`
qualifies.

## Send and receive messages

`WebSocket` carries text, binary, Ping, Pong, and Close messages. It
implements the standard `Stream` and `Sink` traits, so `StreamExt::split`
gives separate sender and receiver halves without a Phantom background task.

- Client frames are masked, and fragmented data frames are reassembled.
- Replies to an incoming Ping or Close are flushed before the event reaches
  you.
- `receive` is cancellation-safe. A cancelled send has the usual ambiguity of
  an interrupted write, so do not retry it blindly.
- `close` sends and flushes a Close frame. You can keep receiving until the
  peer replies. Dropping the connection closes the transport.

### Message limits

| Limit | Default |
| --- | --- |
| Frame size | 16 MiB |
| Reassembled message size | 64 MiB |
| Data frames per message | 131,072 |

The frame count includes the first text or binary frame and every
continuation, including empty ones; interleaved control frames do not count.
The write buffer is also bounded. Replace the three receive limits with a
validated `WebSocketLimits` value.

A message with too many frames fails with `WebSocketErrorKind::Capacity` and
closes the transport. The check runs before decompression or reassembly, so a
peer cannot cause unbounded work with many tiny or empty frames.

### Connections and pooling

WebSocket connections are exclusive and never enter the client's ordinary
HTTP pool. An exact H2 WebSocket uses its own connection.

Under a [profile policy](#profile-connection-policy), a WebSocket can instead
be one stream on a pooled H2 session. That stream uses the profile's
extended-CONNECT pseudo-header order and priority; the session's other
streams keep their own. On a pooled session:

- Before sending CONNECT, the WebSocket takes the same per-origin H2 slot an
  ordinary request takes. It waits while the origin is at
  `max_concurrent_http2_requests_per_origin`, and fails with
  `WebSocketErrorKind::Capacity` when the wait queue is also full. The peer's
  concurrent-stream limit still applies.
- It holds that slot and a lease on the session for its whole life, like a
  response body. Both are released when the WebSocket is dropped or reaches a
  terminal state, such as a completed close handshake.

On any H2 WebSocket, DATA frames carry reads and writes at the same time, and
receive-window capacity is returned as you consume bytes. A graceful shutdown
sends END_STREAM; dropping early resets only the CONNECT stream.

## Ordered opening fields

The opening request is a template: an ordered list of fields that Phantom
emits exactly as given. It holds literal fields plus typed placeholders for
values Phantom manages, such as the URI authority, the random key, and client
cookies. Literal fields keep their order and casing.

Where the template comes from:

- By default, Phantom uses a built-in H1 or H2 template.
- If the client profile carries `WebSocketSettings`, its H1 and H2 templates
  replace the defaults for every WebSocket builder.
- `WebSocketRequestBuilder::headers` replaces the whole template for one
  connection with `WebSocketHeader` values.

To add values:

- `WebSocketHeader::caller_field` reserves the position and spelling of a
  field whose value you supply, such as `User-Agent` or `Origin`. An unfilled
  slot emits nothing.
- `WebSocketRequestBuilder::header` fills the first slot with the same name,
  compared case-insensitively, and keeps the slot's spelling. With no
  matching slot, it appends one literal field.

With `websocket-deflate`, the `WebSocketHeader::permessage_deflate`
placeholder emits the generated compression offer at your chosen position and
spelling. Literal `Sec-WebSocket-Extensions` fields are rejected so the offer
always matches the installed codec.

All validation finishes before network I/O. Both protocols reject literal
`Proxy-Authorization`, so credentials stay with the proxy route and cannot
leak to a direct origin.

### HTTP/1.1 requirements

The template must contain exactly one authority placeholder and one key
placeholder, one valid `Upgrade` field, one `Connection` field containing the
`Upgrade` token, and version 13. Literal `Host` and `Sec-WebSocket-Key` fields
are rejected.

The server must answer with an HTTP/1.1 `101` that has:

- exactly one matching accept value;
- valid `Upgrade` and `Connection` tokens;
- no HTTP body framing;
- no extension the client did not offer; and
- at most one of the offered subprotocols.

Compression responses are parsed strictly before the frame codec is
installed. A duplicate, malformed, unknown, or contradictory selection fails
the handshake. Any other non-`101` response is returned through
`WebSocketError::response` with its streaming body and ordered fields.

### HTTP/2 requirements

The `:method`, `:authority`, `:scheme`, `:path`, and `:protocol = websocket`
pseudo-fields come from the request and profile. The default ordinary fields
are lowercase `sec-websocket-version: 13`, the compression placeholder when
enabled, and the cookie placeholder.

H2 rejects authority and key placeholders, `Host`, `Upgrade`, `Connection`,
`Sec-WebSocket-Key`, uppercase names, and literal extension fields.

The server accepts with a 2xx response. Phantom rejects H1-only `Upgrade`,
`Connection`, transfer-coding, and `Sec-WebSocket-Accept` fields in that
response, and applies the same strict subprotocol and extension checks as H1.

## Profile connection policy

A browser does not always open a WebSocket the same way: it may reuse an
existing H2 connection or open a new one. `WebSocketSettings` on the
`ClientProfile` records that behavior. It holds the ordered H1 and H2
templates, the `permessage-deflate` offer, and a `WebSocketConnectionPolicy`.

`Client::websocket_with_profile_policy` applies the policy. The `websocket`
and `websocket_with_protocol` builders use only the templates. The policy is
profile data and does not depend on which client uses it. It chooses as
follows:

1. `ws://` always uses an HTTP/1.1 Upgrade.
2. For `wss://`, if the client holds a pooled, reusable H2 session to the
   same origin and route, and the peer enabled
   `SETTINGS_ENABLE_CONNECT_PROTOCOL`, the WebSocket becomes a new extended
   CONNECT stream on it. Phantom checks the negotiated H1/H2 pool (direct
   routes only) before the exact H2 pool. It opens nothing to look.
3. Otherwise, `without_http2_session` or `with_incapable_http2_session`
   names the new connection:
   - `Http1Upgrade`: a TLS connection offering `http1_alpn_protocols`, which
     must include `http/1.1` and not `h2`. An ALPS offer whose protocol is no
     longer offered is dropped from this connection's ClientHello; every other
     TLS field is unchanged.
   - `Http2ExtendedConnect`: a connection with the profile's ordinary TLS
     offer.

The choice is made once, before any WebSocket bytes are sent. A rejection,
refused stream, reset, missing peer setting, or ALPN mismatch on the chosen
connection is returned as a typed error. Phantom never retries on another
connection or protocol.

Because the protocol is chosen at connect time, `headers` (a full replacement
template) fails before I/O under this builder. Fill template slots with
`header` instead. With `websocket-deflate`, `PerMessageDeflate::from_profile`
enables compression with the profile's offer.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RequestHeader};

async fn profile_policy_example() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_websocket(chromium::v154_websocket());
    let client = Client::builder(profile).build()?;

    // Fills the recipe's caller slots at their captured positions.
    let socket = client
        .websocket_with_profile_policy("wss://example.com/events")?
        .header(RequestHeader::new("User-Agent", "ExampleAgent/1.0"))
        .header(RequestHeader::new("Origin", "https://example.com"))
        .connect()
        .await?;
    println!("{:?}", socket.handshake_response().version());
    Ok(())
}
```

### Browser recipes

| Recipe | Pooled capable H2 session | No H2 session | Session without the setting |
| --- | --- | --- | --- |
| `chromium::v154_websocket` (Chrome and Edge 153) | Extended CONNECT on it | New TLS connection offering only `http/1.1`; H1 Upgrade | Same as no session |
| `firefox::v156_websocket` | Extended CONNECT on it | New connection offering `h2,http/1.1`; extended CONNECT | New TLS connection offering only `http/1.1`; H1 Upgrade |

The paired `chromium::v154_http2` and `firefox::v156_http2` recipes carry the
captured extended-CONNECT pseudo-header order and a separate
`extended_connect_priority`:

- Chrome: exclusive on stream 0 with weight 147, instead of 256.
- Firefox: non-exclusive on stream 0 with weight 22, instead of 42.

Each recipe also carries two behaviours the captures disagree on:

| Recipe | Refused CONNECT stream | Empty message with deflate |
| --- | --- | --- |
| `chromium::v154_websocket` | Reopen once on the same session | Compressed, RSV1 set |
| `firefox::v156_websocket` | Reported to the caller | Uncompressed, RSV1 clear |

The recipes' H1 and H2 templates reproduce the captured field order,
spelling, and fixed values. These fields are caller slots: `User-Agent`,
`Origin`, `Accept-Encoding`, `Accept-Language`, and, for Firefox,
`Sec-Fetch-Site` and `sec-fetch-storage-access`. Fixture tests replay every
retained capture against the recipes, and loopback tests compare Phantom's
emitted CONNECT HEADERS and H1 openings with the captures.

Each recipe also states its HPACK encoder identity in
[`Http2Settings::hpack`](https://docs.rs/phantom-http/latest/phantom/profile/struct.Http2Settings.html),
so the emitted CONNECT block matches the capture's representation, static name
index, and Huffman flags for every pseudo-field. Chrome and Edge keep
`:method` and `:protocol` out of the dynamic table, name repeated static
entries with the lower index, and Huffman-code only what the coding shortens,
so `CONNECT` and `13` go raw. Firefox indexes both fields incrementally, names
them with entries 3 and 5, and codes whatever the coding does not lengthen.

These recipes do not reproduce:

- Firefox's leading dynamic-table size update.
- Firefox's stream `WINDOW_UPDATE` after CONNECT HEADERS, its CONNECT on
  stream 3 of a new connection (Phantom uses stream 1), and the second H2
  connection it opens and closes when reusing a session.
- Chrome's `RST_STREAM(CANCEL)` after a rejection or an unoffered extension.
- Chrome's variable fragmentation of large uncompressed messages, its
  always-sent compression offer (Phantom offers only when enabled), and the
  cookie field position, which no capture shows.

## Compression

The additive `websocket-deflate` feature compiles RFC 7692
`permessage-deflate` support. It does not change the wire by itself: each
connection opts in through `WebSocketRequestBuilder::permessage_deflate`.

`PerMessageDeflate::new()` offers
`permessage-deflate; client_max_window_bits`. The typed offer API can replace
that with any RFC-valid ordered combination, including no parameters and a
bare or valued `client_max_window_bits`. Duplicate parameters and invalid
window widths fail before I/O. You can also configure context takeover per
direction, the local encoder cap, and the compression level.
`WebSocket::negotiated_permessage_deflate` returns what the server selected.

After negotiation, every text and binary message is compressed. Ping, Pong,
and Close frames never are.

An empty message is the one case browsers disagree on, so
`PerMessageDeflate::compress_empty_messages` selects the rule and a profile
recipe supplies it through `WebSocketSettings::empty_message_compression`. On
by default, a zero-length message is deflated into a one-byte frame with RSV1
set, as Chrome 154 and Edge 153 do. Off, it is sent with RSV1 clear and an
empty payload, as Firefox 156 does. Non-empty messages are compressed either
way, so the encoder history is never skipped. Decompressed data counts against
`WebSocketLimits::max_message_size` as it expands, so an oversized message
stops early. If the two sides' compression state diverges, the connection
ends rather than decoding later frames with a mismatched dictionary. Tracing
records uncompressed byte counts, never payload contents.

## How Phantom implements WebSocket

Phantom owns the opening handshake and the response checks. After a
validated `101`, it hands the connection to `tokio-tungstenite`, which serves
only as the RFC 6455 frame and message engine. Its client handshake, TLS
connectors, and public types are not exposed.

The vendored engine carries an ordered patch series that:

- keeps frames and messages out of dependency logs;
- returns a failure to get mask entropy as a typed error instead of
  panicking;
- adds the compression state machine, so RSV1, fragments, interleaved control
  frames, context takeover, UTF-8 validation, and the decompressed size limit
  share one state; and
- adds the fragment-count limit, without changing default behavior.

The public client is tested against a pinned Autobahn fuzzing server. See
[Validation](../explanation/validation.md#external-suites) for how external
suites are used.

## Current boundary

The Chrome 154 (also used for Edge 153) and Firefox 156 WebSocket recipes
cover connection choice, extended-CONNECT pseudo-header order and priority,
opening field templates, and compression offers. They come from the retained
Windows captures listed in
[Validation](../explanation/validation.md#websocket-browser-evidence).
[Browser recipes](#browser-recipes) lists what they do not reproduce.

Still open:

- Codec output parity, and browser heuristics beyond the empty-message rule
  for which messages to compress.
- Proxied WebSockets. No browser capture goes through a proxy, so a proxied
  profile-policy WebSocket follows the same rules without captured evidence
  for that route.
- WebSocket over HTTP/3 is not implemented, and is not planned while no
  shipping browser opens one by default. See
  [Coverage](../reference/coverage.md) for the evidence.
