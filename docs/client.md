# Using the client

This guide is for integrators. It explains the public client model and the
choices that affect requests; packet-level details live elsewhere.

## The three layers

| Layer | Owns |
| --- | --- |
| Profile | Immutable TLS, HTTP/2, HTTP/3, QUIC, and client-hint wire settings |
| Client | Pools, route defaults, trust, limits, redirects, cookies, learned hints, and TLS sessions |
| Request | Method, URL, ordered fields, body, protocol, route override, and timeout override |

Built-in and custom profiles use the same typed model. A recipe name records
capture provenance; it does not make the runtime branch on browser family or
host operating system.

## Choose a protocol

- `get` and `request` select exactly H1, H2, or H3.
- `get_negotiated` and `request_negotiated` perform one direct TLS handshake
  and select H2 for `h2`, or H1 for `http/1.1` or absent ALPN.
- H3 uses a separate QUIC path and accepts direct routes only.

Unsupported combinations fail explicitly before another protocol or route is
attempted.

## Preserve request intent

`RequestHeader` preserves field-name spelling, value bytes, duplicates, and
global order. Ordinary methods can carry owned bytes or a pull-driven
`http_body::Body<Data = Bytes>`.

`RequestBuilder::trailers` adds an ordered static trailer block after the body
on H1, H2, or H3. Trailers produced dynamically by a streaming body remain
unsupported.

Owned bodies can be replayed where a configured redirect requires it.
Streaming bodies are one-shot. Phantom validates a supplied `Content-Length`;
unknown-length H1 uploads use chunked transfer coding, while H2 and H3 omit the
field.

## Routes and proxies

Set a default route on `ClientBuilder`, or override it on one request. Supported
TCP routes are direct, plaintext HTTP/1.1 forwarding, HTTP/HTTPS CONNECT, and
SOCKS5 with local or proxy-owned DNS and optional credentials.

The complete route participates in pool identity. Proxy failure never falls
back direct, and H3 rejects TCP-only proxy routes before network I/O. Proxy
credentials are validated before I/O and excluded from diagnostics.

## Client-owned state

`Client` is cheap to clone. Clones share bounded state; independently built
clients do not.

- H1 connections are reused sequentially without pipelining.
- H2 and H3 multiplex within peer and local limits.
- Pool admission and retained connections are bounded per origin and route.
- Dropping one H2 or H3 request cancels its stream, not unrelated work.
- Redirects are disabled until a finite policy is configured.
- Cookies require the `cookies` feature and explicit builder activation.
- Learned `Accept-CH` state is bounded and scoped to the exact secure origin.

## Timeouts

Timeouts are disabled by default. Client or request policy can bound pool
admission, connection setup, response head, response-body inactivity, and the
whole operation across redirects and bounded replays. Errors identify the
phase and selected protocol.

## Responses

Every successful request returns `http::Response<ResponseBody>`. Its extensions
include `ResponseInfo` and `OrderedResponseHeaders`. The latter preserves
duplicate interleaving on every protocol and original field-name spelling on
H1.

The body is streaming and backpressured. Consume it to completion when you want
the connection to remain eligible for reuse.

For optional APIs, see [Server-sent events](sse.md) and
[WebSocket](websocket.md). For exhaustive support and planned gaps, see
[Coverage](coverage.md).
