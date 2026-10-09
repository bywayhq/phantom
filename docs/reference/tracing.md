# Tracing

Use these spans and events to follow requests, retries, and stream operations.
Install a `tracing` subscriber in your application and enable the DEBUG level.

## Scope

This page describes the facade targets whose names start with `phantom::`.
The listed records contain operation names, classifications, flags, and counts.
They omit URI paths, queries, user information, header values, cookies, body
contents, WebSocket messages, SSE event contents, and nested error causes.

`method` contains your HTTP method token. Treat a custom method as logged input.
Counts can reveal lengths and activity. Choose your subscriber's retention and
access rules accordingly.

Transport targets such as `phantom_net::` and dependency targets have separate
records. This contract does not cover their fields or formatted errors. Limit
your target filter to the facade when you need the scope above.

Explicit inspection has a separate contract. Responses expose headers and body
data. Error `source()` chains retain diagnostic causes and can contain caller
messages or peer data. Logging those values requires your own redaction.

## Request span

`client.request` covers one `RequestBuilder::send` operation, including its
redirects and retries. It ends when the response headers arrive or sending
fails. A later body-read failure does not change its completed outcome.

| Field | Value |
| --- | --- |
| `method` | HTTP method token |
| `body_bytes` | Known request-body length in bytes |
| `body_kind` | `absent`, `bytes`, `stream`, `buffered` |
| `trailer_fields` | Declared request-trailer count |
| `protocol` | Requested protocol selection |
| `selected_protocol` | Selected or explicitly requested protocol |
| `route` | Initial hop's selected route |
| `retries_performed` | Connection-setup retry count |
| `retry_reason` | `connection_setup` |
| `reused_connection_replays` | Reused HTTP/1 connection replay count |
| `unprocessed_replays` | Peer-unprocessed replay count |
| `status_retries` | Status retry count |
| `http2_fallbacks` | Exact HTTP/3 to HTTP/2 fallback count |
| `timeout_phase` | Failed timeout phase |
| `outcome` | `ok`, `error`, `timeout`, `cancelled`, `panicked` |

Unknown `body_bytes` and unrecorded optional fields are absent. Retry counters
start at zero and span redirect hops. `retry_reason` describes a setup retry
decision, including one whose wait fails. It is not a summary of every replay.
Counts describe retry actions, not requests the peer received.

`selected_protocol` can change after negotiation or HTTP/2 fallback. An exact
request records its chosen protocol before validation. The span has no final
status or `error_kind` field. Read the returned response or typed error for
those values.

Three additional fields describe Basic authentication on HTTP forward requests:

| Field | Value |
| --- | --- |
| `proxy_authentication_preemptive` | Credentials remembered before the attempt |
| `proxy_authentication_retry` | Forward request replayed after a challenge |
| `proxy_attempts` | One or two attempts on the current forward hop |

These fields do not summarize CONNECT tunnel authentication. Browser-required
replays, such as client hints and HTTP/2 PING recovery, emit separate events.

## Protocol and route values

Protocol values are `http/1.1`, `h2`, and `h3`. A negotiated request records
`h2_or_http/1.1` in `protocol`. A profile-selected WebSocket opening records
`profile_policy` there instead.

| Route value | Route |
| --- | --- |
| `direct` | Direct connection |
| `http_connect` | Plain HTTP proxy tunnel |
| `https_connect` | HTTPS proxy tunnel |
| `https_h2_connect` | HTTP/2 HTTPS proxy tunnel |
| `http_forward` | Plain HTTP forwarding |
| `https_forward` | HTTPS forwarding |
| `https_h2_forward` | HTTP/2 HTTPS forwarding |
| `socks5_local_dns` | SOCKS5 with local origin lookup |
| `socks5_remote_dns` | SOCKS5 with proxy origin lookup |
| `connect_udp` | HTTP/3 CONNECT-UDP |
| `connect_udp_h2` | HTTP/2 CONNECT-UDP |
| `connect_udp_http1` | HTTP/1 CONNECT-UDP |

The forwarding names apply to `client.request` on an HTTP origin. WebSocket
and EventSource opening spans record the route's transport name. An HTTP
EventSource can therefore show `http_connect` on its outer span and
`http_forward` on the nested request span.

Timeout phase values are `pool_admission`, `connect`, `response_head`,
`read_idle`, `total`, and `websocket_handshake`.

## Request events

Events use static messages and the following structured fields. Fields appear
when the corresponding action occurs.

| Action | Fields |
| --- | --- |
| Redirect | `hop`, `status`, `same_origin` |
| Connection-setup retry wait | `retry`, `reason=connection_setup` |
| Reused connection replay | `replay`, `reason=reused_connection_closed` |
| Unprocessed replay | `replay`, optional `protocol`, `reason=unprocessed` |
| Status retry | `retry`, `status`, `delay_ms`, `reason=status` |
| HTTP/2 fallback | `fallback`, `error_kind`, `reason=http3_setup_failed` |
| Forward authentication replay | `retry`, `reason=proxy_authentication` |
| Critical client-hint replay | `retry`, `reason=critical_client_hints` |
| Connection client-hint restart | `restart`, `hints_added`, `reason=accept_ch` |
| HTTP/2 PING recovery | `reason=http2_ping_failed` |
| Request timeout | `timeout_phase`, optional `protocol` |
| Response-body timeout | Optional `timeout_phase` |

Redirect and status-retry events contain numeric response statuses. Ordinary
responses do not emit a facade status event. Body reads do not create a facade
completion span or record body contents.

## WebSocket spans

| Span | Fields |
| --- | --- |
| `websocket.connect` | `protocol`, `route`, `connection`, `refused_stream_retry`, `handshake_retries`, `outcome`, `error_kind` |
| `websocket.send` | `message_kind`, `payload_bytes`, `outcome`, `error_kind` |
| `websocket.receive` | `message_kind`, `payload_bytes`, `outcome`, `error_kind` |

`connection` is `http2_session`, `new_http2`, or `new_http1` when the profile's
opening policy selects a connection. Exact openings can leave it absent.
`refused_stream_retry` is recorded as `true` after reopening a refused extended
CONNECT stream. `handshake_retries` counts permitted connection-setup retries.
Neither field has an initial zero or false value.

Message kinds are `text`, `binary`, `ping`, `pong`, and `close`. Payload counts
are bytes. A Close count includes its two-byte code when present. Receive fields
appear after a complete message or control event arrives.

WebSocket outcomes are `ok`, `error`, `cancelled`, and `panicked`. Errors record
the Debug spelling of `WebSocketErrorKind`, such as `Protocol` or `Io`.
Connection-setup retry events carry `retry`, `delay_ms`, and
`reason=connection_setup`. Handshake timeout events carry `timeout_phase` and
an optional `protocol`.

These operation spans belong to the inherent `send`, `receive`, and `connect`
methods. Using the `Stream` or `Sink` traits does not create the same send or
receive spans. `close` uses `send` and its Close message fields.

## SSE spans

| Span | Fields | Completed outcomes |
| --- | --- | --- |
| `sse.next_event` | `outcome` | `event`, `eof`, `line_limit`, `event_limit`, `body_error`, `idle_timeout`, `error` |
| `sse.event_source.connect` | `protocol`, `route`, `reconnects`, `outcome` | `open`, `closed`, `error` |
| `sse.event_source.next_event` | `protocol`, `reconnects`, `outcome` | `event`, `closed`, `idle_timeout`, `reconnect_limit`, `error` |

`reconnects` counts additional requests, including retries of the initial
connection. Connect records it on success. Event reads record it on completion.
Initial retry and later reconnect events carry `attempt` and `maximum`.
EventSource's HTTP work also creates `client.request` spans.

Both inherent `next_event` methods and `Stream::poll_next` use the SSE read
spans. A pending poll keeps its span until completion. Dropping an inherent
`next_event` future records `cancelled`. Dropping a generic stream-read future
can leave that span pending until the next poll or the stream's drop.

## Cancellation

For the listed inherent methods, dropping a polled, unfinished operation records
`cancelled`. Unwinding records `panicked`. A future dropped before its first
poll has not created a span.
Cancellation describes the operation future, not a guarantee that no bytes
were sent or that the peer ignored the request.

## Next

- [Troubleshooting](../guides/troubleshooting.md) for symptoms and fixes.
- [Retries](../guides/retries.md) for retry policies and replay rules.
- [Responses](../guides/responses.md) for body reads and response metadata.
