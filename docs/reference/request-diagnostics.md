# Request diagnostics

Enable a bounded timeline with `RequestBuilder::diagnostics`. Keep its returned
handle to inspect setup, response headers and body consumption separately.
The API is available without a feature flag.

## Lifetime and storage

| State | Meaning |
| --- | --- |
| `NotStarted` | Send future not polled |
| `Pending` | Send running |
| `ResponseHead` | Response headers returned |
| `Failed` | Send returned an error |
| `Cancelled` | Polled send future dropped |

The first call sets the record capacity. Repeated calls return handles to the
same collector. Clones share the collector. Each builder has its own collector.
Timing begins on the first poll of `send`, excluding builder preparation.
`send_elapsed` stops at returned headers, failure or cancellation. Body and
background setup events can finish later.

The collector retains the first `maximum_events` records. It counts later
records in `dropped_events`. Existing pending records still receive their
completion state. `admitted_attempts` counts admissions even after truncation.
Snapshots copy the retained records without clearing them.

Records contain no URLs, headers, credentials or backend error strings.
Diagnostics does not enable TLS secret logging or QUIC qlog output.

## Observed boundaries

| Phase | Interval |
| --- | --- |
| `AttemptAdmission` | Conservative origin HTTP admission |
| `PoolAdmission` | Waiting for request or stream allowance |
| `ConnectionAcquisition` | Pool lookup, shared setup wait and connection readiness |
| `ConnectionUse` | Dispatch on one HTTP connection, with connection facts |
| `ResolutionWait` | Awaiting the local resolver, including cache and overrides |
| `TcpConnect` | One operating-system TCP connect |
| `TlsHandshake` | Initial TLS handshake future |
| `QuicHandshake` | Initial QUIC connection handshake future |
| `SendResponseHead` | Request dispatch through response headers |
| `ResponseBody` | Body availability through public completion |

Event offsets use the same clock origin as `send_elapsed`. Events are retained
in start order. Intervals can overlap: do not add them to obtain request time.
`SendResponseHead` includes upload work awaited before headers. Uploads that
continue after an early response head have no separate upload timing yet.
Body timing starts when the body becomes available, before `send` returns.
It includes caller delays before and between reads, decoding and trailers.
It is not a measure of network transfer time alone.

A phase is absent when unobserved. Absence does not mean zero duration or prove
connection reuse. A reused connection normally has acquisition observations
without another TCP or TLS handshake. Shared DNS work and detached drivers
are not a request's DNS execution time. The resolver wait measures the caller's
wait instead. Setup retained in a background task keeps its original context.
Proxy setup can contribute TCP or TLS events. Setup phases do not identify
which proxy leg they belong to. Connection-use records distinguish origin
TLS from outer proxy TLS when the transport exposes both.

`EarlyData` means the initial handshake future returned for early data. It does
not establish handshake confirmation, resumption or early-data acceptance.

## Connection facts

Completed `ConnectionUse` records have `connection` metadata. Other phases
have `None`. A live snapshot can catch metadata collection before it completes.
These records share the event capacity and carry their hop and admission.
They describe facts at dispatch, including attempts that fail before writing.
TCP's internal rejected-early-data resend records admission separately without
another HTTP dispatch or connection-use record.

`reused` means an earlier HTTP request was dispatched on the same HTTP
connection, including CONNECT or a request that later failed. It is separate
from TLS session resumption. A new HTTP connection inside a reused proxy
tunnel still has `reused: false`.

| Endpoint scope | Meaning |
| --- | --- |
| `TcpSocket` | Local socket address and connected peer, possibly the proxy |
| `QuicEndpoint` | Inner QUIC endpoint addresses, possibly on a virtual tunnel |
| `Unavailable` | Underlying endpoints not exposed |

A QUIC local bind can have an unspecified IP address. Endpoint metadata does
not identify the proxy's chosen origin address or the machine's public IP.

| TLS state | Meaning |
| --- | --- |
| `NotUsed` | This layer uses no TLS |
| `Unavailable` | The transport does not expose this layer's metadata |
| `Pending` | Early-data handshake incomplete at dispatch |
| `Established` | Negotiated settings, resumption and verification state |

Origin and proxy TLS have separate states. Tunneled QUIC leaves outer proxy
TLS unavailable. Opaque caller-owned streams can leave their layers
unavailable too. Pending records remain pending in later snapshots because
they describe the handshake at dispatch.

Established details include the TLS version, cipher suite, ALPN, resumption
and whether peer chain and server name verification were enabled. Available
certificates are leaf-first DER bytes. They describe the peer's supplied or
resumed chain, rather than a newly constructed trust chain. An unavailable
chain has `None`. Certificate presence alone does not establish trust.

Connections retain certificate references and encode DER lazily, once needed.
Snapshots share those bytes. Connections opened without diagnostics retain
the same facts for later observed requests. Debug output omits certificate
bytes. Endpoint addresses remain visible in diagnostic records.

## Attempts and completion

`hop` starts at zero and changes on redirects. `admission` starts at one across
the logical request, including retries and browser replays. Setup that precedes
admission has `None`. Admission is conservative and can precede a failure before
any bytes are sent. Proxy CONNECT, SOCKS negotiation and DNS are not origin
HTTP admissions. TCP rejected-early-data replay records its own admission;
its protocol can be unknown in the TLS driver.

`Completed` marks success at the observed boundary. `Failed` marks a returned
error. `Interrupted` marks a dropped phase future. An unread or partly read
body records `Abandoned` when dropped. An already-empty final body completes
before `send` returns. Collection-limit, decoding and trailer-authentication
errors mark body failure. Body completion does not imply successful `send`
when a later redirect or retry fails.

`Cached` resolution includes cached answers, IP literals and caller overrides
where the resolver reports that distinction. A plain resolver operation may
report `Completed` without distinguishing its answer source.

## Current limits

WebSocket opening diagnostics are separate from this request-builder API.
Records have no serialized export format.

Collection and snapshots use additional CPU and memory. The
[local cost measurements](../internals/request-diagnostics-cost.md) include
disabled collection, enabled collection and separate allocation profiles.

## Next

- [Request timings](../guides/request-diagnostics.md): inspect a live timeline.
- [Tracing](tracing.md): request spans and optional backend diagnostics.
