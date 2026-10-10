# Client WebSocket source continuation

Exact snapshot: `04aa870b7c7dc40183c8752575da86e8e97b73ad`. All identities below are committed Git blob bytes, not Windows working files. This pass ran no Cargo, tests or browser comparisons.

Sixteen files were fully read. The thirteen requested files are complete; the three protocol dispatch files were also read in full to trace ownership and errors. The JSON companion is `request_body/tests/json.rs`.

The supported new finding is A55: `compression.rs:162` collects an unbounded iterator before rejecting more than four offer parameters. `from_profile` also reserves and copies its input length before that check. The accepted remedy keeps the existing four-parameter contract and ordered valid offers; its runtime reproduction belongs to the separate implementation lane. This is a configuration boundary finding.

## Fresh complete reads

| Path | Lines read | Contract |
| --- | --- | --- |
| `crates/phantom/src/websocket.rs` | 1-822 | Builder preflight, exact protocol policy, logical origin/trust, environment route selection, per-attempt timeout and setup retry, redacted trace metadata. Inline trust and future-size controls read. |
| `crates/phantom/src/websocket/compression.rs` | 1-457 | Ordered RFC 7692 offer parameters, window/level checks, profile conversion, codec application, negotiated settings. A55: full collection and profile copy occur before the existing four-parameter bound. |
| `crates/phantom/src/websocket/connection.rs` | 1-727 | Owned upgraded transport and admission lifetime, receive terminal cleanup, automatic Ping/Close flushing, Sink shutdown, outgoing message bounds. Duplex reset tests require accepted CONNECT and subsequent closed state. |
| `crates/phantom/src/websocket/error.rs` | 1-399 | Stable categories, bounded outer formatting, direct typed sources, timeout and existing setup-retry observations, remote H2 refused-stream classification. Sentinel source and redaction controls read. |
| `crates/phantom/src/websocket/handshake.rs` | 1-909 | Ordered template expansion, required protocol fields, caller/default/literal placement, trust-sensitive defaults, cookie emission gating, entropy and subprotocol validation. RFC accept, cookie counter, ordering and sensitivity controls read. |
| `crates/phantom/src/websocket/handshake/syntax.rs` | 1-47 | Comma token parsing trims only SP/HTAB and rejects empty or non-tchar tokens. Generic header validation and upstream byte bounds are separate owners. |
| `crates/phantom/src/websocket/message.rs` | 1-330 | Checked frame/message/fragment and write-buffer limits; valid Close code and UTF-8 byte bounds; redacted message diagnostics; outbound control limits and empty compression override. |
| `crates/phantom/src/websocket/retry.rs` | 1-158 | Bounded additional setup attempts, representable delay preflight, retained last error, fresh per-attempt builder. Existing refusal retry within pooled H2 is separate. |
| `crates/phantom/src/websocket/retry/tests.rs` | 1-129 | Positive attempt counts and order, delay clock advancement, exhausted budget, non-retryable categories, invalid delay with zero attempts. No cancellation-delay runtime claim. |
| `crates/phantom/src/websocket/trace.rs` | 1-40 | RAII completion/cancellation outcomes with static outcomes and typed categories. Subscriber behavior and dependency tracing are outside this read. |
| `crates/phantom/src/request/field_lists/tests.rs` | 1-872 | Independent controlled H1/H2/H3 peer observations and field-list build/check counters across racing, reuse, refused streams, GOAWAY, client hints and status/cookie retry. Exact request/body observations avoid zero-observation success. |
| `crates/phantom/src/request_body/tests.rs` | 1-354 | Exact form and multipart bytes/order/escaping, inclusive bounds, iterator exhaustion controls, metadata validation, shared clone storage, bounded diagnostics and writer failure atomicity. |
| `crates/phantom/src/request_body/tests/json.rs` | 1-99 | Exact JSON bytes and media type, inclusive byte budget, typed serialization source, early traversal stop and sticky writer failure. This is the actual requested JSON companion path. |
| `crates/phantom/src/websocket/http1.rs` | 1-344 | H1 direct/ECH/SOCKS/CONNECT dispatch, origin versus proxy identity, prepared handshake placement, error/source and cookie updates. Fresh full read extends prior partial coverage. |
| `crates/phantom/src/websocket/http2.rs` | 1-521 | Dedicated or pooled H2 dispatch, admission and route isolation, one remote-refused-stream replay, validation before admission, terminal guard cleanup and typed errors. Fresh full read extends prior partial coverage. |
| `crates/phantom/src/websocket/http3.rs` | 1-240 | H3 route/protocol preflight, prepared fields before admission, lease/control ownership, handshake completion before extended CONNECT, finish validation and typed error cleanup. Fresh full read extends prior partial coverage. |

Exact OID and SHA256 values are in the paired coverage JSON. Failed or truncated display attempts were re-read before marking a file complete.

## Coverage accounting

Prior lifecycle records listed these files as pending. Earlier partial compression and protocol-dispatch records keep their original revisions and basis in the JSON; their ranges are not counted twice as new distinct files. The compression partial record used working bytes and is not promoted to committed-blob identity. The earlier complete A49 response validator is retained as prior evidence only.

## Boundary traces

The builder selects protocol and logical origin, validates WebSocket-specific profile/route settings and timeout, then dispatches to a prepared H1/H2/H3 handshake. Caller fields retain explicit placement; managed key/default/cookie fields are expanded by their owner. Generic header syntax remains the lower connector responsibility. H2 admission and H3 leases keep transport/control ownership alive; finish validation failures release guards rather than authorizing a retry. Setup retry permission comes from the existing error marker; status or category alone does not grant it.

The frame owner validates outgoing message bounds, holds upgraded transport and admission, services automatic control responses, and releases them on terminal receive or shutdown failures. Error formats omit arbitrary payloads while typed causes remain available through explicit source inspection. Tracing records static outcomes and categories; dependency targets have their own contract.

The independent test controls use positive peer observations, attempt counts, literal expected encoded bytes, and retained source identity. They are source-read controls, not runtime results from this pass. Synthetic peer comparisons do not establish browser capture parity.

## Remaining gaps

- Generic literal/header-byte preflight in the lower connector and exact caller ordering before cookie or pool state remains a separate source-chain audit; local handshake validation alone does not prove all header syntax checks.
- Compression engine and all lower transport/backend implementations are not full fresh reads in this pass. No codec correctness or browser parity conclusion is made.
- External WebSocket integration suites, subscriber tests, cancellation during retry delays and profile CONNECT field customization were not fully read here.
- Handshake response validation retains its earlier A49 full-read identity; it was not credited as a new full read.
- The wider client inventory remains open. This checkpoint completes only the listed sixteen source files.

No extra finding is promoted from send/close lifetime theories: the caller still owns the WebSocket, and receive completion/drop has explicit cleanup. No new readability abstraction is required. The compression collection order is the actionable boundary defect.

## Next

- [Findings](findings.md): verification and integration state.
