#include <stddef.h>
#include <stdint.h>
/* Buffers remain caller owned for the entire call and must not overlap.
 * dispatch output requires 256 KiB. No function retains borrowed pointers.
 */
size_t phantom_go_dispatch(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
/* Private ABI 2 typed layout is mirrored by native_hot.go and ffi/hot.rs.
 * Request nested spans are borrowed only until request returns. Completion
 * fields and hops use offsets into the caller-owned byte arena. wait_event is
 * called by one completion pump and requires a 256 KiB arena and 64 KiB body,
 * 256 KiB / sizeof(field) fields, and 256 KiB / sizeof(hop) hops.
 * A successful call returns 1; semantic errors are carried by the typed reply.
 * Request flag bits 5..8 select context: 0 inherit, 1 raw, 2 navigation,
 * 3 fetch, 4 fetchNoStore, 5 fetchUpload, 6 script, 7 stylesheet, 8 image,
 * 9 font. Other codes and flag bits are invalid. This extends ABI 2 flags
 * without changing its layout; older payloads reject nonzero context flags.
 */
struct phantom_go_request;
struct phantom_go_reply;
struct phantom_go_event;
struct phantom_go_field;
struct phantom_go_hop;
uint64_t phantom_go_request(const struct phantom_go_request *, const uint8_t *, size_t, struct phantom_go_reply *);
uint64_t phantom_go_operation(uint64_t, uint64_t, uint64_t, const uint8_t *, size_t, struct phantom_go_reply *);
uint64_t phantom_go_wait_event(struct phantom_go_event *, struct phantom_go_field *, size_t, struct phantom_go_hop *, size_t, uint8_t *, size_t, uint8_t *, size_t);
/* Synchronous profile authoring: command <=64 KiB, raw input/output <=16 MiB,
 * metadata >=256 KiB. A zero output capacity probes the exact export length.
 * No pointers are retained; no HTTP operation or body handle is allocated.
 */
size_t phantom_go_profile(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t, uint8_t *, size_t);
/* Synchronous encrypted checkpoints: command <=64 KiB, key exactly 32 bytes
 * for export/restore (empty for copy), ciphertext input/output <=32 MiB,
 * metadata >=256 KiB. Export prepares one bounded operation; copy consumes it.
 * cancel releases a prepared export. No buffers/pointers survive the call.
 */
size_t phantom_go_session(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t, uint8_t *, size_t);
/* Optional SSE ABI 1, negotiated before any request. ABI 2 layouts and its
 * completion kinds are unchanged. sse_request borrows the ordinary descriptor
 * and body for this call only, with explicit line/event limits (<=1/8 MiB).
 * sse_next completes through the ordinary pump. Its result remains owned by
 * that operation until ack/cancel. sse_result probes exact lengths at capacity
 * zero, then copies UTF-8 data/type/committed-ID bytes to disjoint caller output.
 * It retains no foreign pointer and supports events above the pump's buffers.
 */
struct phantom_go_sse_event;
uint64_t phantom_go_sse_version(void);
uint64_t phantom_go_sse_request(const struct phantom_go_request *, const uint8_t *, size_t, uint64_t, uint64_t, struct phantom_go_reply *);
uint64_t phantom_go_sse_next(uint64_t, struct phantom_go_reply *);
uint64_t phantom_go_sse_result(uint64_t, struct phantom_go_sse_event *, uint8_t *, size_t);
/* Optional WebSocket ABI 1. Negotiate before opening; HTTP/SSE layouts stay
 * unchanged. Opening fields and write bytes are copied before async admission.
 * Read/write operations use the completion pump. websocket_result probes the
 * exact payload length at capacity zero, then copies operation-owned bytes.
 * Ack/cancel releases the result. No foreign pointer survives a call.
 */
struct phantom_go_websocket_opening;
struct phantom_go_websocket_message;
uint64_t phantom_go_websocket_version(void);
uint64_t phantom_go_websocket_open(const struct phantom_go_websocket_opening *, struct phantom_go_reply *);
uint64_t phantom_go_websocket_operation(uint64_t, uint64_t, uint64_t, uint64_t, const uint8_t *, size_t, struct phantom_go_reply *);
uint64_t phantom_go_websocket_result(uint64_t, struct phantom_go_websocket_message *, uint8_t *, size_t);
/* Optional WebSocket route ABI 1. The original opening layout stays unchanged.
 * The separate route descriptor borrows proxy and credentials during the call;
 * all bytes are bounded and copied before opening admission. */
struct phantom_go_websocket_route;
uint64_t phantom_go_websocket_route_version(void);
uint64_t phantom_go_websocket_open_with_route(const struct phantom_go_websocket_opening *, const struct phantom_go_websocket_route *, struct phantom_go_reply *);
/* Optional reconnecting EventSource ABI 1. Open copies all bounded options
 * synchronously. next/close/cancel-next use separate scalar verbs 1/2/3.
 * cancel-next preserves completion until the Rust read lease is restored;
 * callers wait for it before starting another next. result reuses SSE payload
 * lengths and carries effective retry/reconnect/closed state. Probe at zero
 * capacity, copy before ack. No foreign pointer survives any call.
 */
struct phantom_go_event_source_opening;
struct phantom_go_event_source_result;
uint64_t phantom_go_event_source_version(void);
uint64_t phantom_go_event_source_open(const struct phantom_go_event_source_opening *, struct phantom_go_reply *);
uint64_t phantom_go_event_source_operation(uint64_t, uint64_t, struct phantom_go_reply *);
uint64_t phantom_go_event_source_result(uint64_t, struct phantom_go_event_source_result *, uint8_t *, size_t);
/* Optional EventSource header-hook ABI 1; requires complete EventSource and
 * header-hook capabilities before opening. Open borrows the unchanged opening
 * descriptor and returns separate operation/owner handles plus the Error record.
 * Owner verbs 1/2/3 wait for one callback/close/release. Wait operations reuse
 * completion kind 6 and its single-use reply/custody contract; they do not read
 * or prefetch events. A dropped GET cancels only its invocation. Source close
 * waits for actual host handback, and failure returns the matching callback
 * operation until the EventSource result is acknowledged. No pointer is retained.
 */
struct phantom_go_event_source_hooks_reply;
uint64_t phantom_go_event_source_hooks_version(void);
uint64_t phantom_go_event_source_hooks_open(const struct phantom_go_event_source_opening *, uint64_t, struct phantom_go_event_source_hooks_reply *);
uint64_t phantom_go_event_source_hooks_operation(uint64_t, uint64_t, struct phantom_go_reply *);
uint64_t phantom_go_event_source_hooks_failure(uint64_t, uint64_t *, struct phantom_go_reply *);
uint64_t phantom_go_event_source_hooks_active(uint64_t, uint64_t, struct phantom_go_reply *);
/* Optional header-hook ABI 1, ordinary HTTP requests only. Negotiate all five
 * symbols before admission. request borrows the unchanged request/body layout
 * and registers 1..256 ordered hooks. Completion kind 6 is intermediate: its
 * part is a single-use ticket, not terminal delivery. copy uses the ordinary
 * field/arena capacities and returns owned offsets. reply borrows <=256 edits
 * (kind 1 append, 2 set, 3 remove), <=64 KiB total name/value bytes. Outcome
 * 0 applies edits; 1 fails; 2 discards. cancel signals without abandoning the
 * terminal completion. Host custody lasts until reply, even after cancellation;
 * ack and shutdown cannot release it early. No Go pointer survives a call.
 */
struct phantom_go_header_hook_invocation;
struct phantom_go_header_hook_edit;
uint64_t phantom_go_header_hook_version(void);
uint64_t phantom_go_header_hook_request(const struct phantom_go_request *, const uint8_t *, size_t, uint64_t, struct phantom_go_reply *);
/* Combined header-hook ABI 1 and SSE ABI 1 submission; negotiate both and this
 * symbol before admission. Extra values are line/event byte limits and hook count.
 * Request layout, callback custody and SSE result/next contracts are unchanged.
 */
uint64_t phantom_go_header_hook_sse_request(const struct phantom_go_request *, const uint8_t *, size_t, uint64_t, uint64_t, uint64_t, struct phantom_go_reply *);
uint64_t phantom_go_header_hook_copy(uint64_t, uint64_t, struct phantom_go_header_hook_invocation *, struct phantom_go_field *, size_t, uint8_t *, size_t);
uint64_t phantom_go_header_hook_reply(uint64_t, uint64_t, uint64_t, const struct phantom_go_header_hook_edit *, size_t, struct phantom_go_reply *);
uint64_t phantom_go_header_hook_cancel(uint64_t, struct phantom_go_reply *);
/* Optional redirect-hook ABI 1; also requires the complete header-hook ABI 1.
 * The unchanged request descriptor supplies maximum hops and credential names.
 * count is 0..256 header hooks. A nonnull limits pair selects raw SSE decoding;
 * otherwise the result is an ordinary response. Negotiate before admission.
 * Completion kind 7 is intermediate and uses the same host custody as kind 6.
 * copy returns four owned UTF-8 spans, status and one-based hop in a 256 KiB
 * arena. Outcome 0 accepts decision 1 Follow, 2 Stop, 3 Reject; outcome 1 fails
 * and outcome 2 discards, both with decision 0. No foreign pointer is retained.
 */
struct phantom_go_redirect_hook_invocation;
struct phantom_go_callback_sse_limits;
uint64_t phantom_go_redirect_hook_version(void);
uint64_t phantom_go_redirect_hook_request(const struct phantom_go_request *, const uint8_t *, size_t, uint64_t, const struct phantom_go_callback_sse_limits *, struct phantom_go_reply *);
uint64_t phantom_go_redirect_hook_copy(uint64_t, uint64_t, struct phantom_go_redirect_hook_invocation *, uint8_t *, size_t);
uint64_t phantom_go_redirect_hook_reply(uint64_t, uint64_t, uint64_t, uint64_t, struct phantom_go_reply *);
/* Optional state-transfer ABI 1. Negotiate all three symbols before admission.
 * Cookie/Alt-Svc rows use UTF-8 offsets into a separate <=32 MiB arena, with
 * <=16384 cookies or <=32768 alternatives. Expiry is signed Unix seconds plus
 * nanoseconds. Tickets are opaque <=16 MiB and require an exact 32-byte key.
 * Import accepts <=256 receiving routes, sharing 64 KiB of route text.
 * Input pointers are borrowed only during submit. Result probes/copies precede
 * ack; cancellation drops late results after the blocking work actually exits.
 */
struct phantom_go_state_transfer;
struct phantom_go_state_result;
struct phantom_go_state_cookie;
struct phantom_go_state_alternative;
uint64_t phantom_go_state_transfer_version(void);
uint64_t phantom_go_state_transfer_submit(const struct phantom_go_state_transfer *, struct phantom_go_reply *);
uint64_t phantom_go_state_transfer_result(uint64_t, struct phantom_go_state_result *, struct phantom_go_state_cookie *, size_t, struct phantom_go_state_alternative *, size_t, uint8_t *, size_t);

/* Optional logical-hook ABI 1 shares callback custody with header/redirect hooks.
 * Completion kind 8 is intermediate; request/response/error phase bits are 1/2/4.
 * Copy uses bounded fields and a 256 KiB byte arena, without body access.
 * Reply outcomes 0/1/2 mean success/failure/discard. Source open uses the same
 * source owner and per-GET rendezvous, preserving cancelled reads and cleanup.
 */
struct phantom_go_logical_hook_options;
struct phantom_go_logical_hook_invocation;
uint64_t phantom_go_logical_hook_version(void);
uint64_t phantom_go_logical_hook_request(const struct phantom_go_request *, const uint8_t *, size_t, const struct phantom_go_logical_hook_options *, struct phantom_go_reply *);
uint64_t phantom_go_logical_hook_copy(uint64_t, uint64_t, struct phantom_go_logical_hook_invocation *, struct phantom_go_field *, size_t, uint8_t *, size_t);
uint64_t phantom_go_logical_hook_reply(uint64_t, uint64_t, uint64_t, struct phantom_go_reply *);
uint64_t phantom_go_logical_hook_source_open(const struct phantom_go_event_source_opening *, uint64_t, uint64_t, struct phantom_go_event_source_hooks_reply *);
