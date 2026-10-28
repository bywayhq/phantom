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
