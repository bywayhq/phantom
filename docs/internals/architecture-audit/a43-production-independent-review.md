# A43 bounded DoH capture production review

Approved `1cbc31e2ce91a25a3d7b74df646a5b124ef22eee` against authenticated fixture parent `415215aabcacdf9c747bfafa2068d10f796bd453`. No actionable source findings. The two-file lane is clean; the signed conventional commit has the required personal author and committer identities.

All fallible TLS/ECH/QUIC setup and SPKI preparation happen before starting the DoH task. Once started, the origin accept loop routes every normal or error exit through `finish_capture`. This joins or deliberately cancels origin work, shuts down and joins the DoH owner, then closes the optional QUIC endpoint before propagating an error or writing output. Original origin capture semantics remain: rejected handshakes and incomplete preconnects are diagnostic records rather than successful pages. The fixture field names and normal output construction are unchanged.

`serve_doh` owns children in a JoinSet. It observes completed child errors before admitting another loopback connection, removes completed tasks, admits exactly eight live children, and fails on the ninth. Listener failure, explicit shutdown and task failure all converge on abort-and-drain cleanup. Completed failures remain observable during draining; only cancellation explicitly requested by the owner and ordinary peer-close errors are excluded. The origin grace path also selects the DoH result. A primary capture error remains first, with any additional cleanup failures retained in the combined diagnostic and the first error as source.

`DohCapture::wait` removes its handle immediately after observing its result. `stop` does not repoll a consumed handle. Mutable JoinHandle waits and JoinSet joins are cancellation safe in the resolved Tokio 1.53.1 source. Normal shutdown joins owned work; Drop aborts it and depends on runtime cancellation for destruction, without claiming a synchronous join on Drop.

The count and byte checks share one synchronous mutex critical section with insertion. The private list starts empty and has no other production writer, so the subtraction and count equality rely on an established bounded invariant. Query 256 and byte 65,536 are inclusive; a rejected next description leaves the list unchanged. Request heads are bounded at 64 KiB before another byte is appended, and POST bodies at 65,535 before allocation. One ten-second handshake timer and one ten-second timer per whole exchange cover header, body, response and flush; progress cannot refresh the exchange timer.

The peer-close classification uses typed socket/TLS states and does not turn malformed TLS, malformed DNS or timer expiry into success. A considered wrapper concern was rejected against the pinned source: BTLS's ordinary read path converts ZERO_RETURN and cause-free SYSCALL EOF to zero bytes before tokio-btls error wrapping. TLS protocol errors remain errors.

All 20 tests and their real loopback/TLS fixtures were read. They exercise the real handlers, authenticated leaf/CA validation with an unrelated-CA negative control, eight admitted connections with actual acknowledged queries, a ninth failure with its required owner cause, 256/257 queries, independently counted 65,536/65,537 bytes with preserved records, handshake/header/body/drip deadlines, live slot reuse, malformed DNS/TLS, ordinary and speculative EOF, and abort/graceful/grace/error cleanup. Pending origin work has an explicit started signal and a destructor signal; peers must close. The drip test observes at least two successful writes and requires the server's request deadline cause, so an outer fixture timeout cannot satisfy it. A simultaneous origin-accept and DNS failure is source-traced rather than separately exercised by these tests.

Exact hashes, OIDs, line counts and full versus partial read ranges are in the JSON. This is not a whole DNS/HTTP parser or browser coverage claim. No Cargo or runtime tests were executed here. Root must run the 20 corrected example tests, applicable platform/static checks, central changelog/ledger updates, and the final integration gate; no vendor source changed in this slice.

## Next

- [Findings](findings.md): verification and integration state.
