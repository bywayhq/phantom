# Chrome 155 Linux peer observations

Pinned httpcloak v1.7.3 supplied the `chrome-155-linux` preset. Six fresh
Linux/amd64 consumer processes exercised TLS and HTTP/2: three first/reused
navigation pairs and three nine-request cookie/HPACK boundary sequences.
`observations-v1` retains actual raw bytes, decoded fields, bodies and exits.
`provenance.json` separates the consumer platform from the advertised identity.

The browser build and Linux release were not observed. There is no TCP/IP,
HTTP/1, QUIC, upload, DNS, WebSocket or resumption comparison. The source-only
16,375-byte DATA cap is not ported. TLS ticket and HTTP/2 idle defaults are
outside this comparison. `phantom/` retains the public-client
comparison and its observed differences. The original `provenance.json` records
the peer preparation stage.

The observed insertion limit is the complete dynamic table: 3,073 and 4,096
bytes insert; 4,097 bytes uses a literal without insertion and preserves a
marker. Sizes include RFC 7541's 32-byte overhead. Caller cookies split into
two crumbs before priority and reuse their dynamic entries.

`consumer/`, `capture.py`, commands, Go sums and binary module metadata identify
execution. The binary and private keys are excluded. `independent-review.md`
records a separate raw-byte review. Failed preparation receipts remain.
The initial prep manifest records a larger historical set; top-level
`sha256.json` covers the exact retained capsule instead.

To repeat the peer run, build `consumer/` with the recorded `build/command.txt`.
Copy the retained `../wreq-util-5715529-safari-ios-26/phantom/capture.py.txt`
to your clean source checkout's `target/tmp/safari-ios-comparison/capture.py`.
It is the retention helper identified by the recorded hash. In WSL, run
`capture.py --source <checkout> --consumer <Linux executable> --output <new directory>`.
The driver uses Windows Git for this checkout's worktree pointer.

`LICENSE` is httpcloak's MIT notice. `licenses/` covers actual linked modules.
The HTTP fork omitted a LICENSE file; `license-resolution/` preserves its pinned
BSD declaration and separately labelled official Go BSD text, without claiming
that text shipped in the fork. Source copyright notices remain attached.
