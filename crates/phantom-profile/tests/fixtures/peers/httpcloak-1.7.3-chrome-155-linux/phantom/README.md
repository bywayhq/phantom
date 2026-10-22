# Phantom public consumer comparison

Six fresh Linux/amd64 processes completed 33 sequential GETs on six HTTP/2
connections. The public client selected `chrome-155-linux` and its navigation
template, verified the retained loopback certificate, and read bounded bodies.

Normalized TLS settings match the pinned peer. Actual extension orders and ECH
payload lengths differ and remain recorded. Observed lengths were 218, 250 and
282 bytes; pinned sources also permit 186. Six samples do not establish matching
distributions. GREASE bodies and ordered trust-anchor bytes match exactly.

HTTP/2 settings, window credit, ordered fields, priority, HPACK representations
and dynamic table states match. Full-table insertion and oversized-marker cases
pass. SETTINGS ACK ordering differs: Phantom sends ACK before WINDOW_UPDATE;
the peer sends it later. The comparator returns 1 for these retained differences.
This is a partial controlled comparison, with no browser or full-wire claim.

`provenance.json` identifies the build, binary, source and comparison limits.
`observations/` retains raw bytes, decoded fields, bodies, exits and public
certificates. Private keys, key logs, executables and build caches are excluded.

To repeat, copy `consumer/`, `capture.py.txt` and `compare.py.txt` into a clean
checkout's `target/tmp/chrome-linux-comparison/`, removing `.txt` from scripts.
Use the retention helper described in the parent README. Build with the retained
command and lockfile, then run the capture driver against a fresh output path.
Run the comparator on those observations. The original build command and
Linux toolchain are retained beside this page. Each run records its consumer
command.
