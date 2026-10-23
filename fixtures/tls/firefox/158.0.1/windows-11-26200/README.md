# Firefox 158 ECH

Firefox 158.0.1, build `20261019185856`, on Windows 25H2 build 26200.9457.
Browser source: `48a735cc74a7e6d730f9bf59c3de58f750287a23`.

Recorded on October 23, 2026, with a fresh headful profile, TRR mode 3 and
HTTP/3 disabled. The disposable profile trusts the local capture CA through
its NSS database. Certificate verification stays enabled.

| File | Result |
| --- | --- |
| `ech-accept.txt` | Config 1 accepted; an HTTP request served |
| `ech-reject.txt` | Config 1 rejected; config 2 then accepted and a request served |

Both runs use `public.phantom.test` as the outer name. Each file retains all
connections from one capture invocation.

Use the Firefox command in the
[ECH capture instructions](../../../../../scripts/capture/README.md).
The peer and driver source used here is commit `b7307c64e`.
