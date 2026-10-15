# TLS response and retirement timing

Use this record to assess the TLS capture test repair and its limits. The
historical failure remains separate from the controlled reproductions.

## Original failure

At `39488c237cdccf61c0abf2f64767fb19fb4e6392`, the native OpenSSL worker in
`test_tickets_only_on_the_first_connection_when_the_scenario_says` timed out
reading `/done`. Its five-second socket deadline covered reads until EOF.
The retained log also reports an asyncio sleep callback taking 17.579 seconds.
It does not record that callback's connection or the source of the pause.

The server sends a complete response with `Content-Length: 2`, then waits
50 milliseconds before retiring the connection. It sends session tickets
before application response records. The helper therefore made inspection
of a complete response depend on the event loop scheduling retirement.

## Controlled results

The original TLS server and tests are byte-identical between the historical
commit and the starting campaign revision, `f9454a9a`. Historical asyncio
source hashes also match the current pinned Python runtime. The historical
transitive dependency and host scheduling identities were not fully retained.

| Control | Result |
| --- | --- |
| Exact historical capture suite | 1,041 tests, four skips, passed |
| Original helper with a 5.3-second retirement stall | Three original server tests timed out |
| Original helper with server closure withheld | Same timeout without an injected loop stall |
| Framed helper with the same retirement stall | Three original server tests passed |
| Final TLS module | 42 tests passed |
| Candidate capture suite | 1,049 tests, four skips, passed |

The failed worker had already received the complete 110-byte response.
Both controlled conditions produce its original exception. They demonstrate
the response/EOF coupling but cannot uniquely identify the historical pause.
Associating the old sleep callback with `/done` retirement is supported by
source order, rather than measured callback ownership.

## Repair and review

The helper uses Python's `HTTPResponse` to read the complete framed response
and retain the original response bytes. A Content-Length response completes
after its stated body length. [RFC 9112, section 6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)

The original ticket, reuse, issued-count, and recorded-request assertions
remain. The server, 50-millisecond delay, and five-second socket deadlines
remain. A truncated response raises `IncompleteRead`. Separate native EOF
controls verify the original abandoned/full/resumed/fresh connection sequence
and server retirement. Withholding closure still makes that EOF control fail.

The integration owner independently reviewed the helper, unchanged assertions,
ticket emission order, truncated-body rejection, and positive/negative EOF
controls. This deliberately changes the helper's completion contract from EOF
to framed-response completion. It does not remove the server cleanup contract.

The candidate full suite loaded before a docstring and unused scratch-list
cleanup. The final committed source separately passed all 42 TLS module tests.
The integration gate must verify the exact delivered composition.

## Retained evidence

The diagnosis packet is archived in the integration checkout under
`target/transport-profile-campaign/tls-done-diagnosis/`. The report binds
18 source, runtime, trace, and log artifacts by byte count and SHA256.
Each artifact was checked before copying from the lane.

- Lane commit: `56f406e21723ae653e14534ebd0578d00df3fe0d`.
- Report: `tls-done-diagnosis-report.json`.
- Report SHA256: `460748bc0dfeb2dc88bfbaa80f7f0f91b503a46bef46b3aefd013e155043e6f0`.

T2's fixture defect has a verified repair. Exact attribution of the historical
17.579-second pause remains unresolved. Green replay does not close it.

## 2026-10-15 isolated observation

One original test from `39488c237cdccf61c0abf2f64767fb19fb4e6392`
failed with Windows error 10048 while connecting for `/retire`, before
reaching `/done`. Owned cleanup completed and historical source stayed
unchanged. The observation records no owner-bound `/done` receive or sleep
timer sequence. This separate address-in-use error does not reproduce the
historical response/EOF timeout or explain its 17.579-second pause. The replay
does not establish the historical native dependency identity, and observer
effects apply. The original cause remains open.

Artifacts are retained at
`C:/code/phantom-worktrees/tls-done-diagnosis/target/transport-profile-campaign/T2-next-causal-step-v1/`:
`observed-once.json` contains the stage events; `owned-once-v1/result.json`
and `complete.log` retain the command, failure and cleanup outcome.

| Input or artifact | SHA256 |
| --- | --- |
| Historical `tls_resumption.py` | `94aa22c6206de97383151dd61be51f323a8f4cfb8187d7eb048defd947300b72` |
| Historical `test_tls_resumption.py` | `5bd2ec3e15b8a86d73b7fdc317d67b9b81209c24b051f4dd05cf1e3034690d68` |
| Observer source | `dcf2e7d4e36b78282fa53ef12af1c08ac7354eb249c7b16d0909d8d3adb2236d` |
| `owned-once-v1/complete.log` | `201e5d40caf9864d11ebe0ec2ae8a2eebbafd3a01ae217e2960b6ce7453417a8` |
| `observed-once.json` | `df1b6b2ade8c635eba120d70685a7995e1575c7edc4cb6f45b8cee11b7b593d5` |

The next causal observation still needs to reach `/done` and associate its
native receive, response completion and retirement timer with one connection.

## Next

- [Campaign](../transport-and-profile-campaign.md): open tasks and delivery.
- [Original evidence](../architecture-audit/evidence.md): historical logs.
