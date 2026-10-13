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

## Next

- [Campaign](../transport-and-profile-campaign.md): open tasks and delivery.
- [Original evidence](../architecture-audit/evidence.md): historical logs.
