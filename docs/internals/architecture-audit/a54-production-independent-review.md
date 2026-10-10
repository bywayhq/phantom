# A54 version server ownership source review

Source approved at `b20506eb348a2c7ef31758201ac18ea2c063eb89`, following the regression-only checkpoint `946858d15e9ef0cf52ccce4690e0eab18726a355`. The paired JSON records exact raw Git hashes and full source ranges for the two changed files, adjacent certificate helper, manual client, and bounded validation passage.

Internal certificate scratch now has a TemporaryDirectory owner from preparation through server shutdown. The acquired-server finally scope starts immediately after acquisition and encloses address discovery, port publication, request waiting, and response grace. Preparation or acquisition failures release scratch without closing a server that was never acquired. Address/publication failure and actual task cancellation close the acquired server. Published caller root and port files remain outside scratch.

The actual baseline log records six passing and three intended failing methods. The corrected retained log records twelve passing methods. The tests use independent filesystem existence and exact caller artifact bytes, real missing-parent publication failure, typed error identity controls, and actual asyncio cancellation with a bounded acquisition barrier. They preserve the original report/loopback/reserved-port controls. The returned synthetic port is never bound and the certificate bytes explicitly do not represent valid TLS material.

The resolved aioquic 1.3.0 server source confirms that serve returns the acquired protocol and close synchronously closes its protocols and transport. The real certificate helper and client consumer were read for lifetime and publication contracts. This is source review and retained-log inspection, not execution or proof of native QUIC/TLS shutdown.

Minor readability improvements remain: separate preparation/state/acquisition paragraphs in run, and separate arrange/act/assert steps in the four initial ownership regressions. These do not change the approved behavior. No production, test, or documentation edits were made. A51 count validation must be composed separately; full integration checks remain with the root owner.

## Next

- [Findings](findings.md): verification and integration state.
