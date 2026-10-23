# Chrome 156 Mac requests

Google Chrome stable 156.0.8078.48 on hosted macOS 26.6.2 arm64 and
macOS 15.7.9 x86_64. Headed runs used fresh profiles, the browser sandbox,
loopback hostname mapping and a certificate SPKI exception, with zero retries.

Each platform directory contains H1, H2 and H3 resource captures. The snapshots
retain TCP/QUIC ClientHello, HTTP/2 and HTTP/3 startup, navigation and client
hints under [client-hints](../../../client-hints/chrome/156.0.8078.48/).
All resource pages completed six requests and `resources:ok`; their connections
closed before publication. H2 resources may use a new connection after `/start`.
The [Ahem font and license](../../../resources/assets/ahem/README.md) are retained
separately.

Snapshot, H1 and ARM H3 source: `d163304966386be553556fded8856362e943fd62`
([run 39947313589](https://github.com/bywayhq/phantom/actions/runs/39947313589)).
Intel H2 uses that run; Intel H3 uses `c8e8e6fde776be708c70b1e23f96c9db41a24554`
([run 39942660683](https://github.com/bywayhq/phantom/actions/runs/39942660683)).
ARM H2 uses `d969be9fb771d36d9e6ef9d61a5eddcff11de598`
([run 39951227146](https://github.com/bywayhq/phantom/actions/runs/39951227146)).
Python was 3.10.11 on ARM and 3.10.21 on Intel, with h2 4.4.1, hpack 4.2.0,
aioquic 1.3.0 and pylsqpack 0.3.24.

Reproduce through the [macOS capture workflow](../../../../scripts/capture/MACOS.md)
with `capture_mode=profile` on its ARM and Intel runners. The workflow pins the
browser build and retains source, browser identity, raw results and
cleanup failures for each attempt.

| Platform/file | SHA256 |
| --- | --- |
| macos-26.6.2-arm64/snapshot-1.txt | b75233eefe8bd78dd62be306166fcdd5013499f2b2847e1001c50542d9688ef9 |
| macos-26.6.2-arm64/resources-h1.txt | e589f4146a88399e6d48bca68f0bac1171c25a0f51e0d5c3a4abefdb03010425 |
| macos-26.6.2-arm64/resources-h2.txt | 0a7442467af8fc85fc08f27a7182bd1a03db2db7cd396cc4cecd308d96729724 |
| macos-26.6.2-arm64/resources-h3.txt | 906f2762a1f3507f6a881c599fa40ad282e5b9e54b8f907a9b1671fdbdd4ad94 |
| macos-15.7.9-x86-64/snapshot-1.txt | fca2864dc192371016d1cdbaaaea10e31e51555d8d22c1696cb79a87c209c2ae |
| macos-15.7.9-x86-64/resources-h1.txt | 9b3b4bcb9dbfc3577495a9d7dc67744773eca27d5a7db7f23ce03a2a072d728d |
| macos-15.7.9-x86-64/resources-h2.txt | 72b38c1d7ba53bb34419b4d9d3e200163eb646c2c169affc025c595ef3a56516 |
| macos-15.7.9-x86-64/resources-h3.txt | 481594d371250e0e3d55b9237cd5caf9def7bcf560ee4e774342580d6460064c |
