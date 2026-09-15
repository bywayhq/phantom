# Chrome HTTP/3 capture design

This workflow captures one forced Chrome HTTP/3 connection on loopback. Its
wire oracle is the authenticated byte stream received by the server, not a
fingerprint summary. It records:

- the raw ordered client QUIC transport-parameter extension before parsing;
- the raw first HTTP/3 control-stream `SETTINGS` frame and ordered settings;
- the first request `HEADERS` frame, QPACK encoder/decoder stream bytes, and
  QPACK-decoded request headers in order.

It does not retain a certificate private key, TLS key log, browser profile,
pcap, NetLog, or qlog. Those are temporary diagnostic inputs only.

The retained fixture is
`fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt`, with
SHA-256 `0199af21d3c623600fb4bdc86c2fd3d019820baaa3fe9b38860adf9b020167de`.
That exact capture did not enable a TLS key log, so its `launch_arguments`
correctly omits `--ssl-key-log-file`. The reproduction workflow below includes
the temporary key-log flag so an operator can independently decrypt its pcap;
the placeholder must therefore remain in any fixture captured by that workflow.

## Capture seam

```text
Chrome 152
  │ UDP/QUIC on loopback
  ├──────────────> temporary pcap + Chrome key log (diagnostic only)
  │
  └──────────────> pinned aioquic 1.3.0 server
                    ├─ raw TLS QUIC transport-parameter extension
                    ├─ raw client unidirectional streams
                    └─ decoded QPACK header list
```

`scripts/capture/chrome_http3.py` pins aioquic because it hooks the private
transport-parameter parser at the only point where the authenticated extension
bytes still retain parameter order and variable-length integer widths. The
server also records stream bytes before aioquic turns `SETTINGS` into a map.
The hook is capture-only and is not a Phantom runtime dependency.

NetLog is useful supporting evidence, but is not the byte oracle. Chromium
explicitly gives NetLog events no compatibility guarantee, and qlog
`parameters_set` represents semantic fields rather than the original ordered
encoding. CDP `Browser.getVersion` and `Page.navigate` are useful automation
controls, but neither exposes QUIC or H3 bytes. The smaller launch below gets
the version from the executable and performs one command-line navigation.

## Reproduce locally

Prerequisites are Chrome, OpenSSL, `tcpdump`, and `uv`. The script binds only a
loopback address, accepts one connection, limits each captured stream to 256
KiB, times out after 30 seconds, and refuses to emit a fixture containing
`authorization`, `cookie`, or `proxy-authorization`.

Run from the repository root. Choose a fixture output outside the temporary
directory:

```sh
fixture_path="$PWD/chrome-h3-capture.txt"
capture_dir="$(mktemp -d /tmp/phantom-chrome-h3.XXXXXX)"

cleanup_capture() {
  case "$capture_dir" in
    /tmp/phantom-chrome-h3.*) rm -R -- "$capture_dir" ;;
    *) return 1 ;;
  esac
}
trap cleanup_capture EXIT INT TERM

uv venv "$capture_dir/venv"
uv pip install --python "$capture_dir/venv/bin/python" aioquic==1.3.0

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$capture_dir/key.pem" \
  -out "$capture_dir/cert.pem" \
  -subj '/CN=server.phantom.test' \
  -addext 'subjectAltName=DNS:server.phantom.test'

spki="$(
  openssl x509 -in "$capture_dir/cert.pem" -pubkey -noout |
    openssl pkey -pubin -outform der |
    openssl dgst -sha256 -binary |
    openssl base64 -A
)"

launch_arguments='--headless=new --user-data-dir=<temporary-profile> --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-default-apps --no-proxy-server --enable-quic --origin-to-force-quic-on=server.phantom.test:9447 --host-resolver-rules=MAP server.phantom.test:9447 127.0.0.1:9447, EXCLUDE localhost --ignore-certificate-errors-spki-list=<certificate-spki> --ssl-key-log-file=<temporary-keylog> --dump-dom'

tcpdump -U -i lo0 -w "$capture_dir/loopback.pcap" udp port 9447 \
  >"$capture_dir/tcpdump.log" 2>&1 &
tcpdump_pid=$!

"$capture_dir/venv/bin/python" -m scripts.capture.chrome_http3 \
  --certificate "$capture_dir/cert.pem" \
  --private-key "$capture_dir/key.pem" \
  --client-version "$(
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' --version |
      awk '{print $3}'
  )" \
  --operating-system "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))" \
  --launch-arguments "$launch_arguments" \
  >"$capture_dir/fixture.txt" &
server_pid=$!

sleep 1
'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
  --headless=new \
  --user-data-dir="$capture_dir/profile" \
  --no-first-run \
  --no-default-browser-check \
  --disable-background-networking \
  --disable-component-update \
  --disable-default-apps \
  --no-proxy-server \
  --enable-quic \
  --origin-to-force-quic-on=server.phantom.test:9447 \
  --host-resolver-rules='MAP server.phantom.test:9447 127.0.0.1:9447, EXCLUDE localhost' \
  --ignore-certificate-errors-spki-list="$spki" \
  --ssl-key-log-file="$capture_dir/client.keys" \
  --dump-dom \
  https://server.phantom.test:9447/ \
  >"$capture_dir/chrome.out" 2>"$capture_dir/chrome.err" &
chrome_pid=$!

wait "$server_pid"
sleep 1
kill "$chrome_pid" "$tcpdump_pid" 2>/dev/null || true
wait "$chrome_pid" "$tcpdump_pid" 2>/dev/null || true
cp "$capture_dir/fixture.txt" "$fixture_path"
```

The pcap and key log can be opened together in Wireshark before the shell exits
if independent packet decryption is needed. Do not copy either into the
repository or CI artifacts. The fixture contains no key material. The
SPKI-scoped exception is preferable to a global certificate-verification
override and is part of Chromium's documented local QUIC workflow.

## Fixture schema

`phantom-http3-client-startup-v1` is line-oriented and ordered. Byte strings
are lowercase hexadecimal.

1. Capture metadata: timestamp, exact client/OS, hostname, listener, launch
   mode and normalized launch arguments, capture tool, QUIC version, and ALPN.
2. Raw and normalized transport-parameter extension bytes.
3. One ordered line per transport parameter, including identifier and length
   varint widths and the exact value bytes.
4. Raw and normalized first `SETTINGS` frame plus the exact control-stream
   prefix (stream type followed by the frame).
5. One ordered line per H3 setting, including identifier and value varint
   widths.
6. The raw first request `HEADERS` frame and the QPACK encoder and decoder
   stream bytes observed through that request.
7. One ordered hex name/value line per decoded request header.

The fixture parser should reject missing, repeated, reordered, or extra fields;
invalid hex; malformed variable-length integers; duplicate parameters or
settings; a non-loopback listener; a non-v1 QUIC version; a non-`h3` ALPN; or
any credential-bearing request header.

## Entropy normalization

Normalization is span-aware and preserves all ordering, element counts,
varint widths, and value lengths.

| Input | Normalization |
| --- | --- |
| QUIC TP `initial_source_connection_id` (`0x0f`) | Zero value bytes in place. Chrome 152 currently sends a zero-length value. |
| Reserved QUIC TP (`31 * N + 27`) | Replace the identifier with the first reserved value of the same varint width and zero its value bytes. |
| QUIC TP `version_information` (`0x11`) | Replace each reserved `0x?a?a?a?a` version with `0x0a0a0a0a`; preserve its position. |
| Reserved H3 setting (`31 * N + 33`) | Replace the identifier with the first reserved value of the same varint width and replace the value with zero using the original width. |
| Packet capture | Never use ciphertext as the semantic oracle. A diagnostic differential may remove timestamps, CIDs, packet numbers, header protection, and ciphertext only after key-log-assisted decryption has reconstructed the same authenticated bytes. |

Do not sort parameters or settings during normalization. Do not collapse
varint widths. Do not remove GREASE entries. Do not normalize QPACK bytes or
request header order.

## Chrome 152 observations

The loop was executed on Chrome `152.0.7977.83`, macOS `15.5` (`24F74`). A
packet-assisted run captured 23 UDP packets and produced all five TLS 1.3
client/server handshake and traffic-secret labels; the pcap, key log,
certificate, key, and profile were then removed. This was a separate validation
run from the retained fixture, which did not create a key log.

Three independent fresh-profile connections showed:

- QUIC v1 with ALPN `h3`;
- 13 client transport parameters each time, with the order different in all
  three captures;
- one reserved transport parameter whose identifier, value, and value length
  changed;
- a reserved version inside `version_information` whose position changed;
- stable H3 settings `0x01=65536`, `0x06=262144`, `0x07=100`, and `0x33=1`, in
  that order, followed by one reserved setting with changing identifier,
  value, and varint width;
- the same first request QPACK field section and the same 17 decoded headers in
  order across the three samples.

QUICHE's own history describes transport-parameter serialization as
randomized. Therefore a Chrome profile must model its permutation and GREASE
policy; it must not hard-code one captured transport-parameter order and call
that canonical. Tests need two complementary forms:

- seeded exact tests for Phantom's serializer, including a retained raw
  fixture; and
- policy tests over several seeds that preserve the invariant parameter set,
  allowed widths and values, one GREASE element, and non-constant order.

The H3 `SETTINGS` sequence is a fixed ordered prefix followed by randomized
GREASE in these observations. A larger retained sample is needed before
claiming the exact GREASE width/value distribution. Header-order claims are
independent of the raw QPACK representation and should compare the decoded
ordered list; raw QPACK remains a separate differential.

Run the deterministic schema and normalization checks without Cargo:

```sh
uv run --with aioquic==1.3.0 \
  python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
uvx ruff check scripts/capture
uvx ruff format --check scripts/capture
```

## Primary references

- [Chromium local QUIC workflow](https://chromium.googlesource.com/experimental/website/+/HEAD/site/quic/playing-with-quic.md)
- [Chromium SSL key-log setup](https://chromium.googlesource.com/chromium/src/+/lkgr/content/browser/network_service_instance_impl.cc)
- [Chromium NetLog design and compatibility](https://chromium.googlesource.com/chromium/src/net/+/HEAD/docs/net-log.md)
- [QUICHE randomized transport-parameter serialization](https://quiche.googlesource.com/quiche/+/6a93efcba4e4339bb3b4fe14f340f4e3f60b28c7)
- [RFC 9000 QUIC transport parameters](https://www.rfc-editor.org/rfc/rfc9000.html#section-18)
- [RFC 8999 reserved QUIC versions](https://www.rfc-editor.org/rfc/rfc8999.html#section-5)
- [RFC 9114 HTTP/3 control streams and SETTINGS](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1)
- [HTTP/3 qlog events](https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema-14/draft-ietf-quic-qlog-h3-events.html)
- [Chrome DevTools Protocol Browser domain](https://chromedevtools.github.io/devtools-protocol/tot/Browser/)
- [Chrome DevTools Protocol Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [aioquic 1.3.0 source](https://github.com/aiortc/aioquic/tree/1.3.0)
