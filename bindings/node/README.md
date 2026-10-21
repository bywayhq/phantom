# Phantom for Node.js

Make requests with reusable native connection pools and explicit browser
profiles. CommonJS and ESM are supported on Node.js 22 and 24.

```js
import { Client } from '@byway/phantom';

const client = new Client({
  profile: 'chrome/154.0.8037.97/windows-11-26200/r1',
  route: 'direct',
});
try {
  const response = await client.request('https://example.com/', {
    method: 'GET', protocol: 'negotiated', context: 'raw', timeoutMs: 30_000,
  });
  try {
    console.log(response.status, await response.text(1024 * 1024));
  } finally { response.close(); }
} finally { await client.close(); }
```

This example uses Chrome's Windows settings. Use `profiles()` to list other
profiles, and reuse the client for later requests.

## Install

Packages are not published to npm yet. Download a matching candidate from the
[package workflow](../../.github/workflows/node-packages.yml) and install it:

```sh
npm install ./package.tgz
```

Candidates cover Linux x64 GNU, Windows x64 MSVC and macOS arm64 on Node 22
and 24. Each includes licenses and a receipt with source, checksums and tested
hosts. The native library is included. Windows needs the x64 Visual
C++ v14 runtime at least as recent as the recorded build tools.

## Build from source

Install the repository's
[native build tools](../../crates/phantom/src/docs/getting-started.md#install-the-build-tools).
From the repository root:

```sh
scripts/dev/with-cargo-lock.sh cargo build -p phantom-node --locked
cd bindings/node
npm ci --ignore-scripts
npm run copy-native
```

## Read a response

Choose `http1`, `http2`, `http3` or `negotiated` explicitly. `response.protocol`
reports the actual protocol. Select `raw` for caller headers, or an available
catalog context such as `navigation`. Unsupported combinations fail.

Headers are ordered `{name, value: Uint8Array, sensitive?}` entries, including
duplicates. H2/H3 caller names must be lowercase. Response headers retain
received spelling, ordering and bytes.
Inputs are copied before async work; shared byte buffers are rejected.

`read(maximumBytes)` pulls up to 65,536 bytes; `null` means EOF. Only one reader
can be pending. `bytes(maximumBytes)`, `text(maximumBytes)` and
`json(maximumBytes)` consume the remaining body within your byte limit and
close it on completion or failure. Content stays encoded unless you pass
`contentDecoding: {mode: 'advertised', maximumDecodedBytes: 1_000_000n}` and
an `accept-encoding` header. Decoded-stream and collection limits are separate.
Headers remain unchanged; `decodedContentCodings` records the selected chain.
`response.trailers` never reads the body: its state is `pending`, `unavailable`
after failure or abandonment, or `complete` after validated EOF. Complete
`headers` retain ordered names and owned byte values, including duplicates;
an empty list means no trailers. Completion survives later close or parse errors.

Text is strict UTF-8 with one leading BOM removed. JSON returns `unknown` in
TypeScript; validate its shape. Parsing is synchronous and cannot be interrupted
by native deadlines. The byte limit bounds input, not parsed-object memory.
HTTP error statuses remain responses. Decode failures use `TextDecode` or
`JsonDecode`; native errors retain their codes.

## Download to a file

Use the response directly with `pipeline`. The same signal cancels the request
and output, including a pending native read:

```js
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';

const controller = new AbortController();
const response = await client.request('https://example.com/file', {
  method: 'GET', protocol: 'http2', context: 'raw',
  signal: controller.signal, timeoutMs: 30_000,
});
try {
  await pipeline(response, createWriteStream('download.bin'), {
    signal: controller.signal,
  });
} finally { response.close(); }
```

Run this while your client is open. Pipeline applies backpressure, closes an
unfinished iterator on output failure, and imposes no total byte limit. Leaving
`for await` also closes unfinished responses. Close any unused response.

## Cancellation and deadlines

`AbortSignal` interrupts setup, uploads and body reads; it remains attached
after the response head. Other multiplexed streams remain usable. Pipeline
can report `AbortError` or `AggregateError`; direct reads use `Cancelled`.
`close()` cancels this client's work and waits up to five seconds by default.

Set client/request `timeouts` with `poolAdmissionMs`, `connectMs`,
`responseHeadMs`, `readIdleMs` and `totalMs`. Omitted fields inherit; `null`
disables a limit and zero is finite. Client limits start disabled. Response-head
time includes upload; total includes body completion. Do not combine
`timeoutMs` with `timeouts.totalMs`. Total zero rejects before sending; other
zero phase timers can race ready work. Errors expose `timeoutPhase`.

## Routing and trust

`baseUrl` joins relative URLs. `additionalRoots` extends origin trust;
`additionalProxyRoots` separately extends HTTPS-proxy trust. Both use DER and
retain certificate verification. Each allows sixteen certificates up to 1 MiB
each. `route: 'proxy'` accepts HTTP(S) and SOCKS5
URIs, with optional paired `proxyUsername`/`proxyPassword`. HTTP credentials
use Basic authentication. Proxy environment variables are ignored.

`serverSpkiPins` and `proxyServerSpkiPins` independently restrict origin and
HTTPS-proxy TLS to accepted leaf keys, while retaining chain and hostname
verification. Each takes 1..32 supplied `Uint8Array` values of exactly 32 bytes:
SHA-256 of the leaf certificate's DER SubjectPublicKeyInfo, not the whole
certificate or raw key. Inputs are copied during construction. Omit a policy
to leave it unset; an empty list is invalid. Origin pins reject cleartext
origins; proxy pins reject plaintext proxy routes but allow direct requests.

Use `await ClientCertificate.fromPem(chainBytes, keyBytes)` or
`fromDer([leafDer, ...chainDer], keyDer)` with an unencrypted key. Parsing runs
off the event loop after copying at most 16 MiB; DER chains allow 1..256 entries.
Set `clientCertificate` and/or ordered `clientCertificatesFor: [[origin, owner]]`
on a client; the last canonical matching origin wins. Server verification still
applies; proxies never receive the identity. Owners are immutable and reusable
across clients and forks. Checkpoints require matching receiving identities;
private keys are neither exported nor serialized.

## Cookies and connections

Cookies are opt-in with `cookies: true`. Use `setCookie`, `cookieValue` and
`clearCookies`; matching uses top-level navigation semantics independently of
header templates. `closeIdleConnections()` closes idle connections;
`refreshConnections()` retires pools while active responses finish. Both retain
learned state. Clear DNS, hints, alternatives or tickets with `clearDnsCache`,
`clearClientHints`, `clearAltSvc` and `clearSessionTickets`.
`clearAltSvcRacingHistory()` resets racing decisions while retaining alternatives.

## Budgets and transfer limits

Attach a shared `new TransferControl({downloadBytes: 1_000_000n,
downloadBytesPerSecond: 100_000n})` through request `transferControl` for native
body-byte caps, pacing and `snapshot()` counters. Download caps and rates count
encoded body bytes. Limits accept safe integer numbers or `bigint` within u64;
zero caps are valid and rates must be positive. The five counters are `bigint`.
Reservations include cancelled paced chunks;
resends count again. Encoded/decoded body counts exclude transport overhead,
and decoded counts can include the binding's buffered unread remainder.

Attach one `AttemptBudget` to concurrent requests through `attemptBudget`.
It counts initial origin attempts and resends. Counts accept safe integer
numbers or `bigint` within the native platform's range. `remaining` returns a
number through `Number.MAX_SAFE_INTEGER`, then `bigint`. `tryAdmit()` charges
attempts outside Phantom and throws `AttemptBudgetExhausted` when exhausted;
Phantom already charges requests carrying that budget. Admissions are not
refunded, including when no bytes are sent. Setup/proxy negotiation are separate.

## Send a body

Replayable byte uploads are limited to 16 MiB. `file: {path, maximumBytes}`
streams a regular file once using its initial length; growth is excluded and
shrinkage fails. A required replay fails rather than rereading a one-shot file.
For streaming sources, pass `body` an `AsyncIterable<Uint8Array>`, including a
byte-mode Node `Readable`. Native demand copies at most 64 KiB per chunk.
Set `bodyLength` for a known byte count; unread suffixes are not validated.
Producers are one-shot. Cancellation and early completion call the iterator's
`return()` cooperatively. Client closure waits for cleanup within its deadline;
unresolved cleanup remains owned. An iterator cannot await its own client's close.
Upload errors expose caller failures through `cause` and `cleanupError`;
automatic formatting omits their text. Cleanup errors may settle later and
are reported by `close()`.

Use `trailers` for ordered static fields sent after a successful body; H2/H3
names must be lowercase. `expectContinueMs` opts into waiting for 100 Continue
before sending a body, including a zero wait. It accepts exact nonnegative
safe integer numbers or u64 `bigint`; the wait counts toward existing deadlines.
A final response before the wait ends sends no upload bytes; producer cleanup
stays cooperative.
Headers and trailers together allow 256 entries/64 KiB.

`await PreparedBody.form(orderedPairs, {maximumBytes})` and
`await PreparedBody.multipart(parts, {boundary, maximumBytes})` prepare reusable
native bodies. Multipart parts use `{name, text}` or `{name, bytes}`, with optional
`filename` and `contentType`. Pass the frozen owner as `body` and put its exact
`contentType` in your ordered headers or a profile's caller slot. `byteLength` is
always bigint; the encoded limit includes multipart framing. Encoding runs on
native CPU workers and is not preemptible.

For one-shot multipart files or streams, use `multipart` instead of `body`:

```js
const response = await client.request(url, {method: 'POST', protocol: 'http1',
  context: 'raw', headers: [{name: 'Content-Type', value: Buffer.from('multipart/form-data; boundary=upload')}],
  multipart: {boundary: 'upload', maximumBytes: 1048576, parts: [
    {name: 'tag', text: 'first'}, {name: 'tag', text: 'last'},
    {name: 'file', file: {path: './image.bin', maximumBytes: 900000}, filename: 'image.bin'},
  ]}});
```

A `stream` part accepts a closeable async iterator or Node `Readable`. The
request owns all streams after validation; use each source in one request.
Only the active part is pulled, and files open on demand. Successful body EOF
awaits cooperative cleanup; `return()` on an unstarted generator need not run
its `finally`. Part/count limits and ownership rules are in `RequestOptions`.

## Capacity and errors

`maximumActiveRequests` counts requests plus unfinished bodies: default 32,
range 1..1024. Full admission returns `Capacity`. Each Worker has an environment
with at most 128 open clients; closed clients remain charged until their work
settles. `PhantomError.code` identifies failures, with `protocol` and
`timeoutPhase` when known. Messages omit inputs, credentials and file paths.

## Observe a request

Attach `diagnostics: new RequestDiagnostics({maximumEvents: 128})` and keep the
owner to call `snapshot()`, including after failure or cancellation. It returns
`null` before attachment; `response_head` means send success, not body completion.
Events retain order, exact bigint nanoseconds and dropped counts. Missing phases
are unobserved. Frozen records contain owned, editable ALPN/DER buffers, within
a 16 MiB copy limit. Each owner is single-use and does not enable secret logs.

## Edit a profile

```js
import { Profile } from '@byway/phantom';

const original = Profile.fromCatalog(
  'chrome/154.0.8037.97/windows-11-26200/r1', 'navigation',
);
const document = original.describe();
document.profile.tls.session_ticket_order = 'OldestFirst';
const custom = Profile.fromDescription(document);
```

Pass `custom` as the client profile and request `context: 'profile'` to use
its attached template. `raw` omits template headers. Named contexts require
catalog ownership. `catalogId` is `null` for imports; settings alone carry no
browser-fidelity claim. `contexts` lists choices.

Profiles are immutable. `describe()` returns a fresh document and uses `bigint`
for large integers. Use `fromDescription()` to preserve them; ordinary
`JSON.stringify()` cannot. `exportJson()` and `Profile.importJson()` exchange
complete JSON bytes within 16 MiB and the core's schema/structural limits.
Documents can contain literal headers. Import/export errors expose redacted
`kind` and `field`. Shared buffers, accessors, cycles and unsupported values
are rejected.

Partial imports use `Profile.importJa3(text, {base: original})`, `importAkamai`,
`importJa4(text, {base: original, format: 'original'})`, `importClientHello` or
`importQuicTransport`. Results expose `profile`, `observedFields` and
`supplementedFields`. JA3/JA4 require raw descriptions, not hashes; JA4 also
accepts `format: 'sorted'`. ClientHello bytes include the four-byte handshake
header without TLS records; QUIC bytes are extension 57's payload. Missing
settings come from the explicit base.

## Redirects

Set client/request `redirectPolicy: {mode: 'limited', maximumHops: 5}` to follow
redirects; the default returns them. Request policies replace client policies;
`{mode: 'none'}` stops following. `redirectHistoryLimit: 3` retains the first
selected hops in `response.redirectHistory`, including their URLs. Later hops
increment `omittedHops`; disabled history is `null`.

## Retries

Caller retries default to disabled. Set
`retryPolicy: {statusRetry: {statuses: [503], maximum: 2, delayMs: 100}}` on a
client or request. Request policies replace the whole policy; `{}` disables it.
Connection retries, replay controls, capped backoff, jitter and bounded
`Retry-After` use the same core policies; see [types](index.d.ts).
All attempts share deadlines and `AttemptBudget`. Core replay and credential
rules apply; one-shot files cannot be resent with their body.

## Share session state

Use `const worker = client.fork({cookies: true, tickets: true})` for independent
pools with selected live state. Close each client. Selectors are `cookies`,
`dns`, `clientHints`, `discovery` and `tickets`, all false by default. Selected
learning, expiry and clearing are shared; other state starts empty. Sharing does
not enable disabled features. Profile, routes, trust and timeouts are retained.
Admission and shutdown stay independent. You can fork a closed source into an
open client. Shared tickets remain single-use; this does not save a checkpoint.

## Encrypted session checkpoints

Use `const bytes = await client.exportSession(key)` with a random 32-byte key;
keep the key separately. `await client.restoreSession(bytes, key)` returns
independent state and pools without changing the receiving client. Checkpoints
are limited to 32 MiB. Optional `receivingRoutes` validate request-only ticket
routes; profile, trust and default route must match. Cookies, direct Alt-Svc and
TLS tickets use core persistence rules; this is not serialized configuration.
CPU work runs off the event loop and is not abortable.

## Next

From the repository root, build and run the loopback tests and type checks with
the independent HTTP/3 peer setup:

```sh
scripts/dev/with-cargo-lock.sh scripts/dev/check-node-binding.sh
```

See the [Rust API](https://docs.rs/phantom-http) for underlying behavior.
