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

This example selects Windows Chrome. Inspect `profiles()` for your host's
profile. Reuse the client for subsequent requests.

## Native package candidates

Packages are not published to npm yet. Download a matching candidate from the
[package workflow](../../.github/workflows/node-packages.yml) and install it:

```sh
npm install ./package.tgz
```

Candidates cover Linux x64 GNU, Windows x64 MSVC and macOS arm64. They are
installed and tested outside the checkout on Node 22 and 24. Each includes
licenses and source/checksum/dependency receipts. No install downloader runs.
Only recorded hosts and runtimes are verified. Windows needs the x64 Visual
C++ v14 runtime at least as recent as the receipt's build tools.

For a source build, install the repository's
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

## Cancellation and client state

`AbortSignal` interrupts setup, uploads and body reads; it remains attached
after the response head. Other multiplexed streams remain usable. Pipeline
can report `AbortError` or `AggregateError`; direct reads use `Cancelled`.
`close()` cancels this client's work and waits up to five seconds by default.

Set client/request `timeouts` with `poolAdmissionMs`, `connectMs`,
`responseHeadMs`, `readIdleMs` and `totalMs`. Omitted fields inherit; `null`
disables a limit and zero is finite. Client limits start disabled. Response-head
time includes upload; total includes body completion. Do not combine
`timeoutMs` with `timeouts.totalMs`. An idle body's deadline is checked on its
next read; ready work can win against zero. Errors expose `timeoutPhase`.

`baseUrl` joins relative URLs. `additionalRoots` extends origin trust;
`additionalProxyRoots` separately extends HTTPS-proxy trust. Both use DER and
retain certificate verification. `route: 'proxy'` accepts HTTP(S) and SOCKS5
URIs, with optional paired `proxyUsername`/`proxyPassword`. HTTP credentials
use Basic authentication. Proxy environment variables are ignored.

Cookies are opt-in with `cookies: true`. Use `setCookie`, `cookieValue` and
`clearCookies`; matching uses top-level navigation semantics independently of
header templates. `closeIdleConnections()` closes idle connections;
`refreshConnections()` retires pools while active responses finish. Both retain
learned state. Clear DNS, hints, alternatives or tickets with `clearDnsCache`,
`clearClientHints`, `clearAltSvc` and `clearSessionTickets`.
`clearAltSvcRacingHistory()` resets racing decisions while retaining alternatives.

Attach one `AttemptBudget` to concurrent requests through `attemptBudget`.
It counts initial origin attempts and resends. Counts accept safe integer
numbers or `bigint` within the native platform's range. `remaining` returns a
number through `Number.MAX_SAFE_INTEGER`, then `bigint`. `tryAdmit()` charges
attempts outside Phantom and throws `AttemptBudgetExhausted` when exhausted;
Phantom already charges requests carrying that budget. Admissions are not
refunded, including when no bytes are sent. Setup/proxy negotiation are separate.

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

Request headers allow 256 entries/64 KiB. Additional roots allow sixteen
certificates up to 1 MiB each.

`maximumActiveRequests` counts requests plus unfinished bodies: default 32,
range 1..1024. Full admission returns `Capacity`. Each Worker has an environment
with at most 128 open clients; closed clients remain charged until their work
settles. `PhantomError.code` identifies failures, with `protocol` and
`timeoutPhase` when known. Messages omit inputs, credentials and file paths.

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
settings come from the explicit base. Imports do not establish browser fidelity.

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

## Next

Run `npm test` and `npm run check-types` from this directory after building.
See the [Rust API](https://docs.rs/phantom-http) for underlying behavior.
