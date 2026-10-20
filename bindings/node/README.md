# Node.js

Use a reusable native Phantom client from CommonJS or ESM. This source adapter
targets Node.js 22 and 24.

Build from the repository root, then install the local development tools:

```sh
PHANTOM_CARGO_SLOTS=2 scripts/dev/with-cargo-lock.sh \
  cargo build -p phantom-node --locked -j2
cd bindings/node
npm ci --ignore-scripts
npm run copy-native
npm test
npm run check-types
```

The Rust build uses Phantom's existing native dependencies. See the repository
installation instructions for your platform.

## Native package candidates

The [package workflow](../../.github/workflows/node-packages.yml) builds optimized
candidates for Linux x64 GNU, Windows x64 MSVC and macOS arm64. Each package
contains its native addon, JavaScript, types and dependency notices. Its receipt
records source and lockfile identities, hashes, toolchains, native linkage and
tested Node versions. It is uploaded after fresh outside-checkout installations
pass CommonJS, ESM, TypeScript and the existing loopback and Worker controls on
Node 22 and 24. Failed checks retain logs without promoting an artifact.

Download the candidate matching your host and run `npm install ./package.tgz`.
No install script or downloader runs. Keep its licenses and notices when
redistributing it. Packages remain private and are not published to npm.
The receipt establishes only its recorded host and Node versions. Older OS/libc
versions and fully static linkage are unverified. Windows needs the Microsoft
x64 Visual C++ v14 runtime, at least as recent as its recorded MSVC build tools.
OS/SDK runtime licenses are separate from the package's dependency notices.

```js
import { Client, profiles } from '@byway/phantom';

// Inspect profiles() and choose an exact build and platform.
const client = new Client({
  profile: 'chrome/154.0.8037.97/windows-11-26200/r1',
  route: 'direct',
});
try {
  const response = await client.request('https://example.com/', {
    method: 'GET', protocol: 'http2', context: 'navigation', timeoutMs: 5000,
  });
  try {
    console.log(response.status, await response.text(1024 * 1024));
  } finally { response.close(); }
} finally { await client.close(); }
```

Choose `http1`, `http2`, `http3`, or `negotiated` explicitly. The response's
`protocol` reports the actual protocol. Choose `raw` for caller fields,
or a captured context offered by that profile. An unsupported combination
fails. Headers are ordered `{ name, value: Uint8Array, sensitive? }` entries,
including duplicates. Responses retain received field order and byte values.
Inputs are copied before asynchronous work starts. SharedArrayBuffer inputs
are rejected.

## Edit a profile

Use an exact catalog profile or import the core's complete custom-profile JSON.
`Profile` owns immutable native settings; `describe()` returns a fresh editable
document. Select a catalog context to include its template in the export:

```js
import { Profile } from '@byway/phantom';

const original = Profile.fromCatalog(
  'chrome/154.0.8037.97/windows-11-26200/r1', 'navigation',
);
const document = original.describe();
document.profile.tls.session_ticket_order = 'OldestFirst';
const custom = Profile.fromDescription(document);
const customClient = new Client({profile: custom, route: 'direct'});
try {
  const response = await customClient.request('https://example.com/', {
    method: 'GET', protocol: 'http2', context: 'profile', timeoutMs: 5000,
  });
  try { console.log(await response.text(1024)); }
  finally { response.close(); }
} finally { await customClient.close(); }
```

`exportJson()` returns a fresh Buffer for storage or exact byte-based imports.
Documents include configured literal headers; handle them as potentially
sensitive data. Input is limited to 16 MiB and uses the Rust importer's strict
schema and resource bounds. `describe()` represents large integers as `bigint`;
`fromDescription()` preserves them. It accepts ordinary data objects and arrays,
rejecting getters, cycles and unsupported values. Use it instead of ordinary
`JSON.stringify()` when editing a description. Errors with code `ProfileImport`
or `ProfileExport` expose `kind` and `field` without supplied values. Client
construction still checks backend and host support.

`catalogId` is the exact ID for catalog-owned profiles and `null` for every
import, including an unchanged round trip. An import carries settings, not
browser evidence. `contexts` lists available choices. Use `profile` to apply
an attached template, or `raw` for caller fields only. Named catalog contexts
remain available on catalog-owned profiles; imports reject them. This API
imports complete JSON, not compact fingerprints or versioned bundles.

## Read a response

`read(maximumBytes)` pulls up to 65,536 bytes. Only one reader can be pending,
including a whole-body collection.
Async iteration closes an unfinished body when you leave the loop.
`bytes(maximumBytes)` collects the remaining body within your explicit limit.
It grows with received bytes rather than reserving that limit. Close an unused
response to release its stream. The adapter holds at most one received frame
between reads and does not collect bodies in the background.
Body bytes retain their content encoding; decompression is not automatic.

`text(maximumBytes)` decodes strict UTF-8 and removes one leading UTF-8 BOM.
`json(maximumBytes)` parses that text and returns `unknown` in TypeScript.
Validate its shape before using it. Both require a byte limit and consume the
remaining body, including after a partial `read()`. At EOF, text is empty and
JSON fails. Neither guesses a charset, decompresses content or rejects HTTP
error statuses. Failures use redacted `TextDecode` or `JsonDecode` codes.
Native errors, including `Cancelled`, `Timeout` and `ResponseBodyLimit`, retain
their codes. Consumption closes the body on completion or failure.

The limit bounds input bytes, not decoded text or parsed-object memory.
JSON parsing is synchronous; cancellation and the native deadline cannot
interrupt that parsing step.

## Download to a file

Use the response directly with Node's pipeline. Pass the same signal to the
request and pipeline so an abort also interrupts a pending native body read.

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

Pipeline applies backpressure and closes an unfinished body on output failure.
It does not impose a total download limit. Keep the client for further requests,
then call `await client.close()` at application shutdown. Node's pipeline may
report `AbortError` or combine cancellation errors in an `AggregateError`.
Direct response reads use `PhantomError` with `Cancelled`.

## Cancellation and client state

Pass an `AbortSignal` to cancel setup, uploads, or body reads. It stays attached
after the response head arrives. `timeoutMs` covers the whole request through
body completion; an idle body's elapsed deadline is enforced on its next read.
Cancellation drops an idle body immediately. Cancelling a multiplexed stream
does not close another request's stream. `close()` cancels the client's work
and waits for native shutdown, with a default five-second shutdown deadline.

Set client or request `timeouts` with `poolAdmissionMs`, `connectMs`,
`responseHeadMs`, `readIdleMs`, and `totalMs`. Omitted fields inherit, `null`
disables a limit, and zero is a finite limit. A ready core phase can finish
before its timer runs. Do not combine `timeoutMs`
with `timeouts.totalMs`. Timeout errors expose `timeoutPhase`; request errors
also expose `protocol` when known.

`baseUrl` joins relative request URLs using Rust's URL rules. `additionalRoots`
trusts origin DER certificates; `additionalProxyRoots` trusts HTTPS proxies.
Verification remains enabled. `closeIdleConnections()` retires idle connections;
`refreshConnections()` retires pools while preserving tickets. Active responses
remain usable. Clear cookies, DNS, client hints, Alt-Svc, or tickets explicitly
with `clearCookies()`, `clearDnsCache()`, `clearClientHints()`, `clearAltSvc()`,
or `clearSessionTickets()`.

`maximumActiveRequests` bounds requests plus unfinished bodies, defaults to 32,
and accepts 1 through 1024. Admission fails with `Capacity` when full. Each
Worker owns its environment; teardown cancels its clients without calling JS.
At most 128 open clients are allowed in one environment.
Closed clients still count until their owned work settles. Request slots do
not bound the shared napi-rs Tokio runtime's host-dependent worker count.

`AttemptBudget` wraps the shared native origin-attempt counter. Attach the same
object to concurrent requests to share its allowance. Native cookies are
opt-in with `cookies: true`; use `setCookie` and `cookieValue` for jar access.
Cookie matching uses top-level navigation semantics. A fetch template changes
headers only.
Use `route: 'proxy'` with an explicit HTTP/HTTPS or SOCKS5 URI, and optional
`proxyUsername` plus `proxyPassword`. There is no proxy-to-direct fallback.
HTTP Basic credentials follow the native challenge-driven authentication policy.

Byte uploads are replayable and limited to 16 MiB. File uploads use
`file: { path, maximumBytes }`, stream a regular file once, and enforce its
initial metadata length. Later growth is excluded; shrinkage fails. They do
not become replayable automatically. Request headers are limited to 256
entries and 64 KiB in total. Additional DER roots are limited to sixteen
certificates of at most 1 MiB each. `PhantomError.code` identifies failures;
error messages omit request inputs, proxy credentials, and local file paths.

## Next

See the [Rust API](https://docs.rs/phantom-http) for the underlying client.
