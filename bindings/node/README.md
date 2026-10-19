# Node.js

Use a reusable native Phantom client from CommonJS or ESM. This source adapter
targets Node.js 22 and 24. It does not ship prebuilt packages.

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

```js
import { Client, profiles } from './index.mjs';

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
    console.log(response.status, (await response.bytes(1024 * 1024)).toString());
  } finally { response.close(); }
} finally { await client.close(); }
```

Choose `http1`, `http2`, or `http3` explicitly. Choose `raw` for caller fields,
or a captured context offered by that profile. An unsupported combination
fails. Headers are ordered `{ name, value: Uint8Array, sensitive? }` entries,
including duplicates. Responses retain received field order and byte values.
Inputs are copied before asynchronous work starts. SharedArrayBuffer inputs
are rejected.

`read(maximumBytes)` pulls up to 65,536 bytes. Only one read can be pending.
Async iteration closes an unfinished body when you leave the loop.
`bytes(maximumBytes)` collects within your explicit limit. Close an unused
response to release its stream. The adapter holds at most one received frame
between reads and does not collect bodies in the background.
Body bytes retain their content encoding; decompression is not automatic.

Pass an `AbortSignal` to cancel setup, uploads, or body reads. It stays attached
after the response head arrives. `timeoutMs` covers the whole request through
body completion; an idle body's elapsed deadline is enforced on its next read.
Cancellation drops an idle body immediately. Cancelling a multiplexed stream
does not close another request's stream. `close()` cancels the client's work
and waits for native shutdown, with a default five-second shutdown deadline.

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
