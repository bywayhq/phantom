'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test: run } = require('node:test');
const { Worker } = require('node:worker_threads');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { Client, AttemptBudget, PhantomError, profiles } = require('..');
const test = (name, action) => run(name, { timeout: 30000 }, action);

const profile = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const request = { method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000 };
const makeClient = (options = {}) => new Client({ profile, route: 'direct', ...options });
const code = (expected) => (error) => error instanceof PhantomError && error.code === expected;

async function peer(t, handler) {
  const server = http.createServer(handler);
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

test('CJS and ESM share the native catalog and classes', async () => {
  const esm = await import('../index.mjs');
  assert.equal(esm.Client, Client);
  assert.equal(esm.AttemptBudget, AttemptBudget);
  assert.ok(profiles().includes(profile));
  assert.deepEqual(esm.profiles(), profiles());
});

test('reuses connections and preserves ordered duplicate byte fields and owned uploads', async (t) => {
  const observed = [];
  const { url } = await peer(t, async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    observed.push({ port: req.socket.remotePort, headers: req.rawHeaders, body: Buffer.concat(chunks) });
    res.writeHead(200, ['X-First', 'one', 'X-Dup', 'a', 'X-Last', 'z', 'X-Dup', 'b']);
    res.end(Buffer.from([0, 255, 1]));
  });
  const client = makeClient();
  t.after(() => client.close());
  const value = Buffer.from([0x80]);
  const body = Buffer.from('original');
  const pending = client.request(url, {
    ...request, method: 'POST', body,
    headers: [{ name: 'X-Dup', value }, { name: 'X-Other', value: Buffer.from('middle') }, { name: 'X-Dup', value: Buffer.from('last') }],
  });
  body.fill(120); value[0] = 0x79;
  const response = await pending;
  assert.deepEqual(await response.bytes(3), Buffer.from([0, 255, 1]));
  const ordered = response.headers.filter(({ name }) => name.startsWith('X-'));
  assert.deepEqual(ordered.map(({ name, value }) => [name, value.toString()]), [['X-First', 'one'], ['X-Dup', 'a'], ['X-Last', 'z'], ['X-Dup', 'b']]);
  assert.equal(observed[0].body.toString(), 'original');
  const index = observed[0].headers.indexOf('X-Dup');
  assert.deepEqual(observed[0].headers.slice(index, index + 6), ['X-Dup', '\x80', 'X-Other', 'middle', 'X-Dup', 'last']);
  const second = await client.request(url, request);
  await second.bytes(3);
  assert.equal(observed[0].port, observed[1].port);
});

test('native attempt budgets atomically gate concurrent sends and stay independent', async (t) => {
  let received = 0;
  const { url } = await peer(t, (_req, res) => { received++; res.end('ok'); });
  const client = makeClient();
  t.after(() => client.close());
  const budget = new AttemptBudget(1);
  const outcomes = await Promise.allSettled([0, 1].map(() => client.request(url, { ...request, attemptBudget: budget })));
  const successful = outcomes.filter(({ status }) => status === 'fulfilled');
  assert.equal(successful.length, 1);
  const rejected = outcomes.find(({ status }) => status === 'rejected');
  assert.match(rejected.reason.code, /AttemptBudget/);
  assert.equal(budget.remaining, 0);
  assert.equal(received, 1);
  await successful[0].value.bytes(2);
  const independent = await client.request(url, { ...request, attemptBudget: new AttemptBudget(1) });
  await independent.bytes(2);
  assert.equal(received, 2);
});

test('compiled navigation headers remain protocol-specific and response encoding stays explicit', async (t) => {
  let fields;
  const encoded = require('node:zlib').gzipSync('encoded body');
  const {url} = await peer(t, (req, res) => {
    fields = req.headers;
    res.writeHead(200, {'Content-Encoding': 'gzip'});
    res.end(encoded);
  });
  const client = makeClient();
  t.after(() => client.close());
  // The macOS navigation template requires a caller-owned User-Agent.
  const userAgent = 'Phantom-Node-Test Chrome/154.0.0.0';
  const response = await client.request(url, {
    ...request, context: 'navigation',
    headers: [{name: 'User-Agent', value: Buffer.from(userAgent)}],
  });
  assert.equal(fields['user-agent'], userAgent);
  assert.match(fields['user-agent'], /Chrome\/154\./);
  assert.equal(fields.priority, undefined);
  assert.deepEqual(await response.bytes(encoded.length), encoded);
});

test('native cookies and explicit authenticated forward proxy remain isolated', async (t) => {
  let observed;
  const authentication = [];
  const { url } = await peer(t, (req, res) => {
    observed = req;
    if (req.url.startsWith('http://')) {
      authentication.push(req.headers['proxy-authorization']);
      if (!req.headers['proxy-authorization']) {
        res.writeHead(407, {'Proxy-Authenticate': 'Basic realm="loopback"'});
        res.end();
        return;
      }
    }
    res.setHeader('Set-Cookie', 'peer=yes; Path=/'); res.end('ok');
  });
  const client = makeClient({ cookies: true });
  t.after(() => client.close());
  client.setCookie(url, 'caller=yes; Path=/');
  let response = await client.request(url, request);
  await response.bytes(2);
  assert.equal(observed.headers.cookie, 'caller=yes');
  assert.match(client.cookieValue(url), /peer=yes/);
  const proxy = makeClient({ route: 'proxy', proxy: url, proxyUsername: 'user', proxyPassword: 'password' });
  t.after(() => proxy.close());
  response = await proxy.request('http://origin.invalid/path', request);
  await response.bytes(2);
  assert.equal(observed.url, 'http://origin.invalid/path');
  assert.equal(observed.headers['proxy-authorization'], `Basic ${Buffer.from('user:password').toString('base64')}`);
  assert.deepEqual(authentication, [undefined, `Basic ${Buffer.from('user:password').toString('base64')}`]);
  assert.equal(observed.headers.cookie, undefined);
});

test('pull reads remain bounded, reject overlap and release capacity on iterator return', async (t) => {
  let release;
  const { url } = await peer(t, (_req, res) => {
    res.writeHead(200); res.flushHeaders();
    release = () => res.end('abcdefghij');
  });
  const client = makeClient({ maximumActiveRequests: 1 });
  t.after(() => client.close());
  const response = await client.request(url, request);
  await assert.rejects(client.request(url, request), code('Capacity'));
  const read = response.read(3);
  await assert.rejects(response.read(3), code('ConcurrentRead'));
  release();
  assert.equal((await read).toString(), 'abc');
  assert.equal((await response.read(3)).toString(), 'def');
  await response[Symbol.asyncIterator]().return();
  const next = await client.request(url, request);
  await next[Symbol.asyncIterator]().return();
});

test('bounded collection refuses overflow and never blocks another client', async (t) => {
  const { url } = await peer(t, (_req, res) => res.end('0123456789'));
  const client = makeClient({ maximumActiveRequests: 1 });
  t.after(() => client.close());
  const response = await client.request(url, request);
  await assert.rejects(response.bytes(9), code('ResponseBodyLimit'));
  assert.equal((await (await client.request(url, request)).bytes(10)).length, 10);
});

test('abort stays attached after response head and cancels an idle body', async (t) => {
  const { url } = await peer(t, (_req, res) => { res.writeHead(200); res.flushHeaders(); });
  const client = makeClient({ maximumActiveRequests: 1 });
  t.after(() => client.close());
  const controller = new AbortController();
  controller.signal.addEventListener('abort', (event) => event.stopImmediatePropagation());
  const response = await client.request(url, { ...request, signal: controller.signal });
  controller.abort();
  await assert.rejects(response.read(), code('Cancelled'));
  const next = await client.request(url, request);
  next.close();
});

test('aborting pending setup and body reads rejects without affecting independent requests', async (t) => {
  let heads;
  const { url } = await peer(t, (req, res) => {
    if (req.url === '/healthy') return res.end('ok');
    if (req.url === '/body') { res.writeHead(200); res.flushHeaders(); }
    heads?.();
  });
  const client = makeClient();
  t.after(() => client.close());
  for (const pathname of ['/setup', '/body']) {
    const controller = new AbortController();
    const seen = new Promise((resolve) => { heads = resolve; });
    const pending = client.request(url + pathname, { ...request, signal: controller.signal });
    await seen;
    const operation = pathname === '/body' ? (await pending).read() : pending;
    controller.abort();
    await assert.rejects(operation, code('Cancelled'));
    assert.equal((await (await client.request(url + '/healthy', request)).bytes(2)).toString(), 'ok');
  }
});

test('one total deadline covers pending response body completion', async (t) => {
  const { url } = await peer(t, (_req, res) => { res.writeHead(200); res.flushHeaders(); });
  const client = makeClient();
  t.after(() => client.close());
  const response = await client.request(url, { ...request, timeoutMs: 1000 });
  await assert.rejects(response.read(), code('Timeout'));
});

test('file uploads use bounded one-shot streams and reject metadata beyond the caller limit', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-node-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, 'upload.bin');
  const payload = Buffer.alloc(131075, 0x61);
  await fs.writeFile(filename, payload);
  let received;
  const { url } = await peer(t, async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received = Buffer.concat(chunks);
    res.end('ok');
  });
  const client = makeClient();
  t.after(() => client.close());
  const response = await client.request(url, { ...request, method: 'POST', file: { path: filename, maximumBytes: payload.length } });
  await response.bytes(2);
  assert.deepEqual(received, payload);
  await assert.rejects(client.request(url, { ...request, method: 'POST', file: { path: filename, maximumBytes: 1 } }), code('InputLimit'));
});

test('abort interrupts an unfinished request and explicit shutdown cancels an idle body', async (t) => {
  let uploading;
  let resolveUpload;
  const uploadSeen = new Promise((resolve) => { resolveUpload = resolve; });
  const { url } = await peer(t, (req, res) => {
    if (req.url === '/upload') { uploading = req; req.pause(); resolveUpload(); }
    else if (req.url === '/idle') { res.writeHead(200); res.flushHeaders(); }
    else res.end('ok');
  });
  const client = makeClient();
  t.after(() => client.close());
  const controller = new AbortController();
  const pending = client.request(url + '/upload', { ...request, method: 'POST', body: Buffer.alloc(8 * 1024 * 1024), signal: controller.signal });
  await uploadSeen;
  assert.equal(uploading.complete, false);
  controller.abort();
  await assert.rejects(pending, code('Cancelled'));
  assert.equal((await (await client.request(url + '/healthy', request)).bytes(2)).toString(), 'ok');
  const idle = await client.request(url + '/idle', request);
  await client.close();
  await assert.rejects(idle.read(), code('Cancelled'));
});

test('invalid inputs produce typed redacted errors and explicit shutdown rejects new work', async () => {
  assert.throws(() => makeClient({ profile: 'secret-profile' }), (error) => code('UnknownProfile')(error) && !error.message.includes('secret-profile'));
  const client = makeClient();
  await assert.rejects(client.request('http://secret.invalid', { ...request, protocol: 'secret-protocol' }), (error) => code('InvalidProtocol')(error) && !error.message.includes('secret'));
  await assert.rejects(client.request('http://127.0.0.1', undefined), code('InvalidArgument'));
  await assert.rejects(client.request('http://127.0.0.1', { ...request, signal: {} }), code('InvalidArgument'));
  const shared = new Uint8Array(new SharedArrayBuffer(4));
  await assert.rejects(client.request('http://127.0.0.1', { ...request, body: shared }), code('InvalidArgument'));
  const hidden = Buffer.from(new SharedArrayBuffer(4));
  Object.defineProperty(hidden, 'buffer', {value: new ArrayBuffer(4)});
  await assert.rejects(client.request('http://127.0.0.1', { ...request, body: hidden }), code('InvalidArgument'));
  const foreign = require('node:vm').runInNewContext('new SharedArrayBuffer(4)');
  await assert.rejects(client.request('http://127.0.0.1', { ...request, body: Buffer.from(foreign) }), code('InvalidArgument'));
  await client.close();
  await assert.rejects(client.request('http://127.0.0.1', request), code('ClientClosed'));
});

test('Worker teardown cancels its native work without closing another environment', async (t) => {
  const { url } = await peer(t, (req, res) => {
    if (req.url === '/healthy') res.end('ok');
    else { res.writeHead(200); res.flushHeaders(); }
  });
  const worker = new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    const { Client } = require(workerData.module);
    (async () => {
      const client = new Client({profile: workerData.profile, route: 'direct'});
      const response = await client.request(workerData.url, workerData.request);
      parentPort.postMessage('ready');
      await response.read();
    })().catch(error => parentPort.postMessage({error: error.code}));
  `, { eval: true, workerData: { module: path.resolve(__dirname, '..'), profile, url, request } });
  t.after(() => worker.terminate());
  assert.deepEqual(await once(worker, 'message'), ['ready']);
  await worker.terminate();
  const client = makeClient();
  t.after(() => client.close());
  assert.equal((await (await client.request(url + '/healthy', request)).bytes(2)).toString(), 'ok');
});

test('a fresh Worker reloads after the last native environment terminates pending work', async () => {
  const source = `
    const assert = require('node:assert/strict');
    const http = require('node:http');
    const { once } = require('node:events');
    const { Worker } = require('node:worker_threads');
    const modulePath = process.argv[1];
    const profile = process.argv[2];
    const sockets = new Set();
    const closures = [];
    let sawSetup;
    const setup = new Promise(resolve => { sawSetup = resolve; });
    const server = http.createServer((req, res) => {
      if (req.url === '/healthy') { res.end('ok'); return; }
      closures.push(once(req.socket, 'close', {signal: AbortSignal.timeout(5000)}));
      if (req.url === '/setup') sawSetup();
      else { res.writeHead(200); res.flushHeaders(); }
    });
    server.on('connection', socket => {
      sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    });
    const workerSource = \`
      const {parentPort, workerData} = require('node:worker_threads');
      const {Client} = require(workerData.modulePath);
      (async () => {
        const client = new Client({profile: workerData.profile, route: 'direct'});
        const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 10000};
        if (workerData.pending) {
          // The Android profile admits one HTTP/1 request per origin. Keep both
          // operations pending without making the body request wait for setup.
          const setupClient = new Client({profile: workerData.profile, route: 'direct'});
          const setup = setupClient.request(workerData.url + '/setup', options);
          const body = await client.request(workerData.url + '/body', options);
          const read = body.read();
          parentPort.postMessage('pending');
          await Promise.all([setup, read]);
          throw new Error('unfinished requests unexpectedly completed');
        }
        const response = await client.request(workerData.url + '/healthy', options);
        const value = (await response.bytes(2)).toString();
        await client.close();
        parentPort.postMessage(value);
      })().catch(error => { console.error(error); process.exitCode = 1; });
    \`;
    (async () => {
      const timer = setTimeout(() => { console.error('Worker reload control timed out'); process.exit(1); }, 15000);
      timer.unref();
      const workers = [];
      try {
        assert.equal(require.cache[require.resolve(modulePath)], undefined);
        server.listen(0, '127.0.0.1'); await once(server, 'listening');
        const url = 'http://127.0.0.1:' + server.address().port;
        const first = new Worker(workerSource, {eval: true, workerData: {modulePath, profile, url, pending: true}});
        workers.push(first);
        assert.deepEqual(await once(first, 'message'), ['pending']);
        await setup;
        assert.equal(closures.length, 2);
        await first.terminate();
        await Promise.all(closures);
        const second = new Worker(workerSource, {eval: true, workerData: {modulePath, profile, url, pending: false}});
        workers.push(second);
        const exited = once(second, 'exit');
        assert.deepEqual(await once(second, 'message'), ['ok']);
        assert.deepEqual(await exited, [0]);
        assert.equal(require.cache[require.resolve(modulePath)], undefined);
        assert.equal(Object.keys(require.cache).some(name => name.endsWith('phantom.node')), false);
        console.log('worker-only reload ok');
      } finally {
        for (const worker of workers) await worker.terminate();
        for (const socket of sockets) socket.destroy();
        await new Promise(resolve => server.close(resolve));
        clearTimeout(timer);
      }
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `;
  const {stdout, stderr} = await promisify(execFile)(process.execPath, ['-e', source, path.resolve(__dirname, '..'), profile], {timeout: 20000});
  assert.equal(stdout.trim(), 'worker-only reload ok');
  assert.equal(stderr, '');
});

test('a live response retains its client across forced garbage collection', async () => {
  const source = `
    const assert = require('node:assert/strict');
    const http = require('node:http');
    const { once } = require('node:events');
    const { setImmediate } = require('node:timers/promises');
    const { Client } = require(process.argv[1]);
    (async () => {
      let finish;
      const server = http.createServer((_req, res) => {
        res.writeHead(200); res.flushHeaders(); finish = () => res.end('alive');
      });
      server.listen(0, '127.0.0.1'); await once(server, 'listening');
      let client = new Client({profile: process.argv[2], route: 'direct'});
      const response = await client.request('http://127.0.0.1:' + server.address().port,
        {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000});
      const weak = new WeakRef(client);
      client = null;
      for (let i = 0; i < 10; i++) { global.gc(); await setImmediate(); }
      assert.ok(weak.deref(), 'response must retain its client');
      finish();
      assert.equal((await response.bytes(5)).toString(), 'alive');
      await new Promise(resolve => server.close(resolve));
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `;
  await promisify(execFile)(process.execPath, ['--expose-gc', '-e', source, path.resolve(__dirname, '..'), profile], { timeout: 20000 });
});

test('direct native byte inputs reject actual shared or detached backing', async (t) => {
  const native = require('../phantom.node');
  const environment = new native.NativeEnvironment();
  const shared = Buffer.from(new SharedArrayBuffer(4));
  Object.defineProperty(shared, 'buffer', {value: new ArrayBuffer(4)});
  assert.throws(() => environment.client({profile, route: 'direct', additionalRoots: [shared]}), /PHANTOM:InvalidArgument:/);
  const client = environment.client({profile, route: 'direct'});
  t.after(() => client.close(5000));
  const options = {url: 'http://127.0.0.1', ...request};
  const submit = (overrides) => client.request({...options, ...overrides}, new native.NativeCancellation());
  assert.throws(() => submit({body: shared}), /PHANTOM:InvalidArgument:/);
  assert.throws(() => submit({headers: [{name: 'x-shared', value: shared}]}), /PHANTOM:InvalidArgument:/);
  const foreign = Buffer.from(require('node:vm').runInNewContext('new SharedArrayBuffer(4)'));
  assert.throws(() => submit({body: foreign}), /PHANTOM:InvalidArgument:/);
  const backing = new ArrayBuffer(4);
  const detached = Buffer.from(backing);
  structuredClone(backing, {transfer: [backing]});
  assert.throws(() => submit({body: detached}), /PHANTOM:InvalidArgument:/);
  const {url} = await peer(t, async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    res.end(Buffer.concat(chunks));
  });
  for (const body of [Buffer.alloc(0), Buffer.from('before-offset-after').subarray(7, 13), Buffer.from(new ArrayBuffer(4, {maxByteLength: 8}))]) {
    const response = await client.request({url, ...request, method: 'POST', body}, new native.NativeCancellation());
    const chunks = [];
    for (;;) { const part = await response.read(65536); if (part === null) break; chunks.push(part); }
    assert.deepEqual(Buffer.concat(chunks), body);
  }
});
