'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const {createHash} = require('node:crypto');
const http = require('node:http');
const http2 = require('node:http2');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const {Readable} = require('node:stream');
const {test} = require('node:test');
const {Client, AttemptBudget, PhantomError} = require('..');
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'POST', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const code = (name) => (error) => error instanceof PhantomError && error.code === name;

async function peer(t, handler) {
  const server = http.createServer(handler);
  const sockets = new Set();
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('clientError', (_, socket) => socket.destroy());
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); });
  return `http://127.0.0.1:${server.address().port}`;
}

test('HTTP/1 streams known and unknown lengths without whole-body materialization', {timeout: 30000}, async (t) => {
  const observed = [];
  const url = await peer(t, async (request, response) => {
    const hash = createHash('sha256'); let count = 0;
    for await (const chunk of request) { count += chunk.length; hash.update(chunk); }
    observed.push({count, hash: hash.digest('hex'), length: request.headers['content-length'], transfer: request.headers['transfer-encoding'], headers: request.rawHeaders});
    response.end('ok');
  });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const completions = [];
  const chunk = Buffer.alloc(70000, 0xa5), repetitions = 250;
  const expected = createHash('sha256'); for (let i = 0; i < repetitions; i++) expected.update(chunk);
  const digest = expected.digest('hex');
  for (const known of [true, false]) {
    let finished = false;
    completions.push(() => finished);
    async function* source() { try { yield Buffer.alloc(0); for (let i = 0; i < repetitions; i++) yield chunk; } finally { finished = true; } }
    const response = await client.request(url, {...options, body: Readable.from(source()),
      bodyLength: known ? BigInt(chunk.length * repetitions) : undefined,
      headers: [{name: 'X-First', value: Buffer.from('one')}, {name: 'X-Last', value: Buffer.from('two')}]});
    assert.equal(await response.text(2), 'ok');
    const wire = observed.at(-1);
    assert.equal(wire.count, chunk.length * repetitions); assert.equal(wire.hash, digest);
    assert.equal(wire.length, known ? String(wire.count) : undefined);
    assert.equal(wire.transfer, known ? undefined : 'chunked');
    assert.ok(wire.headers.indexOf('X-First') < wire.headers.indexOf('X-Last'));
  }
  await client.close();
  assert.ok(completions.every((finished) => finished()));
});

test('zero declared length does not pull and demanded mismatches fail without exposing source text', {timeout: 30000}, async (t) => {
  const url = await peer(t, (request, response) => { request.resume(); request.on('end', () => response.end('ok')); });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  let pulls = 0, returns = 0;
  const source = { [Symbol.asyncIterator]() { return this; }, async next() { pulls++; return {done: false, value: Buffer.from('extra')}; }, async return() { returns++; return {done: true}; } };
  const empty = await client.request(url, {...options, body: source, bodyLength: 0n});
  assert.equal(await empty.text(2), 'ok');
  await client.close();
  assert.equal(pulls, 0); assert.equal(returns, 1);
  const other = new Client({profile, route: 'direct'}); t.after(() => other.close());
  for (const [length, bytes] of [[10, 'short'], [1, 'long']]) {
    async function* mismatch() { yield Buffer.from(bytes); }
    await assert.rejects(other.request(url, {...options, body: mismatch(), bodyLength: length}), code('UploadLength'));
  }
  async function* broken() { throw new Error('secret-source-value'); }
  await assert.rejects(other.request(url, {...options, body: broken()}), (error) => code('UploadSource')(error) && !error.message.includes('secret'));
  for (const bodyLength of [-1, true, 1.5, Number.MAX_SAFE_INTEGER + 1, 1n << 64n]) {
    await assert.rejects(other.request(url, {...options, body: source, bodyLength}), code('InvalidArgument'));
  }
  await assert.rejects(other.request(url, {...options, body: source, file: {path: 'unused', maximumBytes: 1}}), code('InvalidArgument'));
});

test('cancelled HTTP/2 producers leave an already live sibling and connection intact', {timeout: 30000}, async (t) => {
  const sessions = new Set(), selected = new Map();
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem'), settings: {initialWindowSize: 0}});
  server.on('session', (session) => { sessions.add(session); session.on('error', () => {}); });
  let finishSibling, siblingSession;
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {});
    if (headers[':path'] === '/warm') { stream.respond({':status': 200}); stream.end('warm'); }
    else if (headers[':path'] === '/healthy') { siblingSession = stream.session; stream.respond({':status': 200}); finishSibling = () => stream.end('healthy'); }
    else {
      let received = 0; stream.on('data', (bytes) => { received += bytes.length; });
      const closed = new Promise((resolve) => stream.on('close', () => resolve({reset: stream.rstCode, received})));
      selected.set(headers[':path'], {session: stream.session, closed});
      stream.respond({':status': 200});
    }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const session of sessions) session.destroy(); await new Promise((resolve) => server.close(resolve)); });
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')], timeouts: {totalMs: 5000}}); t.after(() => client.close());
  const url = `https://127.0.0.1:${server.address().port}`;
  const request = {...options, method: 'GET', protocol: 'http2'};
  const warm = await client.request(url + '/warm', request); assert.equal(await warm.text(4), 'warm');
  for (const mode of ['abort', 'close', 'total', 'total-zero', 'idle']) {
    const controller = new AbortController(); let returned = false;
    const source = { [Symbol.asyncIterator]() { return this; }, async next() { return mode === 'total-zero' ? {done: true} : {done: false, value: Buffer.alloc(65536)}; }, async return() { returned = true; return {done: true}; } };
    const response = await client.request(url + '/' + mode, {...request, method: 'POST', body: source, signal: controller.signal,
      bodyLength: mode === 'total-zero' ? 0n : undefined, timeoutMs: undefined,
      timeouts: mode === 'idle' ? {readIdleMs: 50} : undefined});
    const healthy = await client.request(url + '/healthy', {...request, timeoutMs: undefined, timeouts: {totalMs: null}});
    assert.equal(selected.get('/' + mode).session, siblingSession);
    if (mode === 'abort') controller.abort();
    if (mode === 'close') response.close();
    if (mode === 'idle') await assert.rejects(response.read(), (error) => code('Timeout')(error) && error.timeoutPhase === 'readIdle');
    const result = await selected.get('/' + mode).closed;
    assert.equal(result.reset, http2.constants.NGHTTP2_CANCEL); assert.equal(result.received, 0);
    finishSibling(); assert.equal(await healthy.text(7), 'healthy');
    if (mode.startsWith('total')) await assert.rejects(response.read(), (error) => code('Timeout')(error) && error.timeoutPhase === 'total');
    else response.close();
    // close waits for the JS iterator's cooperative return, not just response headers.
    if (!returned) await new Promise((resolve) => setImmediate(resolve));
    if (mode !== 'total-zero') assert.equal(returned, true);
  }
  assert.equal(sessions.size, 1);
});

test('streams keep core replay and shared-attempt admission rules', {timeout: 30000}, async (t) => {
  const sent = [];
  const url = await peer(t, (request, response) => {
    request.resume(); request.on('end', () => {
      sent.push(request.url);
      if (request.url === '/status') { response.writeHead(503); response.end(); }
      else { response.writeHead(307, {location: '/unexpected'}); response.end(); }
    });
  });
  const client = new Client({profile, route: 'direct', retryPolicy: {statusRetry: {statuses: [503], maximum: 1, delayMs: 0}}, redirectPolicy: {mode: 'limited', maximumHops: 1}});
  t.after(() => client.close());
  async function* source() { yield Buffer.from('one-shot'); }
  const response = await client.request(url + '/status', {...options, method: 'PUT', body: source()});
  assert.equal(response.status, 503); await response.bytes(0);
  await assert.rejects(client.request(url + '/redirect', {...options, method: 'PUT', body: source()}), code('RequestBody'));
  await assert.rejects(client.request(url + '/budget', {...options, body: source(), attemptBudget: new AttemptBudget(0)}), code('AttemptBudgetExhausted'));
  assert.deepEqual(sent, ['/status', '/redirect']);
});

test('stream total limits inherit, disable explicitly, and reject zero before a producer pull', {timeout: 30000}, async (t) => {
  const url = await peer(t, (request, response) => { request.resume(); request.on('end', () => response.end('ok')); });
  const client = new Client({profile, route: 'direct', timeouts: {totalMs: 0}}); t.after(() => client.close());
  let pulls = 0;
  async function* source() { pulls++; yield Buffer.from('data'); }
  await assert.rejects(client.request(url, {...options, timeoutMs: undefined, body: source()}), (error) => code('Timeout')(error) && error.timeoutPhase === 'total');
  assert.equal(pulls, 0);
  const response = await client.request(url, {...options, timeoutMs: undefined, timeouts: {totalMs: null}, body: source()});
  assert.equal(await response.text(2), 'ok');
});

test('cancelling TLS setup closes a source without pulling upload bytes', {timeout: 30000}, async (t) => {
  let accepted, socket;
  const connected = new Promise((resolve) => { accepted = resolve; });
  const server = net.createServer((connection) => { socket = connection; connection.pause(); accepted(); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { socket?.destroy(); await new Promise((resolve) => server.close(resolve)); });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  let pulls = 0, returned = 0;
  const body = { [Symbol.asyncIterator]() { return this; }, async next() { pulls++; return {done: false, value: Buffer.from('data')}; }, async return() { returned++; return {done: true}; } };
  const controller = new AbortController();
  const pending = client.request(`https://127.0.0.1:${server.address().port}`, {...options, body, signal: controller.signal});
  const rejected = assert.rejects(pending, code('Cancelled'));
  await connected; controller.abort(); await rejected; await client.close();
  assert.equal(pulls, 0); assert.equal(returned, 1);
});
