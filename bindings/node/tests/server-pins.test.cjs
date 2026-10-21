'use strict';
const assert = require('node:assert/strict');
const {createHash, X509Certificate} = require('node:crypto');
const {once} = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const http2 = require('node:http2');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const {test} = require('node:test');
const {Client, AttemptBudget, PhantomError} = require('..');
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const certificate = fixture('certificate.pem'), root = fixture('certificate.der');
const pin = createHash('sha256').update(new X509Certificate(certificate).publicKey.export({type: 'spki', format: 'der'})).digest();
const wrong = Buffer.alloc(32);
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 10000};
const code = (name) => (error) => error instanceof PhantomError && error.code === name;
function keep(t, owner) {t.after(() => owner.close()); return owner;}
function client(t, extra = {}) {return keep(t, new Client({profile, route: 'direct', additionalRoots: [root], ...extra}));}
async function listen(t, server, secure) {
  const sockets = new Set();
  server.on('connection', (socket) => {sockets.add(socket); socket.on('close', () => sockets.delete(socket));});
  server.on('tlsClientError', () => {});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve));});
  return `${secure ? 'https' : 'http'}://127.0.0.1:${server.address().port}`;
}
async function send(owner, url, extra = {}) {
  const response = await owner.request(url, {...options, ...extra});
  try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
}

for (const protocol of ['http1', 'http2', 'negotiated']) {
  test(`${protocol} origin pins own bytes and retain pool, refresh and fork policy`, {timeout: 30000}, async (t) => {
    const connections = [];
    const server = http2.createSecureServer({key: fixture('key.pem'), cert: certificate, allowHTTP1: true}, (request, response) => {
      connections.push(request.stream?.session ?? request.socket); response.end('ok');
    });
    server.on('sessionError', () => {});
    const url = await listen(t, server, true);
    const mutable = Buffer.from(pin), pins = [wrong, mutable, mutable];
    const owner = client(t, {serverSpkiPins: pins});
    mutable.fill(0); pins.length = 0;
    await send(owner, url, {protocol}); await send(owner, url, {protocol});
    assert.equal(connections[0], connections[1]);
    await owner.refreshConnections(); await send(owner, url, {protocol});
    assert.notEqual(connections[1], connections[2]);
    const fork = keep(t, owner.fork()); await owner.close();
    await send(fork, url, {protocol}); assert.notEqual(connections[2], connections[3]);
    const count = connections.length;
    await assert.rejects(client(t, {serverSpkiPins: [wrong]}).request(url, {...options, protocol}), code('Tls'));
    await assert.rejects(client(t, {serverSpkiPins: [pin], additionalRoots: []}).request(url, {...options, protocol}), code('Tls'));
    assert.equal(connections.length, count, 'failed verification must send no origin HTTP');
  });
}

test('origin and HTTPS proxy pins remain independent and never bypass hostname verification', {timeout: 30000}, async (t) => {
  let originRequests = 0, connects = 0;
  const origin = https.createServer({key: fixture('key.pem'), cert: certificate}, (_, response) => {originRequests++; response.end('ok');});
  const originUrl = await listen(t, origin, true);
  const proxy = https.createServer({key: fixture('key.pem'), cert: certificate});
  const upstreams = new Set(), failures = [];
  const disconnect = (error) => ['ECONNRESET', 'ECONNABORTED', 'EPIPE'].includes(error.code);
  proxy.on('connect', (_request, downstream, head) => {
    connects++;
    const upstream = net.connect({host: '127.0.0.1', port: origin.address().port}); upstreams.add(upstream);
    upstream.on('close', () => upstreams.delete(upstream));
    upstream.on('error', (error) => {if (!disconnect(error)) failures.push(error); downstream.destroy();});
    downstream.on('error', (error) => {
      if (!disconnect(error)) failures.push(error);
      upstream.destroy();
    });
    downstream.on('close', () => upstream.destroy());
    upstream.on('connect', () => {
      downstream.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      downstream.pipe(upstream); upstream.pipe(downstream);
    });
  });
  const proxyUrl = await listen(t, proxy, true);
  t.after(() => {for (const socket of upstreams) socket.destroy(); assert.deepEqual(failures, []);});
  const base = {route: 'proxy', proxy: proxyUrl, additionalProxyRoots: [root]};
  await assert.rejects(client(t, {...base, serverSpkiPins: [pin], proxyServerSpkiPins: [wrong]}).request(originUrl, options), code('Proxy'));
  assert.equal(connects, 0); assert.equal(originRequests, 0);
  await assert.rejects(client(t, {...base, serverSpkiPins: [wrong], proxyServerSpkiPins: [pin]}).request(originUrl, options), code('Tls'));
  assert.equal(connects, 1); assert.equal(originRequests, 0);
  const trusted = client(t, {...base, serverSpkiPins: [pin], proxyServerSpkiPins: [pin]});
  await send(trusted, originUrl); assert.equal(originRequests, 1);
  // CONNECT routes this unresolvable hostname to the same loopback peer.
  await assert.rejects(trusted.request(`https://wrong.invalid:${origin.address().port}/`, options), code('Tls'));
  assert.equal(connects, 3); assert.equal(originRequests, 1);
});

test('plaintext pin-policy misuse fails before I/O or attempt admission, direct proxy-only policy remains usable', {timeout: 30000}, async (t) => {
  let connections = 0;
  const server = http.createServer((_, response) => response.end('ok'));
  server.on('connection', () => connections++);
  const url = await listen(t, server, false);
  for (const extra of [{serverSpkiPins: [pin]},
    {route: 'proxy', proxy: url, proxyServerSpkiPins: [pin]}]) {
    const owner = client(t, extra), budget = new AttemptBudget(1);
    await assert.rejects(owner.request(url, {...options, attemptBudget: budget}), code('ServerPinPolicy'));
    assert.equal(budget.remaining, 1);
  }
  assert.equal(connections, 0);
  await send(client(t, {proxyServerSpkiPins: [pin]}), url);
  assert.equal(connections, 1);
});

test('encrypted session bindings canonicalize pin sets and reject changed origin or proxy policies', {timeout: 30000}, async (t) => {
  const key = Buffer.alloc(32, 85);
  const source = client(t, {cookies: true, serverSpkiPins: [pin, wrong], proxyServerSpkiPins: [pin]});
  source.setCookie('https://example.test/', 'source=owned; Secure; Path=/');
  const snapshot = await source.exportSession(key);
  const equivalent = client(t, {cookies: true, serverSpkiPins: [wrong, pin, pin], proxyServerSpkiPins: [pin, pin]});
  const restored = keep(t, await equivalent.restoreSession(snapshot, key));
  assert.equal(restored.cookieValue('https://example.test/'), 'source=owned');
  for (const extra of [{serverSpkiPins: [wrong], proxyServerSpkiPins: [pin]},
    {serverSpkiPins: [pin, wrong], proxyServerSpkiPins: [wrong]}]) {
    const receiving = client(t, {cookies: true, ...extra});
    receiving.setCookie('https://example.test/', 'receiving=unchanged; Secure; Path=/');
    await assert.rejects(receiving.restoreSession(snapshot, key), (error) => error.code === 'SessionSnapshot' && error.kind === 'incompatible');
    assert.equal(receiving.cookieValue('https://example.test/'), 'receiving=unchanged');
  }
});

test('pinned HTTP/2 cancellation preserves a live sibling and its verified session', {timeout: 30000}, async (t) => {
  const sessions = new Set(), observed = new Map(); let finishHealthy, reset;
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: certificate});
  server.on('session', (session) => {sessions.add(session); session.on('error', () => {});});
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {}); observed.set(headers[':path'], stream.session);
    stream.respond({':status': 200});
    if (headers[':path'] === '/healthy') finishHealthy = () => stream.end('ok');
    else if (headers[':path'] === '/selected') reset = new Promise((resolve) => stream.once('close', () => resolve(stream.rstCode)));
    else stream.end('ok');
  });
  const url = await listen(t, server, true);
  t.after(() => {for (const session of sessions) session.destroy();});
  const owner = client(t, {serverSpkiPins: [pin]}), controller = new AbortController();
  const healthy = await owner.request(url + '/healthy', {method: 'GET', protocol: 'http2', context: 'raw', timeouts: {totalMs: null}});
  const selected = await owner.request(url + '/selected', {...options, protocol: 'http2', signal: controller.signal});
  try {
    assert.equal(observed.get('/healthy'), observed.get('/selected'));
    await assert.rejects(client(t, {serverSpkiPins: [wrong]}).request(url, {...options, protocol: 'http2'}), code('Tls'));
    const rejected = assert.rejects(selected.read(), code('Cancelled')); controller.abort(); await rejected;
    assert.equal(await reset, http2.constants.NGHTTP2_CANCEL);
    finishHealthy(); assert.equal(await healthy.text(2), 'ok');
    await send(owner, url + '/reuse', {protocol: 'http2'});
    assert.equal(observed.get('/healthy'), observed.get('/reuse'));
  } finally {healthy.close(); selected.close();}
});
