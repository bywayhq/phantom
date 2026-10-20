'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const { test } = require('node:test');
const { Client, PhantomError } = require('..');

const profile = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw'};
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const client = (t, configuration = {}) => {
  const owner = new Client({profile, route: 'direct', ...configuration});
  t.after(() => owner.close());
  return owner;
};
const timeout = (phase) => (error) => error instanceof PhantomError
  && error.code === 'Timeout' && error.timeoutPhase === phase;

async function peer(t, handler, secure = false) {
  const server = secure
    ? https.createServer({key: fixture('key.pem'), cert: fixture('certificate.pem')}, handler)
    : http.createServer(handler);
  const sockets = new Set();
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return `${secure ? 'https' : 'http'}://127.0.0.1:${server.address().port}`;
}

test('base URL joining and negotiated requests report the actual final protocol', {timeout: 30000}, async (t) => {
  const observed = [];
  const url = await peer(t, (request, response) => { observed.push(request.url); response.end('ok'); });
  const owner = client(t, {baseUrl: url + '/api/'});
  const response = await owner.request('child?q=1', {...options, protocol: 'negotiated'});
  assert.equal((await response.bytes(2)).toString(), 'ok');
  assert.deepEqual(observed, ['/api/child?q=1']);
  assert.equal(response.url, url + '/api/child?q=1');
  assert.equal(response.protocol, 'http1');
  assert.equal(response.redirects, 0);
  assert.equal(response.connectionRetries, 0);
});

test('phase overrides distinguish inheritance, disabled limits and immediate zero', {timeout: 30000}, async (t) => {
  let release;
  const started = new Promise((resolve) => { release = resolve; });
  const url = await peer(t, (request, response) => {
    if (request.url === '/body') { response.writeHead(200); response.flushHeaders(); }
    else if (request.url === '/disabled') {
      response.writeHead(200); response.flushHeaders(); release(() => response.end('ok'));
    }
    else response.end('ok');
  });
  const owner = client(t, {timeouts: {responseHeadMs: 0, readIdleMs: 30, totalMs: 3000}});
  await assert.rejects(owner.request(url, options), timeout('responseHead'));
  const overridden = await owner.request(url, {...options, timeouts: {responseHeadMs: null}});
  assert.equal((await overridden.bytes(2)).toString(), 'ok');
  const idle = await owner.request(url + '/body', {...options, timeouts: {responseHeadMs: null}});
  await assert.rejects(idle.bytes(10), timeout('readIdle'));
  const pending = owner.request(url + '/disabled', {...options, timeouts: {responseHeadMs: null, readIdleMs: null}});
  const finish = await started;
  const disabled = await pending;
  const collection = disabled.bytes(2);
  // Keep the read pending beyond the inherited idle limit before releasing it.
  await new Promise((resolve) => setTimeout(resolve, 90));
  finish();
  assert.equal((await collection).toString(), 'ok');
  await assert.rejects(owner.request(url, {...options, timeouts: {totalMs: 0}}), timeout('total'));
});

test('invalid timeout inputs and conflicting total limits do not dispatch requests', {timeout: 30000}, async (t) => {
  let count = 0;
  const url = await peer(t, (_, response) => { count++; response.end(); });
  const owner = client(t);
  for (const value of [-1, Infinity, NaN, 0.5, '1', true]) {
    await assert.rejects(owner.request(url, {...options, timeouts: {connectMs: value}}),
      (error) => error instanceof PhantomError && error.code === 'InvalidArgument');
  }
  await assert.rejects(owner.request(url, {...options, timeouts: {unknownMs: 1}}),
    (error) => error instanceof PhantomError && error.code === 'InvalidArgument');
  await assert.rejects(owner.request(url, {...options, timeoutMs: 1, timeouts: {totalMs: null}}),
    (error) => error instanceof PhantomError && error.code === 'InvalidTimeout');
  assert.equal(count, 0);
});

test('origin trust roots do not silently authenticate an HTTPS proxy', {timeout: 30000}, async (t) => {
  const url = await peer(t, (_, response) => response.end('proxy'), true);
  const root = fixture('certificate.der');
  const ordinary = client(t, {route: 'proxy', proxy: url, additionalRoots: [root]});
  await assert.rejects(ordinary.request('http://origin.invalid/path', {...options, timeoutMs: 5000}),
    (error) => error instanceof PhantomError && error.code !== 'Timeout');
  const trusted = client(t, {route: 'proxy', proxy: url, additionalProxyRoots: [root]});
  assert.equal((await (await trusted.request('http://origin.invalid/path', {...options, timeoutMs: 5000})).bytes(5)).toString(), 'proxy');
});

test('idle retirement and refresh keep the client usable while caches can be cleared', {timeout: 30000}, async (t) => {
  const sockets = [];
  const url = await peer(t, (request, response) => { sockets.push(request.socket); response.end('ok'); });
  const owner = client(t, {cookies: true});
  const send = async () => assert.equal((await (await owner.request(url, options)).bytes(2)).toString(), 'ok');
  await send(); await send();
  assert.equal(sockets[0], sockets[1]);
  owner.setCookie(url, 'a=1');
  owner.clearCookies();
  assert.equal(owner.cookieValue(url), null);
  owner.clearDnsCache(); owner.clearClientHints(); owner.clearAltSvc();
  assert.equal(typeof owner.clearSessionTickets(), 'number');
  await owner.closeIdleConnections();
  await send();
  assert.notEqual(sockets[1], sockets[2]);
  await owner.refreshConnections();
  await send();
  assert.notEqual(sockets[2], sockets[3]);
});
