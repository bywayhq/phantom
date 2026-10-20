'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const { test } = require('node:test');
const { Client, PhantomError, Profile } = require('..');

const identifier = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const code = (expected) => (error) => error instanceof PhantomError && error.code === expected;
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));

function keep(t, owner) { t.after(() => owner.close()); return owner; }
function client(t, configuration = {}) {
  return keep(t, new Client({profile: identifier, route: 'direct', ...configuration}));
}
async function send(owner, url, overrides = {}) {
  const response = await owner.request(url, {...options, ...overrides});
  assert.equal((await response.bytes(2)).toString(), 'ok');
}
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

test('fork shares peer-learned cookies and clears only selected jars', {timeout: 30000}, async (t) => {
  const observed = [];
  const url = await peer(t, (request, response) => {
    observed.push(request.headers.cookie);
    if (request.url === '/alpha') response.setHeader('Set-Cookie', 'alpha=1; Path=/');
    if (request.url === '/beta') response.setHeader('Set-Cookie', 'beta=2; Path=/');
    response.end('ok');
  });
  const source = client(t, {cookies: true});
  await send(source, url + '/alpha');
  const shared = keep(t, source.fork({cookies: true}));
  const separate = keep(t, source.fork());
  assert.match(shared.cookieValue(url), /alpha=1/);
  assert.equal(separate.cookieValue(url), null);
  await send(shared, url + '/beta');
  assert.match(observed[1], /alpha=1/);
  assert.match(source.cookieValue(url), /beta=2/);
  await send(source, url);
  assert.match(observed[2], /alpha=1/);
  assert.match(observed[2], /beta=2/);
  await send(separate, url + '/alpha');
  assert.equal(observed[3], undefined);
  shared.clearCookies();
  assert.equal(source.cookieValue(url), null);
  assert.match(separate.cookieValue(url), /alpha=1/);
  await send(source, url + '/beta');
  source.clearCookies();
  assert.equal(shared.cookieValue(url), null);
});

test('fork pools, admission, cancellation and shutdown remain independent', {timeout: 30000}, async (t) => {
  const observed = [];
  const held = new Map();
  const url = await peer(t, (request, response) => {
    observed.push({url: request.url, socket: request.socket});
    if (request.url.startsWith('/hold')) {
      response.writeHead(200, {'Content-Length': '2'});
      response.flushHeaders();
      held.set(request.url, response);
    } else response.end('ok');
  });
  const source = client(t, {maximumActiveRequests: 1});
  const fork = keep(t, source.fork());
  await send(source, url); await send(source, url);
  await send(fork, url); await send(fork, url);
  assert.equal(observed[0].socket, observed[1].socket);
  assert.equal(observed[2].socket, observed[3].socket);
  assert.notEqual(observed[0].socket, observed[2].socket);
  const disposable = keep(t, source.fork());
  await disposable.close();
  await send(source, url);
  const controller = new AbortController();
  const selected = await source.request(url + '/hold-source', {...options, signal: controller.signal});
  const sibling = await fork.request(url + '/hold-fork', options);
  await assert.rejects(source.request(url, options), code('Capacity'));
  await assert.rejects(fork.request(url, options), code('Capacity'));
  const cancelled = assert.rejects(selected.read(), code('Cancelled'));
  const healthy = sibling.bytes(2);
  controller.abort();
  await cancelled;
  held.get('/hold-fork').end('ok');
  assert.equal((await healthy).toString(), 'ok');
  await source.close();
  await send(fork, url);
  await fork.close();
  const reopened = keep(t, source.fork());
  await send(reopened, url);
  await assert.rejects(source.request(url, options), code('ClientClosed'));
});

test('fork preserves custom templates, base URL, origin trust and timeouts', {timeout: 30000}, async (t) => {
  const observed = [];
  const url = await peer(t, (request, response) => {
    observed.push({url: request.url, headers: request.rawHeaders});
    if (request.url === '/api/hang') return;
    response.end('ok');
  }, true);
  const document = Profile.fromCatalog(identifier, 'navigation').describe();
  document.profile.request_template.http1_fields.unshift(
    {variant: 'Literal', name: 'X-Fork-First', value: 'first'},
    {variant: 'Literal', name: 'X-Fork-Last', value: 'last'},
  );
  const source = client(t, {profile: Profile.fromDescription(document),
    baseUrl: url + '/api/', additionalRoots: [fixture('certificate.der')],
    timeouts: {responseHeadMs: 50, totalMs: 5000}});
  const fork = keep(t, source.fork());
  await source.close();
  await send(fork, 'child?x=a%20b', {context: 'profile',
    headers: [{name: 'User-Agent', value: Buffer.from('Phantom-Test Chrome/154.0.0.0')}]});
  assert.equal(observed[0].url, '/api/child?x=a%20b');
  const position = observed[0].headers.indexOf('X-Fork-First');
  assert(position >= 0);
  assert.deepEqual(observed[0].headers.slice(position, position + 4),
    ['X-Fork-First', 'first', 'X-Fork-Last', 'last']);
  await assert.rejects(fork.request('hang', options), (error) =>
    code('Timeout')(error) && error.timeoutPhase === 'responseHead');
});

test('fork retains an explicit proxy and its separate trust roots', {timeout: 30000}, async (t) => {
  const observed = [];
  const proxy = await peer(t, (request, response) => {
    observed.push(request.url);
    response.end('ok');
  }, true);
  const source = client(t, {route: 'proxy', proxy,
    additionalProxyRoots: [fixture('certificate.der')]});
  const fork = keep(t, source.fork());
  await source.close();
  await send(fork, 'http://origin.invalid/path');
  assert.deepEqual(observed, ['http://origin.invalid/path']);
});

test('sharing selectors reject ambiguous values and never enable disabled cookies', async (t) => {
  const source = client(t);
  let evaluated = false;
  const getter = {get cookies() { evaluated = true; return true; }};
  for (const invalid of [null, [], true, 'cookies', {cookie: true}, {cookies: 1},
    {dns: undefined}, {tickets: null}, {[Symbol('cookies')]: true}, getter,
    new Proxy({}, {}), Object.create({cookies: true})]) {
    assert.throws(() => source.fork(invalid), code('InvalidArgument'));
  }
  assert.equal(evaluated, false);
  const fork = keep(t, source.fork({cookies: true, dns: true, clientHints: true,
    discovery: true, tickets: true}));
  assert.throws(() => fork.cookieValue('http://example.com/'), code('CookiesDisabled'));
  assert.throws(() => fork.setCookie('http://example.com/', 'a=1'), code('CookiesDisabled'));
});
