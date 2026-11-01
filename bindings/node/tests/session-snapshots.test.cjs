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
const key = Buffer.from('checkpoint-test-key-not-a-secret');
const options = {method: 'GET', protocol: 'http1', context: 'profile', timeoutMs: 5000,
  headers: [{name: 'User-Agent', value: Buffer.from('Phantom-Node-Test Chrome/154.0.0.0')}]};
const kind = (expected) => (error) => error instanceof PhantomError
  && error.code === 'SessionSnapshot' && error.kind === expected;
function keep(t, client) { t.after(() => client.close()); return client; }
function client(t, overrides = {}) {
  return keep(t, new Client({profile: identifier, route: 'direct', cookies: true, ...overrides}));
}

test('caller storage roundtrip uses native encrypted state without changing the receiver', {timeout: 30000}, async (t) => {
  const source = client(t), values = new Map();
  const store = {
    async save(name, snapshot, {signal}) { signal.throwIfAborted(); values.set(name, snapshot); },
    async load(name, {signal}) { signal.throwIfAborted(); return values.get(name) ?? null; },
  };
  source.setCookie('https://example.test', 'state=original; Secure; Path=/');
  await source.saveSession(store, 'job/session', key, {timeoutMs: 5000});
  assert(!values.get('job/session').includes(Buffer.from('state=original')));
  source.setCookie('https://example.test', 'state=changed; Secure; Path=/');
  assert.equal(await source.loadSession(store, 'absent', key, {timeoutMs: 5000}), null);
  const restored = keep(t, await source.loadSession(store, 'job/session', key, {timeoutMs: 5000, receivingRoutes: [{route: 'direct'}]}));
  assert.equal(restored.cookieValue('https://example.test'), 'state=original');
  await assert.rejects(source.loadSession(store, 'job/session', Buffer.alloc(32), {timeoutMs: 5000}), kind('authentication'));
  assert.equal(source.cookieValue('https://example.test'), 'state=changed');
});

test('encrypted checkpoints retain private cookies, profile templates and independent pools', {timeout: 30000}, async (t) => {
  const observed = [];
  const sockets = new Set();
  const peer = http.createServer((request, response) => {
    observed.push({socket: request.socket, url: request.url, cookie: request.headers.cookie,
      mode: request.headers['sec-fetch-mode']});
    response.end('ok');
  });
  peer.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  peer.listen(0, '127.0.0.1'); await once(peer, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => peer.close(resolve)); });
  const url = `http://127.0.0.1:${peer.address().port}`;
  const source = client(t, {profile: Profile.fromCatalog(identifier, 'navigation'), baseUrl: url + '/'});
  const send = async (owner, target) => {
    const response = await owner.request(target, options);
    assert.equal((await response.bytes(2)).toString(), 'ok');
  };
  source.setCookie(url, 'checkpoint=original; Path=/');
  await send(source, 'source');
  const snapshot = await source.exportSession(key);
  assert(Buffer.isBuffer(snapshot));
  assert(!snapshot.includes(Buffer.from('checkpoint=original')));
  source.setCookie(url, 'checkpoint=changed; Path=/');
  const restored = keep(t, await source.restoreSession(snapshot, key, {
    receivingRoutes: [{route: 'direct'}, {route: 'proxy', proxy: 'http://127.0.0.1:80'}],
  }));
  assert.match(restored.cookieValue(url), /checkpoint=original/);
  assert.match(source.cookieValue(url), /checkpoint=changed/);
  await send(restored, 'restored'); await send(restored, 'reuse');
  assert.notEqual(observed[0].socket, observed[1].socket);
  assert.equal(observed[1].socket, observed[2].socket);
  restored.setCookie(url, 'private=child; Path=/');
  assert(!source.cookieValue(url).includes('private=child'));
  await source.close();
  await send(restored, 'after-close');
  const fromClosed = keep(t, await source.restoreSession(snapshot, key));
  await send(fromClosed, 'closed-source');
  assert.deepEqual(observed.map((entry) => entry.url), ['/source', '/restored', '/reuse', '/after-close', '/closed-source']);
  assert(observed.every((entry) => entry.mode === 'navigate'));
  assert.equal(observed[0].cookie, 'checkpoint=original');
  assert.equal(observed[1].cookie, 'checkpoint=original');
});

test('checkpoint failures preserve receiving state and report precise redacted categories', {timeout: 30000}, async (t) => {
  const source = client(t);
  const receiving = client(t);
  source.setCookie('https://example.test', 'source=private-cookie; Secure; Path=/');
  receiving.setCookie('https://example.test', 'receiving=unchanged; Secure; Path=/');
  const snapshot = await source.exportSession(key);
  await assert.rejects(receiving.restoreSession(snapshot, Buffer.alloc(32)), kind('authentication'));
  const tampered = Buffer.from(snapshot); tampered[tampered.length - 1] ^= 1;
  await assert.rejects(receiving.restoreSession(tampered, key), kind('authentication'));
  await assert.rejects(receiving.restoreSession(Buffer.from('not a checkpoint'), key), kind('invalid_snapshot'));
  await assert.rejects(client(t, {cookies: false}).restoreSession(snapshot, key), kind('disabled'));
  await assert.rejects(client(t, {route: 'proxy', proxy: 'http://127.0.0.1:80'}).restoreSession(snapshot, key), kind('incompatible'));
  const certificate = fs.readFileSync(path.join(__dirname, 'fixtures/certificate.der'));
  await assert.rejects(client(t, {additionalRoots: [certificate]}).restoreSession(snapshot, key), kind('incompatible'));
  const credentialed = client(t, {route: 'proxy', proxy: 'http://127.0.0.1:80', proxyUsername: 'private-user', proxyPassword: 'private-password'});
  await assert.rejects(credentialed.exportSession(key), (error) => {
    assert(kind('unsupported')(error));
    for (const output of [String(error), JSON.stringify(error)]) assert(!output.includes('private-'));
    return true;
  });
  assert.equal(receiving.cookieValue('https://example.test'), 'receiving=unchanged');
  assert.equal(source.cookieValue('https://example.test'), 'source=private-cookie');
});

test('checkpoint inputs enforce exact key and byte bounds without shared backing', {timeout: 30000}, async (t) => {
  const owner = client(t);
  for (const length of [0, 31, 33]) {
    await assert.rejects(owner.exportSession(Buffer.alloc(length)), kind('invalid_key_length'));
  }
  await assert.rejects(owner.restoreSession(Buffer.alloc(32 * 1024 * 1024 + 1), key), kind('too_large'));
  await assert.rejects(owner.exportSession(new Uint8Array(new SharedArrayBuffer(32))), (error) => error.code === 'InvalidArgument');
  const buffer = Buffer.alloc(40); key.copy(buffer, 4);
  const slicedKey = new Uint8Array(buffer.buffer, buffer.byteOffset + 4, 32);
  const exporting = owner.exportSession(slicedKey);
  buffer.fill(0);
  const snapshot = await exporting;
  const restoreKey = Buffer.from(key);
  const restoring = owner.restoreSession(snapshot, restoreKey);
  snapshot.fill(0); restoreKey.fill(0);
  const restored = keep(t, await restoring);
  assert.equal(restored.cookieValue('https://example.test'), null);
});


test('typed cookie transfer is atomic, ordered and keeps existing cookies', (t) => {
  const source = client(t), target = client(t);
  source.setCookie('https://example.test/', 'first=one; Secure; HttpOnly; SameSite=Lax; Path=/');
  source.setCookie('https://example.test/', 'second=two; Secure; Path=/');
  const entries = source.exportCookies();
  assert.deepEqual(entries.map((entry) => entry.name), ['first', 'second']);
  assert.equal(entries[0].sourceScheme, 'https'); assert.equal(entries[0].httpOnly, true);
  assert.equal(entries[0].sameSite, 'lax'); assert.equal(entries[0].expiresAtNanoseconds, null);
  target.setCookie('https://example.test/', 'first=held; Secure; Path=/');
  target.importCookies(entries);
  assert.equal(target.cookieValue('https://example.test/'), 'second=two; first=held');
  assert.equal(source.cookieValue('https://example.test/'), 'first=one; second=two');
  const before = target.exportCookies();
  assert.throws(() => target.importCookies([{...entries[0], name: 'new'}, {...entries[1], domain: 'COM', hostOnly: false}]),
    (error) => error.code === 'CookieSnapshot' && error.entryIndex === 1);
  assert.deepEqual(target.exportCookies(), before);
  const fresh = client(t);
  fresh.importCookies([{...entries[0], expiresAtNanoseconds: -123456700n}]);
  assert.deepEqual(fresh.exportCookies(), []);
});

test('disabled standalone stores differ from enabled empty stores and reject imports', (t) => {
  const disabled = client(t, {cookies: false}), enabled = client(t, {network: {maxAltSvcOrigins: 8}});
  assert.equal(disabled.exportCookies(), null); assert.equal(disabled.exportAltSvc(), null);
  assert.deepEqual(enabled.exportCookies(), []); assert.deepEqual(enabled.exportAltSvc(), []);
  assert.throws(() => disabled.importCookies([]), (error) => error.code === 'CookieSnapshot' && error.kind === 'disabled');
  assert.throws(() => disabled.importAltSvc([]), (error) => error.code === 'AltSvcSnapshot' && error.kind === 'disabled');
});

test('typed Alt-Svc transfer preserves core expiry, precedence and atomic validation', async (t) => {
  const source = client(t, {network: {maxAltSvcOrigins: 8}});
  const expiry = BigInt(Date.now() + 60000) * 1000000n + 123400n;
  const entry = {origin: 'https://example.test', alternativeHost: 'alt.example.test', alternativePort: 443, expiresAtNanoseconds: expiry};
  source.importAltSvc([entry]);
  const exported = source.exportAltSvc();
  assert.deepEqual(exported, [{...entry, expiresAtNanoseconds: expiry / 1000000000n * 1000000000n}]);
  source.importAltSvc([{...entry, alternativePort: 8443}]);
  assert.deepEqual(source.exportAltSvc(), exported);
  assert.throws(() => source.importAltSvc([{...entry, origin: 'https://new.test'}, {...entry, origin: 'http://invalid.test'}]),
    (error) => error.code === 'AltSvcSnapshot' && error.entryIndex === 1);
  assert.deepEqual(source.exportAltSvc(), exported);
  const forked = keep(t, source.fork());
  assert.deepEqual(forked.exportAltSvc(), []);
  const shared = keep(t, source.fork({discovery: true}));
  assert.deepEqual(shared.exportAltSvc(), exported);
  const restored = keep(t, await source.restoreSession(await source.exportSession(key), key));
  assert.deepEqual(restored.exportAltSvc(), exported);
});

test('ticket-only encrypted import authenticates before mutation and preserves source state', {timeout: 30000}, async (t) => {
  const source = client(t), receiver = client(t);
  source.setCookie('https://example.test/', 'unrelated=source; Secure; Path=/');
  receiver.setCookie('https://example.test/', 'unrelated=receiver; Secure; Path=/');
  const snapshot = await source.exportSessionTickets(key);
  assert(Buffer.isBuffer(snapshot)); assert(snapshot.length <= 16 * 1024 * 1024);
  await receiver.importSessionTickets(snapshot, key, {receivingRoutes: [{route: 'direct'}]});
  assert.equal(receiver.cookieValue('https://example.test/'), 'unrelated=receiver');
  await assert.rejects(receiver.importSessionTickets(snapshot, Buffer.alloc(32)),
    (error) => error.code === 'SessionTickets' && error.kind === 'authentication');
  await assert.rejects(receiver.importSessionTickets(Buffer.from('invalid framing'), key),
    (error) => error.code === 'SessionTickets' && error.kind === 'invalid_snapshot');
  assert.equal(receiver.cookieValue('https://example.test/'), 'unrelated=receiver');
  assert.equal(source.cookieValue('https://example.test/'), 'unrelated=source');
  await receiver.importSessionTickets(await source.exportSessionTickets(key), key);
  await source.close();
  await assert.rejects(source.exportSessionTickets(key), (error) => error.code === 'ClientClosed');
  assert.throws(() => source.exportCookies(), (error) => error.code === 'ClientClosed');
});


test('ticket-only transfer resumes real TLS without consuming the source or replacing cookies', {timeout: 30000}, async (t) => {
  const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
  const resumed = [], sockets = new Set();
  const peer = https.createServer({key: fixture('key.pem'), cert: fixture('certificate.pem'),
    minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2'}, (request, response) => {
    resumed.push(request.socket.isSessionReused());
    response.setHeader('Connection', 'close'); response.end('ok');
  });
  peer.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  peer.listen(0, '127.0.0.1'); await once(peer, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => peer.close(resolve)); });
  const source = client(t, {additionalRoots: [fixture('certificate.der')]}), receiver = client(t, {additionalRoots: [fixture('certificate.der')]});
  source.setCookie('https://example.test', 'state=source; Secure; Path=/');
  receiver.setCookie('https://example.test', 'state=receiver; Secure; Path=/');
  const url = `https://127.0.0.1:${peer.address().port}`;
  const send = async (owner) => { const response = await owner.request(url, {...options, context: 'raw'}); assert.equal((await response.bytes(2)).toString(), 'ok'); };
  await send(source);
  const snapshot = await source.exportSessionTickets(key);
  await receiver.importSessionTickets(snapshot, key);
  await assert.rejects(receiver.importSessionTickets(snapshot, Buffer.alloc(32)), (error) => error.code === 'SessionTickets' && error.kind === 'authentication');
  await send(receiver); await send(source);
  assert.deepEqual(resumed, [false, true, true]);
  assert.equal(source.cookieValue('https://example.test'), 'state=source');
  assert.equal(receiver.cookieValue('https://example.test'), 'state=receiver');
});


test('native typed import supports all default 3300 cookies without a small metadata cap', {timeout: 30000}, (t) => {
  const owner = client(t);
  const entries = Array.from({length: 3300}, (_, index) => ({sourceScheme: 'https', name: `c${index}`,
    value: 'x'.repeat(4000), domain: `example${index}.test`, path: '/', hostOnly: true, secure: true,
    httpOnly: false, sameSite: null, partitionKey: null, expiresAtNanoseconds: null}));
  owner.importCookies(entries);
  const exported = owner.exportCookies();
  assert.equal(exported.length, 3300);
  assert.deepEqual(exported.map((entry) => entry.name), entries.map((entry) => entry.name));
  assert.equal(exported[3299].value.length, 4000);
});
