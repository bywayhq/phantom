'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
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
