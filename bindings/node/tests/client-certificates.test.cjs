'use strict';
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const {createPrivateKey, X509Certificate} = require('node:crypto');
const {once} = require('node:events');
const fs = require('node:fs');
const http2 = require('node:http2');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const {inspect} = require('node:util');
const {test} = require('node:test');
const {Client, ClientCertificate, PhantomError} = require('..');
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const root = fixture('certificate.der');
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 10000};
const checkpointKey = Buffer.alloc(32, 7);

function identities(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'phantom-node-mtls-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const result = {};
  for (const name of ['a', 'b']) {
    const keyPath = path.join(directory, `${name}.key`), certPath = path.join(directory, `${name}.pem`);
    const run = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-nodes', '-keyout', keyPath, '-out', certPath, '-subj', `/CN=client-${name}`, '-days', '1',
      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature',
      '-addext', 'extendedKeyUsage=clientAuth'], {timeout: 10000, windowsHide: true});
    assert.equal(run.error, undefined, 'OpenSSL must be available for clientAuth fixtures');
    assert.equal(run.status, 0, 'OpenSSL clientAuth fixture generation must succeed');
    const pem = fs.readFileSync(certPath), key = fs.readFileSync(keyPath);
    result[name] = {pem, key, der: new X509Certificate(pem).raw,
      keyDer: createPrivateKey(key).export({format: 'der', type: 'pkcs8'})};
  }
  return result;
}
function keep(t, owner) {t.after(() => owner.close()); return owner;}
function client(t, extra = {}) {return keep(t, new Client({profile, route: 'direct', additionalRoots: [root], ...extra}));}
async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {sockets.add(socket); socket.on('close', () => sockets.delete(socket));});
  // Negative authentication controls deliberately terminate handshakes.
  server.on('tlsClientError', () => {});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve));});
  return `https://127.0.0.1:${server.address().port}`;
}
function tls(ca) {return {key: fixture('key.pem'), cert: fixture('certificate.pem'), ca, requestCert: true, rejectUnauthorized: true};}
async function send(owner, url, extra = {}) {
  const response = await owner.request(url, {...options, ...extra});
  try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
}

test('PEM and DER parse preserve typed redacted causes and copy byte inputs before await', {timeout: 30000}, async (t) => {
  const {a, b} = identities(t);
  for (const [chain, key, kind] of [[Buffer.from('private supplied'), a.key, 'certificate'],
    [a.pem, Buffer.from('private supplied'), 'private_key'], [a.pem, b.key, 'key_mismatch']]) {
    await assert.rejects(ClientCertificate.fromPem(chain, key), (error) => {
      assert(error instanceof PhantomError); assert.equal(error.code, 'ClientCertificate'); assert.equal(error.kind, kind);
      for (const shown of [String(error), JSON.stringify(error), inspect(error, {showHidden: true})]) assert(!shown.includes('supplied'));
      return true;
    });
  }
  const chain = Buffer.from(a.pem), key = Buffer.from(a.key);
  const pending = ClientCertificate.fromPem(chain, key); chain.fill(0); key.fill(0);
  const owner = await pending;
  assert(Object.isFrozen(owner)); assert.deepEqual(Object.keys(owner), []);
  assert.equal(inspect(owner, {showHidden: true}), 'ClientCertificate {}');
  const server = https.createServer(tls(a.pem), (_request, response) => response.end('ok'));
  const url = await listen(t, server);
  await send(client(t, {clientCertificate: owner}), url);
  const esm = await import('../index.mjs'); assert.equal(esm.ClientCertificate, ClientCertificate);
});

test('ordered last origin mapping survives fork source close and compatible checkpoint restore', {timeout: 30000}, async (t) => {
  const {a, b} = identities(t);
  const first = await ClientCertificate.fromPem(a.pem, a.key);
  const selected = await ClientCertificate.fromDer([b.der], b.keyDer);
  const seen = [], ports = [];
  const server = https.createServer(tls(b.pem), (request, response) => {
    seen.push(request.socket.getPeerCertificate().raw); ports.push(request.socket.remotePort); response.end('ok');
  });
  const url = await listen(t, server);
  const source = client(t, {clientCertificate: first, clientCertificatesFor: [[url + '/', first], [url, selected]]});
  await send(source, url); await send(source, url);
  assert.equal(ports[0], ports[1]);
  const child = keep(t, source.fork());
  const snapshot = await source.exportSession(checkpointKey);
  const restored = keep(t, await source.restoreSession(snapshot, checkpointKey));
  await source.close();
  await send(child, url + '/fork'); await send(restored, url + '/restore');
  assert.deepEqual(seen, [b.der, b.der, b.der, b.der]);
  assert.notEqual(ports[2], ports[0]); assert.notEqual(ports[3], ports[2]);
  const equivalent = await ClientCertificate.fromPem(b.pem, b.key);
  const receiver = client(t, {clientCertificate: first, clientCertificatesFor: [[url, equivalent]]});
  const compatible = keep(t, await receiver.restoreSession(snapshot, checkpointKey));
  await send(compatible, url);
  const changed = client(t, {clientCertificate: first});
  await assert.rejects(changed.restoreSession(snapshot, checkpointKey), {code: 'SessionSnapshot', kind: 'incompatible'});
  // Restore failure leaves the receiver usable; it still cannot authenticate to b.
  await assert.rejects(send(changed, url));
});

test('missing wrong unmapped identities and untrusted servers cannot authenticate', {timeout: 30000}, async (t) => {
  const {a, b} = identities(t);
  const wrong = await ClientCertificate.fromPem(a.pem, a.key), right = await ClientCertificate.fromPem(b.pem, b.key);
  let requests = 0;
  const server = https.createServer(tls(b.pem), (_request, response) => {requests++; response.end('ok');});
  const url = await listen(t, server);
  for (const extra of [{}, {clientCertificate: wrong}, {clientCertificatesFor: [['https://unmapped.invalid', right]]}]) {
    // TLS 1.3 alerts may be observed by request or by response body collection.
    await assert.rejects(send(client(t, extra), url), (error) => error instanceof PhantomError);
  }
  const untrusted = keep(t, new Client({profile, route: 'direct', clientCertificate: right}));
  await assert.rejects(send(untrusted, url), {code: 'Tls'});
  assert.equal(requests, 0);
  for (const origin of ['http://127.0.0.1', url + '/path', 'https://user:private@example.com']) {
    assert.throws(() => client(t, {clientCertificatesFor: [[origin, right]]}), (error) => {
      assert.equal(error.code, 'InvalidPolicy');
      assert(!String(error).includes('private')); return true;
    });
  }
  assert.equal(requests, 0);
});

test('default DER identity preserves verified H2 reuse and independent fork ownership', {timeout: 30000}, async (t) => {
  const {a} = identities(t);
  const identity = await ClientCertificate.fromDer([a.der], a.keyDer);
  const sessions = [], certificates = [];
  const server = http2.createSecureServer(tls(a.pem));
  server.on('session', (session) => session.on('error', () => {}));
  server.on('stream', (stream) => {
    stream.on('error', () => {});
    sessions.push(stream.session); certificates.push(stream.session.socket.getPeerCertificate().raw);
    stream.respond({':status': 200}); stream.end('ok');
  });
  const url = await listen(t, server), source = client(t, {clientCertificate: identity});
  await send(source, url, {protocol: 'http2'}); await send(source, url, {protocol: 'http2'});
  assert.equal(sessions[0], sessions[1]);
  const child = keep(t, source.fork()); await source.close();
  await send(child, url, {protocol: 'http2'});
  assert.notEqual(sessions[1], sessions[2]); assert.deepEqual(certificates, [a.der, a.der, a.der]);
});


test('origin identity is not disclosed to an HTTPS proxy requesting client authentication', {timeout: 30000}, async (t) => {
  const {a} = identities(t);
  const identity = await ClientCertificate.fromPem(a.pem, a.key);
  let connects = 0;
  const proxy = https.createServer(tls(a.pem));
  proxy.on('connect', (_request, socket) => {connects++; socket.destroy();});
  const proxyUrl = await listen(t, proxy);
  const owner = client(t, {route: 'proxy', proxy: proxyUrl, additionalProxyRoots: [root], clientCertificate: identity});
  await assert.rejects(send(owner, 'https://origin.invalid/'), {code: 'Proxy'});
  assert.equal(connects, 0);
});
