'use strict';
const assert = require('node:assert/strict');
const {execFile} = require('node:child_process');
const {X509Certificate} = require('node:crypto');
const {once} = require('node:events');
const fs = require('node:fs/promises');
const http = require('node:http');
const http2 = require('node:http2');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const {promisify} = require('node:util');
const {test} = require('node:test');
const {Client, PhantomError} = require('..');

const unix = process.platform !== 'win32';
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 10000};
const code = (expected) => (error) => error instanceof PhantomError && error.code === expected;
const snapshotUnsupported = (error) => code('SessionSnapshot')(error) && error.kind === 'unsupported';

async function peer(t, server) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'p-unix-'));
  const socketPath = path.join(directory, 's'), sockets = new Set();
  server.on('connection', (socket) => {sockets.add(socket); socket.once('close', () => sockets.delete(socket));});
  server.on('tlsClientError', () => {}); server.on('sessionError', () => {});
  try {server.listen(socketPath); await once(server, 'listening');}
  catch (error) {await fs.rm(directory, {recursive: true, force: true}); throw error;}
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(directory, {recursive: true, force: true});
  });
  return socketPath;
}

async function material(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'p-unix-tls-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const config = path.join(directory, 'tls.cnf'), key = path.join(directory, 'key.pem'), cert = path.join(directory, 'cert.pem');
  await fs.writeFile(config, '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=phantom.invalid\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:phantom.invalid\n');
  await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
    '-days', '2', '-config', config, '-keyout', key, '-out', cert], {timeout: 10000, maxBuffer: 65536});
  const certificate = await fs.readFile(cert);
  return {key: await fs.readFile(key), cert: certificate, root: new X509Certificate(certificate).raw};
}

async function read(client, url, overrides = {}) {
  const response = await client.request(url, {...options, ...overrides});
  try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
}

test('Unix HTTP keeps logical authority, connection reuse and independent fork pools', {skip: !unix, timeout: 30000}, async (t) => {
  const records = [];
  const socketPath = await peer(t, http.createServer((request, response) => {
    records.push({socket: request.socket, host: request.headers.host, path: request.url}); response.end('ok');
  }));
  const client = new Client({profile, route: 'direct', cookies: true, network: {unixSocket: socketPath}});
  const key = Buffer.alloc(32, 7);
  try {
    await read(client, 'http://unresolved.invalid:4567/one');
    await read(client, 'http://unresolved.invalid:4567/two');
    assert.equal(records[0].socket, records[1].socket);
    assert.deepEqual(records.map(({host, path}) => [host, path]), [
      ['unresolved.invalid:4567', '/one'], ['unresolved.invalid:4567', '/two'],
    ]);
    const fork = client.fork();
    try {
      await read(fork, 'http://unresolved.invalid:4567/fork');
      assert.notEqual(records[0].socket, records[2].socket);
      await client.close();
      await read(fork, 'http://unresolved.invalid:4567/after-close');
      assert.equal(records[2].socket, records[3].socket);
      await assert.rejects(fork.exportSession(key), snapshotUnsupported);
      const ordinary = new Client({profile, route: 'direct', cookies: true});
      try {
        const snapshot = await ordinary.exportSession(key);
        await assert.rejects(fork.restoreSession(snapshot, key), snapshotUnsupported);
      } finally {await ordinary.close();}
    } finally {await fork.close();}
  } finally {await client.close();}
});

test('Unix TLS retains verified URL identity for HTTP/1, HTTP/2 and ALPN', {skip: !unix, timeout: 60000}, async (t) => {
  const tls = await material(t);
  for (const protocol of ['http1', 'http2', 'negotiated']) {
    const records = [];
    const handler = (request, response) => {
      records.push({version: request.httpVersionMajor, host: request.headers.host ?? request.headers[':authority'],
        sni: request.socket.servername}); response.end('ok');
    };
    const server = protocol === 'http1'
      ? https.createServer({key: tls.key, cert: tls.cert, ALPNProtocols: ['http/1.1']}, handler)
      : http2.createSecureServer({key: tls.key, cert: tls.cert}, handler);
    const socketPath = await peer(t, server);
    const client = new Client({profile, route: 'direct', additionalRoots: [tls.root], network: {unixSocket: socketPath}});
    try {
      await read(client, 'https://phantom.invalid:4567/', {protocol});
      assert.deepEqual(records, [{version: protocol === 'http1' ? 1 : 2, host: 'phantom.invalid:4567', sni: 'phantom.invalid'}]);
      await assert.rejects(read(client, 'https://wrong.invalid:4567/', {protocol}), code('Tls'));
      assert.equal(records.length, 1);
    } finally {await client.close();}
    const untrusted = new Client({profile, route: 'direct', network: {unixSocket: socketPath}});
    try {await assert.rejects(read(untrusted, 'https://phantom.invalid:4567/', {protocol}), code('Tls'));}
    finally {await untrusted.close();}
  }
});

test('Unix HTTP/2 cancellation leaves the sibling and connection usable', {skip: !unix, timeout: 30000}, async (t) => {
  const tls = await material(t), sessions = [], controller = new AbortController();
  let arrived;
  const pendingArrival = new Promise((resolve) => {arrived = resolve;});
  const server = http2.createSecureServer({key: tls.key, cert: tls.cert});
  server.on('stream', (stream, headers) => {
    sessions.push(stream.session); stream.on('error', () => {});
    if (headers[':path'] === '/pending') {arrived(); return;}
    stream.respond({':status': 200, 'content-length': '2'});
    if (headers[':path'] === '/held') stream.write('a'); else stream.end('ok');
  });
  const socketPath = await peer(t, server);
  const client = new Client({profile, route: 'direct', additionalRoots: [tls.root], network: {unixSocket: socketPath}});
  const request = {...options, protocol: 'http2'};
  let held;
  try {
    held = await client.request('https://phantom.invalid/held', request);
    const pending = client.request('https://phantom.invalid/pending', {...request, signal: controller.signal});
    const rejected = assert.rejects(pending, code('Cancelled'));
    await pendingArrival; controller.abort(); await rejected;
    await read(client, 'https://phantom.invalid/healthy', {protocol: 'http2'});
    held.close();
    await read(client, 'https://phantom.invalid/reused', {protocol: 'http2'});
    assert.equal(sessions.length, 4); assert(sessions.every((session) => session === sessions[0]));
  } finally {controller.abort(); held?.close(); await client.close();}
});

test('Unix transport rejects conflicting policies and HTTP/3 without opening a socket', {skip: !unix, timeout: 15000}, async (t) => {
  let hits = 0, connections = 0;
  const server = http.createServer((_request, response) => {hits++; response.end('ok');});
  server.on('connection', () => {connections++;});
  const socketPath = await peer(t, server);
  for (const network of [{unixSocket: socketPath, localAddresses: ['127.0.0.1']},
    {unixSocket: socketPath, interface: 'lo'},
    {unixSocket: socketPath, hostOverrides: [{host: 'phantom.invalid', addresses: ['127.0.0.1']}]}]) {
    assert.throws(() => new Client({profile, route: 'direct', network}), code('InvalidPolicy'));
  }
  assert.throws(() => new Client({profile, route: 'proxy', proxy: 'http://127.0.0.1:80', network: {unixSocket: socketPath}}), code('InvalidPolicy'));
  const client = new Client({profile, route: 'direct', network: {unixSocket: socketPath}});
  try {await assert.rejects(client.request('https://phantom.invalid/', {...options, protocol: 'http3'}), code('ProtocolUnavailable'));}
  finally {await client.close();}
  assert.equal(hits, 0); assert.equal(connections, 0);
  const missing = new Client({profile, route: 'direct', network: {unixSocket: socketPath + '-absent'}});
  try {await assert.rejects(read(missing, 'http://unresolved.invalid/'), code('Connect'));}
  finally {await missing.close();}
  assert.equal(hits, 0);
});

test('Windows rejects explicit Unix socket configuration with a typed redacted error', {skip: unix}, () => {
  assert.throws(() => new Client({profile, route: 'direct', network: {unixSocket: 'private-path'}}), (error) => {
    assert(code('UnsupportedPlatform')(error)); assert(!String(error).includes('private-path')); return true;
  });
});
