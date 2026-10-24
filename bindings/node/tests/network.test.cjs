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

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', context: 'raw', timeoutMs: 10000};
const code = (name) => (error) => error instanceof PhantomError && error.code === name;

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {sockets.add(socket); socket.once('close', () => sockets.delete(socket));});
  server.on('tlsClientError', () => {}); server.on('sessionError', () => {});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve));});
  return server.address().port;
}

async function material(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-network-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const config = path.join(directory, 'tls.cnf'), key = path.join(directory, 'key.pem'), cert = path.join(directory, 'cert.pem');
  await fs.writeFile(config, '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=phantom.invalid\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:phantom.invalid,DNS:other.invalid\n');
  await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
    '-days', '2', '-config', config, '-keyout', key, '-out', cert], {timeout: 10000, maxBuffer: 65536});
  const certificate = await fs.readFile(cert);
  return {key: await fs.readFile(key), cert: certificate, root: new X509Certificate(certificate).raw};
}

test('network overrides retain verified TLS identity, per-origin pools and source selection', {timeout: 60000}, async (t) => {
  const tls = await material(t), records = [], sockets = new Set();
  let port, connections = 0;
  for (const protocol of ['http1', 'http2', 'negotiated']) {
    const handler = (request, response) => {
      assert.equal(request.httpVersionMajor, protocol === 'http1' ? 1 : 2);
      records.push({host: request.headers.host ?? request.headers[':authority'],
        sni: request.socket.servername, source: request.socket.remoteAddress, connection: protocol === 'http1' ? request.socket : request.stream.session});
      sockets.add(protocol === 'http1' ? request.socket : request.stream.session); response.end('ok');
    };
    const server = protocol === 'http1'
      ? https.createServer({key: tls.key, cert: tls.cert, ALPNProtocols: ['http/1.1']}, handler)
      : http2.createSecureServer({key: tls.key, cert: tls.cert}, handler);
    server.on('connection', () => { connections++; });
    port = await listen(t, server);
    const client = new Client({profile, route: 'direct', additionalRoots: [tls.root], network: {
      hostOverrides: [{host: 'PHANTOM.invalid', addresses: []}, {host: 'phantom.invalid', addresses: ['127.0.0.1']},
        {host: 'other.invalid', addresses: ['127.0.0.1']}], localAddresses: ['127.0.0.1']}});
    try {
      const start = records.length;
      for (const [index, host] of ['phantom.invalid', 'phantom.invalid', 'other.invalid'].entries()) {
        let response;
        try {response = await client.request(`https://${host}:${port}/`, {...options, protocol});}
        catch (error) {
          t.diagnostic(JSON.stringify({protocol, host, port, ordinal: index + 1,
            totalConnections: connections, receivedRequests: records.length - start,
            code: error.code, errorProtocol: error.protocol, timeoutPhase: error.timeoutPhase}));
          throw error;
        }
        try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
      }
      const seen = records.slice(start);
      assert.equal(seen[0].connection, seen[1].connection); assert.notEqual(seen[1].connection, seen[2].connection);
      for (const [index, host] of ['phantom.invalid', 'phantom.invalid', 'other.invalid'].entries()) {
        assert.equal(seen[index].host, `${host}:${port}`); assert.equal(seen[index].sni, host);
        assert.equal(seen[index].source, '127.0.0.1');
      }
      const fork = client.fork(); await client.close();
      try {
        const response = await fork.request(`https://phantom.invalid:${port}/`, {...options, protocol});
        try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
      } finally {await fork.close();}
    } finally {await client.close();}
  }
  const before = records.length, connectionsBefore = connections;
  for (const network of [{hostOverrides: [{host: 'phantom.invalid', addresses: []}]},
    {hostOverrides: [{host: 'phantom.invalid', addresses: ['127.0.0.1']}], localAddresses: ['::1']}]) {
    const client = new Client({profile, route: 'direct', additionalRoots: [tls.root], network});
    try {await assert.rejects(client.request(`https://phantom.invalid:${port}/`, {...options, protocol: 'http1'}), code('Connect'));}
    finally {await client.close();}
  }
  assert.equal(records.length, before); assert.equal(connections, connectionsBefore); assert(sockets.size >= 9);
});

test('HTTP proxy hostname overrides apply without resolving the origin locally', {timeout: 15000}, async (t) => {
  const requests = [];
  const server = http.createServer((request, response) => {requests.push(request.url); response.end('ok');});
  const port = await listen(t, server);
  const client = new Client({profile, route: 'proxy', proxy: `http://proxy.invalid:${port}`, network: {
    hostOverrides: [{host: 'proxy.invalid', addresses: ['127.0.0.1']}, {host: 'phantom.invalid', addresses: []}]}});
  try {
    const response = await client.request('http://phantom.invalid/path', {...options, protocol: 'http1'});
    try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
  } finally {await client.close();}
  assert.deepEqual(requests, ['http://phantom.invalid/path']);
});

test('native network address and source validation fails without echoing input', () => {
  for (const [network, expected] of [[{localAddresses: ['0.0.0.0']}, 'InvalidPolicy'], [{interface: ''}, 'InvalidPolicy'],
    [{hostOverrides: [{host: '127.0.0.1', addresses: ['127.0.0.1']}]}, 'InvalidPolicy'],
    [{hostOverrides: [{host: 'example.invalid', addresses: ['private supplied value']}]}, 'InvalidConfiguration']]) {
    assert.throws(() => new Client({profile, route: 'direct', network}), (error) => {
      assert.equal(error.code, expected); assert(!String(error).includes('supplied')); return true;
    });
  }
});
