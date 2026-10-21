'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const http2 = require('node:http2');
const net = require('node:net');
const path = require('node:path');
const {test} = require('node:test');
const {Client, PhantomError} = require('..');

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const request = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const code = (value) => (error) => error instanceof PhantomError && error.code === value;
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {sockets.add(socket); socket.once('close', () => sockets.delete(socket));});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return server.address().port;
}

// Independently decode SOCKS4's literal CONNECT request before opening a tunnel.
async function socksPeer(t, targetPort, reject = false) {
  const records = [], errors = [], incoming = new Set(), outgoing = new Set();
  let connections = 0, closing = false;
  const server = net.createServer((socket) => {
    connections++;
    incoming.add(socket); socket.once('close', () => incoming.delete(socket));
    let input = Buffer.alloc(0), completed = false;
    socket.on('error', (error) => {
      if (!closing && !['ECONNRESET', 'ECONNABORTED', 'EPIPE'].includes(error.code)) errors.push(error);
    });
    socket.once('end', () => {if (!completed && !closing) errors.push(Error('incomplete SOCKS4 handshake'));});
    const read = (data) => {
      try {
        input = Buffer.concat([input, data]);
        assert(input.length <= 1024, 'bounded SOCKS4 request');
        if (input.length < 9) return;
        assert.equal(input[0], 4); assert.equal(input[1], 1);
        assert.equal(input.readUInt16BE(2), targetPort);
        const userEnd = input.indexOf(0, 8);
        if (userEnd < 0) return;
        const address = [...input.subarray(4, 8)];
        const remote = address[0] === 0 && address[1] === 0 && address[2] === 0 && address[3] !== 0;
        const hostEnd = remote ? input.indexOf(0, userEnd + 1) : userEnd;
        if (hostEnd < 0) return;
        assert.equal(input.length, hostEnd + 1, 'origin bytes must wait for SOCKS success');
        records.push({address, userId: Buffer.from(input.subarray(8, userEnd)),
          host: remote ? input.subarray(userEnd + 1, hostEnd).toString('utf8') : undefined});
        completed = true; socket.removeListener('data', read);
        if (reject) {socket.end(Buffer.from([0, 91, 0, 0, 0, 0, 0, 0])); return;}
        const upstream = net.connect({host: '127.0.0.1', port: targetPort});
        outgoing.add(upstream); upstream.once('close', () => outgoing.delete(upstream));
        upstream.on('error', (error) => {
          if (!closing && !['ECONNRESET', 'ECONNABORTED', 'EPIPE'].includes(error.code)) errors.push(error);
          socket.destroy();
        });
        socket.once('close', () => upstream.destroy());
        upstream.once('connect', () => {
          socket.write(Buffer.from([0, 90, 0, 0, 0, 0, 0, 0]));
          socket.pipe(upstream); upstream.pipe(socket);
        });
      } catch (error) {errors.push(error); socket.destroy();}
    };
    socket.on('data', read);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port;
  t.after(async () => {
    closing = true;
    const settled = [...incoming, ...outgoing].map((socket) => {
      const closed = once(socket, 'close'); socket.destroy(); return closed;
    });
    await new Promise((resolve) => server.close(resolve));
    await Promise.all(settled);
    assert.deepEqual(errors, []);
  });
  return {port, records, get connections() {return connections;}};
}

test('SOCKS4 local DNS and SOCKS4a remote DNS retain literal targets and user IDs', {timeout: 30000}, async (t) => {
  const hosts = [];
  const originPort = await listen(t, http.createServer((req, res) => {hosts.push(req.headers.host); res.end('ok');}));
  for (const scheme of ['socks4', 'socks4a']) {
    const proxy = await socksPeer(t, originPort);
    const owner = new Client({profile, route: 'proxy', proxy: `${scheme}://127.0.0.1:${proxy.port}`,
      proxyUserId: 'é-user', network: {hostOverrides: [{host: 'origin.invalid',
        addresses: scheme === 'socks4' ? ['::1', '127.0.0.1'] : []}]}});
    try {
      const response = await owner.request(`http://origin.invalid:${originPort}/`, request);
      try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
      assert.equal(proxy.records.length, 1);
      const record = proxy.records[0];
      assert.deepEqual(record.userId, Buffer.from('é-user'));
      assert.deepEqual(record.address, scheme === 'socks4' ? [127, 0, 0, 1] : [0, 0, 0, 1]);
      assert.equal(record.host, scheme === 'socks4a' ? 'origin.invalid' : undefined);
    } finally {await owner.close();}
  }
  assert.deepEqual(hosts, Array(2).fill(`origin.invalid:${originPort}`));
});

test('SOCKS4a carries verified HTTP2 without changing TLS identity or fork ownership', {timeout: 30000}, async (t) => {
  const observed = [], failures = [];
  const origin = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem')}, (req, res) => {
    observed.push({host: req.headers[':authority'], sni: req.socket.servername, protocol: req.httpVersionMajor}); res.end('ok');
  });
  origin.on('tlsClientError', (error) => failures.push(error));
  origin.on('sessionError', (error) => failures.push(error));
  const originPort = await listen(t, origin), proxy = await socksPeer(t, originPort);
  const owner = new Client({profile, route: 'proxy', proxy: `socks4a://127.0.0.1:${proxy.port}`,
    additionalRoots: [fixture('certificate.der')], network: {hostOverrides: [{host: 'localhost', addresses: []}]}});
  let child;
  try {
    const send = async (client) => {
      const response = await client.request(`https://localhost:${originPort}/`, {...request, protocol: 'http2'});
      try {assert.equal(await response.text(2), 'ok'); assert.equal(response.protocol, 'http2');} finally {response.close();}
    };
    await send(owner);
    child = owner.fork(); await owner.close(); await send(child);
    assert.equal(proxy.records.length, 2);
    for (const record of proxy.records) {assert.equal(record.host, 'localhost'); assert.equal(record.userId.length, 0);}
    assert.deepEqual(observed, Array(2).fill({host: `localhost:${originPort}`, sni: 'localhost', protocol: 2}));
    assert.deepEqual(failures, []);
  } finally {await child?.close(); await owner.close();}
});

test('SOCKS4 rejects passwords, unsupported targets and failed DNS before proxy I/O', {timeout: 30000}, async (t) => {
  const proxy = await socksPeer(t, 80);
  const uri = `socks4://127.0.0.1:${proxy.port}`;
  for (const extra of [{proxyPassword: 'private-password'}, {proxyUsername: 'private-user'},
    {proxyUsername: 'private-user', proxyPassword: 'private-password'}, {proxyUserId: 'private\0user'}]) {
    assert.throws(() => new Client({profile, route: 'proxy', proxy: uri, ...extra}),
      (error) => code('InvalidProxy')(error) && !String(error).includes('private'));
  }
  const owner = new Client({profile, route: 'proxy', proxy: uri,
    network: {hostOverrides: [{host: 'origin.invalid', addresses: []}]}});
  try {
    await assert.rejects(owner.request('https://origin.invalid/', {...request, protocol: 'http3'}), code('UnsupportedRoute'));
    await assert.rejects(owner.request('http://[::1]/', request), code('Proxy'));
    await assert.rejects(owner.request('http://origin.invalid/', request), code('Resolve'));
    assert.equal(proxy.connections, 0);
  } finally {await owner.close();}
});

test('SOCKS4 proxy rejection never falls back to a direct origin connection', {timeout: 30000}, async (t) => {
  let hits = 0, connections = 0;
  const origin = http.createServer((_req, res) => {hits++; res.end('unexpected');});
  origin.on('connection', () => {connections++;});
  const originPort = await listen(t, origin), proxy = await socksPeer(t, originPort, true);
  const owner = new Client({profile, route: 'proxy', proxy: `socks4://127.0.0.1:${proxy.port}`});
  try {
    await assert.rejects(owner.request(`http://127.0.0.1:${originPort}/`, request), code('Proxy'));
    assert.equal(proxy.records.length, 1); assert.equal(hits, 0); assert.equal(connections, 0);
  } finally {await owner.close();}
});
