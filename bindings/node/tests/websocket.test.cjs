'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const http2 = require('node:http2');
const path = require('node:path');
const {test: run} = require('node:test');
const {Worker} = require('node:worker_threads');
const {WebSocket, WebSocketServer} = require('ws');

const {Client, WebSocketConnection} = require('..');

const test = (name, action) => run(name, {timeout: 30000}, action);
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const failure = (kind) => (error) => error.code === 'WebSocket' && error.kind === kind;

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {sockets.add(socket); socket.on('close', () => sockets.delete(socket));});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve));});
  return server.address().port;
}

async function peer(t, onConnection, configure = () => {}) {
  const server = http.createServer((_req, res) => res.end('ok'));
  const websocket = new WebSocketServer({server, perMessageDeflate: false});
  configure(websocket);
  websocket.on('connection', (socket, request) => {
    socket.on('error', () => {});
    onConnection(socket, request);
  });
  const port = await listen(t, server);
  t.after(() => {for (const socket of websocket.clients) socket.terminate(); websocket.close();});
  return {url: `ws://127.0.0.1:${port}`, http: `http://127.0.0.1:${port}`};
}

test('WebSocket uses Rust opening fields, selected subprotocol and owned binary messages', async (t) => {
  let opening;
  const {url} = await peer(t, (socket, request) => {
    opening = request;
    socket.on('message', (data, binary) => socket.send(data, {binary}));
  }, (server) => server.on('headers', (headers) => headers.push('X-Duplicate: one', 'X-Duplicate: two')));
  const client = new Client({profile, route: 'direct', headers: [{name: 'X-Client', value: Buffer.from('default')}]});
  t.after(() => client.destroy());
  const socket = await client.websocket(url + '/chat', {headers: [{name: 'Sec-WebSocket-Protocol', value: Buffer.from('chat')}], handshakeTimeoutMs: 5000});
  t.after(() => socket.abort());
  assert(socket instanceof WebSocketConnection);
  assert.equal(socket.handshake.status, 101); assert.equal(socket.handshake.protocol, 'http1');
  assert.equal(socket.handshake.selectedProtocol, 'chat');
  assert.deepEqual(socket.handshake.headers.filter(({name}) => name.toLowerCase() === 'x-duplicate').map(({value}) => value.toString()), ['one', 'two']);
  assert.equal(opening.headers['x-client'], 'default');
  assert.equal(opening.headers['sec-websocket-extensions'], undefined);
  const reading = socket.receive();
  await assert.rejects(socket.receive(), {code: 'InvalidOperation'});
  await socket.send('hello'); assert.deepEqual(await reading, {type: 'text', data: 'hello'});
  const original = Buffer.from([0, 255, 1]);
  const sending = socket.send(original); original.fill(120); await sending;
  assert.deepEqual(await socket.receive(), {type: 'binary', data: Buffer.from([0, 255, 1])});
  await socket.close(1000, 'done'); assert.deepEqual(await socket.receive(), {type: 'close', code: 1000, reason: 'done'});
  assert.equal(await socket.receive(), null);
});

test('WebSocket assembles fragments, flushes automatic pong, and sends explicit controls', async (t) => {
  let upstream;
  const {url} = await peer(t, (socket) => {
    upstream = socket;
    socket.send('hel', {fin: false}); socket.send('lo', {fin: true});
    socket.ping(Buffer.from('automatic'));
  });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.destroy());
  const socket = await client.websocket(url); t.after(() => socket.abort());
  assert.deepEqual(await socket.receive(), {type: 'text', data: 'hello'});
  const pong = once(upstream, 'pong');
  assert.deepEqual(await socket.receive(), {type: 'ping', data: Buffer.from('automatic')});
  assert.equal((await pong)[0].toString(), 'automatic');
  await socket.ping(Buffer.from('caller'));
  assert.deepEqual(await socket.receive(), {type: 'pong', data: Buffer.from('caller')});
  const explicit = once(upstream, 'pong');
  await socket.pong(Buffer.from('explicit')); assert.equal((await explicit)[0].toString(), 'explicit');
  await assert.rejects(socket.close(1005), failure('InvalidRequest'));
  await socket.send('still open');
  await socket.close(); assert.deepEqual(await socket.receive(), {type: 'close', code: null, reason: null});
});

test('WebSocket size limits reject outgoing data before writing and oversized incoming frames close', async (t) => {
  let upstream, sent = 0;
  const {url} = await peer(t, (socket) => {upstream = socket; socket.on('message', () => sent++);});
  const client = new Client({profile, route: 'direct'}); t.after(() => client.destroy());
  const socket = await client.websocket(url, {maximumFrameBytes: 4, maximumMessageBytes: 8}); t.after(() => socket.abort());
  await assert.rejects(socket.send('123456789'), failure('Capacity'));
  assert.equal(sent, 0);
  await socket.send('ok');
  upstream.send('12345');
  await assert.rejects(socket.receive(), failure('Capacity'));
});

test('WebSocket AbortSignal interrupts opening and reads, and handshake timeout remains distinguishable', async (t) => {
  let arrived;
  const seen = new Promise((resolve) => {arrived = resolve;});
  const server = http.createServer(); server.on('upgrade', () => arrived());
  const port = await listen(t, server);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.destroy());
  const controller = new AbortController();
  const opening = client.websocket(`ws://127.0.0.1:${port}`, {signal: controller.signal});
  const rejected = assert.rejects(opening, {code: 'Cancelled'});
  await seen; controller.abort(); await rejected;
  await assert.rejects(client.websocket(`ws://127.0.0.1:${port}`, {handshakeTimeoutMs: 100}), (error) => failure('Timeout')(error) && error.timeoutPhase === 'webSocketHandshake');
  const {url} = await peer(t, () => {});
  const live = new AbortController();
  const socket = await client.websocket(url, {signal: live.signal});
  const reading = socket.receive(); const cancelled = assert.rejects(reading, {code: 'Cancelled'});
  live.abort(); await cancelled;
});

test('destroy closes idle WebSockets and abort releases binding admission', async (t) => {
  const connections = [];
  const {url, http: endpoint} = await peer(t, (socket) => connections.push(socket));
  const client = new Client({profile, route: 'direct', maximumActiveRequests: 1});
  t.after(() => client.destroy());
  const socket = await client.websocket(url);
  await assert.rejects(client.get(endpoint, {context: 'raw'}), {code: 'Capacity'});
  socket.abort();
  const response = await client.get(endpoint, {context: 'raw'});
  assert.equal(await response.text(2), 'ok'); response.close();
  const idle = await client.websocket(url);
  const closed = once(connections[1], 'close');
  await client.destroy(); await closed;
  await assert.rejects(idle.send('after shutdown'), {code: 'Cancelled'});
});

test('graceful close times out without aborting a live WebSocket and can resume', async (t) => {
  const {url, http: endpoint} = await peer(t, (socket) => socket.on('message', (data) => socket.send(data)));
  const client = new Client({profile, route: 'direct'}); t.after(() => client.destroy());
  const socket = await client.websocket(url); t.after(() => socket.abort());
  await assert.rejects(client.close({timeoutMs: 0}), {code: 'Timeout'});
  await assert.rejects(client.get(endpoint, {context: 'raw'}), {code: 'ClientClosed'});
  await assert.rejects(client.websocket(url), {code: 'ClientClosed'});
  await socket.send('still open');
  assert.equal((await socket.receive()).data.toString(), 'still open');
  const closing = client.close();
  await socket.close(1000, 'done');
  assert.deepEqual(await socket.receive(), {type: 'close', code: 1000, reason: 'done'});
  await closing;
});

test('destroy interrupts a pending graceful close and blocked WebSocket receive', async (t) => {
  let connected;
  const {url} = await peer(t, (socket) => {connected = socket;});
  const client = new Client({profile, route: 'direct'}); t.after(() => client.destroy());
  const socket = await client.websocket(url);
  const received = assert.rejects(socket.receive(), {code: 'Cancelled'});
  const closed = once(connected, 'close');
  const closing = client.close();
  await client.destroy(); await closing; await received; await closed;
});

test('graceful close preserves a rejected WebSocket body through timeout', async (t) => {
  const server = http.createServer();
  server.on('upgrade', (_request, socket) => socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied'));
  const port = await listen(t, server);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.destroy());
  let response;
  await assert.rejects(client.websocket(`ws://127.0.0.1:${port}`), (error) => {response = error.response; return failure('HandshakeRejected')(error);});
  t.after(() => response?.close());
  await assert.rejects(client.close({timeoutMs: 0}), {code: 'Timeout'});
  const closing = client.close();
  assert.equal(await response.text(6), 'denied');
  await closing;
});

test('graceful close preserves a pending opening and its late rejected body', async (t) => {
  let rejectOpening, arrived;
  const seen = new Promise((resolve) => {arrived = resolve;});
  const server = http.createServer();
  server.on('upgrade', (_request, socket) => {
    rejectOpening = () => socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied');
    arrived();
  });
  const port = await listen(t, server);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.destroy());
  let response;
  const rejected = assert.rejects(client.websocket(`ws://127.0.0.1:${port}`), (error) => {
    response = error.response; return failure('HandshakeRejected')(error);
  });
  await seen;
  await assert.rejects(client.close({timeoutMs: 0}), {code: 'Timeout'});
  const closing = client.close();
  rejectOpening(); await rejected;
  t.after(() => response?.close());
  assert.equal(await response.text(6), 'denied');
  await closing;
});

test('rejected WebSocket responses retain headers, bounded bodies, cancellation and admission', async (t) => {
  const server = http.createServer((_request, response) => response.end('ok'));
  server.on('upgrade', (_request, socket) => {
    socket.write('HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nX-Duplicate: one\r\nX-Duplicate: two\r\nConnection: close\r\n\r\ndenied');
    socket.end();
  });
  const port = await listen(t, server);
  const client = new Client({profile, route: 'direct', maximumActiveRequests: 1});
  t.after(() => client.destroy());
  const url = `ws://127.0.0.1:${port}/denied`, endpoint = `http://127.0.0.1:${port}`;
  for (const action of ['read', 'limit', 'abort', 'close', 'shutdown']) {
    const controller = new AbortController();
    let failure;
    await assert.rejects(client.websocket(url, {signal: controller.signal}), (error) => {
      failure = error; return error.code === 'WebSocket' && error.kind === 'HandshakeRejected' && error.status === 403;
    });
    const response = failure.response;
    assert.equal(response.status, 403); assert.equal(response.protocol, 'http1');
    assert.equal(response.url, url); assert.equal(response.connectionRetries, null);
    assert.deepEqual(response.headers.filter(({name}) => name.toLowerCase() === 'x-duplicate').map(({value}) => value.toString()), ['one', 'two']);
    await assert.rejects(client.get(endpoint, {context: 'raw'}), {code: 'Capacity'});
    if (action === 'read') assert.equal(await response.text(6), 'denied');
    if (action === 'limit') await assert.rejects(response.bytes(5), {code: 'ResponseBodyLimit'});
    if (action === 'abort') {controller.abort(); await assert.rejects(response.read(), {code: 'Cancelled'});}
    if (action === 'shutdown') {await client.destroy(); await assert.rejects(response.read(), {code: 'Cancelled'});}
    response.close();
    if (action !== 'shutdown') {
      const healthy = await client.get(endpoint, {context: 'raw'});
      assert.equal(healthy.connectionRetries, 0);
      assert.equal(await healthy.text(2), 'ok'); healthy.close();
    }
  }
});

test('HTTP/2 WebSocket abort leaves an unrelated response and pooled connection usable', async (t) => {
  const sessions = [], sockets = new Set();
  let held;
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem'), settings: {enableConnectProtocol: true}});
  server.on('session', (session) => {sockets.add(session); session.on('close', () => sockets.delete(session));});
  server.on('stream', (stream, headers) => {
    sessions.push(stream.session); stream.on('error', () => {});
    if (headers[':protocol'] === 'websocket') {
      stream.respond({':status': 200});
      // ws 8.22.0's server framing engine receives the independently accepted
      // RFC 8441 stream; its ordinary server only performs HTTP/1 upgrades.
      const socket = new WebSocket(null, undefined, {autoPong: true, closeTimeout: 1000});
      socket.on('error', () => {});
      socket.setSocket(stream, Buffer.alloc(0), {allowSynchronousEvents: true, maxPayload: 64 * 1024 * 1024, skipUTF8Validation: false});
      socket.on('message', (data, binary) => socket.send(data, {binary}));
    } else {
      stream.respond({':status': 200});
      if (headers[':path'] === '/held') {held = stream; stream.write('a');} else stream.end('ok');
    }
  });
  const port = await listen(t, server);
  t.after(() => {for (const session of sockets) session.destroy();});
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')]});
  t.after(() => client.destroy());
  const endpoint = `https://127.0.0.1:${port}`;
  const warm = await client.get(endpoint, {context: 'raw'}); assert.equal(await warm.text(2), 'ok'); warm.close();
  const response = await client.get(endpoint + '/held', {context: 'raw'}); t.after(() => response.close());
  const socket = await client.websocket(`wss://127.0.0.1:${port}/chat`, {protocol: 'profile'}); t.after(() => socket.abort());
  assert.equal(socket.handshake.protocol, 'http2');
  const reading = socket.receive(); await socket.send('echo'); assert.deepEqual(await reading, {type: 'text', data: 'echo'});
  const pending = socket.receive(); const aborted = assert.rejects(pending, {code: 'Cancelled'}); socket.abort(); await aborted;
  assert.equal((await response.read(1)).toString(), 'a'); held.end('b');
  assert.equal((await response.read(1)).toString(), 'b'); assert.equal(await response.read(1), null);
  const healthy = await client.get(endpoint, {context: 'raw'}); assert.equal(await healthy.text(2), 'ok'); healthy.close();
  assert.equal(sessions.length, 4); assert(sessions.every((session) => session === sessions[0]));
});

test('worker shutdown tears down an idle native WebSocket', async (t) => {
  let opened;
  const connected = new Promise((resolve) => {opened = resolve;});
  const {url} = await peer(t, (socket) => opened(socket));
  const worker = new Worker(`const {parentPort, workerData} = require('node:worker_threads');
    const {Client} = require(workerData.module);
    (async () => {const client = new Client({profile: workerData.profile, route: 'direct'});
      global.socket = await client.websocket(workerData.url); parentPort.postMessage('open');})();`,
  {eval: true, workerData: {module: path.resolve(__dirname, '..'), profile, url}});
  t.after(() => worker.terminate());
  const notified = once(worker, 'message');
  const socket = await connected; const closed = once(socket, 'close');
  assert.equal((await notified)[0], 'open');
  await worker.terminate(); await closed;
});
