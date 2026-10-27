'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const http2 = require('node:http2');
const path = require('node:path');
const {test: run} = require('node:test');

const {Client, RequestDiagnostics} = require('..');

const test = (name, action) => run(name, {timeout: 30000}, action);
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {protocol: 'http1', context: 'raw', timeoutMs: 10000};
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => {sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve));});
  return server.address().port;
}

async function peer(t, handler) {
  const server = http.createServer(handler); const port = await listen(t, server);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.destroy());
  return {client, url: `http://127.0.0.1:${port}`};
}

test('SSE decodes fragmented fields, UTF-8 replacement and persistent ID/retry state', async (t) => {
  let request;
  const bytes = Buffer.concat([Buffer.from('\ufeff: comment\r\nid: first\rretry: 0\nevent: update\r\ndata: hé\r\ndata: two\r\n\r\n'),
    Buffer.from('id:\nretry: 18446744073709551615\nretry: nope\ndata: '), Buffer.from([0xff]),
    Buffer.from('\n\nid: final\nretry: 17\n\ndata: discarded at EOF')]);
  const {client, url} = await peer(t, (incoming, response) => {
    request = incoming;
    response.writeHead(200, {'content-type': 'Text/Event-Stream; charset=utf-8', trailer: 'X-End'});
    let offset = 0;
    function write() {
      if (response.destroyed) return;
      if (offset === bytes.length) {response.addTrailers({'X-End': 'done'}); response.end(); return;}
      response.write(bytes.subarray(offset, ++offset)); setImmediate(write);
    }
    write();
  });
  const diagnostics = new RequestDiagnostics();
  const response = await client.post(url + '/events?x=1', {...options, diagnostics, body: 'request',
    headers: [{name: 'X-Test', value: Buffer.from('kept')}]});
  const stream = response.events();
  assert.equal(stream.lastEventId, ''); assert.equal(stream.retryMs, null);
  assert.deepEqual(await stream.read(), {data: 'hé\ntwo', event: 'update', id: 'first', retryMs: 0n});
  assert.deepEqual(await stream.read(), {data: '\ufffd', event: 'message', id: '', retryMs: 18446744073709551615n});
  assert.equal(await stream.read(), null); assert.equal(await stream.read(), null);
  assert.equal(stream.lastEventId, 'final'); assert.equal(stream.retryMs, 17n);
  assert.equal(request.method, 'POST'); assert.equal(request.url, '/events?x=1'); assert.equal(request.headers['x-test'], 'kept');
  assert.equal(response.trailers.state, 'complete');
  assert.deepEqual(response.trailers.headers.map(({name, value}) => [name.toLowerCase(), value.toString()]), [['x-end', 'done']]);
  assert.equal(diagnostics.snapshot().events.find((event) => event.phase === 'response_body').outcome, 'completed');
  response.close();
});

test('SSE metadata validation preserves ordinary response consumption', async (t) => {
  const cases = [
    {status: 204, headers: {'content-type': 'text/event-stream'}, kind: 'UnexpectedStatus', body: ''},
    {status: 403, headers: {'content-type': 'text/event-stream'}, kind: 'UnexpectedStatus', body: 'denied'},
    {status: 200, headers: {}, kind: 'InvalidContentType', body: 'missing'},
    {status: 200, headers: {'content-type': 'application/json'}, kind: 'InvalidContentType', body: '{}'},
    {status: 200, headers: {'content-type': ['text/event-stream', 'text/plain']}, kind: 'InvalidContentType', body: 'duplicate'},
    {status: 200, headers: {'content-type': 'text/event-stream', 'content-encoding': 'gzip'}, kind: 'UnsupportedContentEncoding', body: 'encoded'},
  ];
  const {client, url} = await peer(t, (request, response) => {
    const item = cases[Number(request.url.slice(1))]; response.writeHead(item.status, item.headers); response.end(item.body);
  });
  for (const [index, item] of cases.entries()) {
    const response = await client.get(url + '/' + index, options);
    assert.throws(() => response.events(), {code: 'Sse', kind: item.kind});
    assert.equal(await response.text(64), item.body);
    assert.equal(response.trailers.state, 'complete'); response.close();
  }
});

test('SSE applies encoded line and block limits including zero and explicit large events', async (t) => {
  const large = Array.from({length: 20}, () => 'data: ' + 'a'.repeat(60000) + '\n').join('') + '\n';
  const payloads = {'/line': 'data: ' + 'a'.repeat(65531) + '\n\n', '/event': large, '/small': 'data: x\n\n'};
  const {client, url} = await peer(t, (request, response) => {
    response.writeHead(200, {'content-type': 'text/event-stream'}); response.end(payloads[request.url]);
  });
  for (const [target, limits, kind] of [['/line', undefined, 'LineTooLong'], ['/event', undefined, 'EventTooLarge'],
    ['/small', {maximumLineBytes: 0}, 'LineTooLong'], ['/small', {maximumEventBytes: 0}, 'EventTooLarge']]) {
    const response = await client.get(url + target, options); const stream = response.events(limits);
    await assert.rejects(stream.read(), {code: 'Sse', kind}); assert.equal(await stream.read(), null);
    assert.equal(response.trailers.state, 'unavailable');
  }
  const response = await client.get(url + '/event', options);
  const stream = response.events({maximumEventBytes: 2 * 1024 * 1024});
  const event = await stream.read(); assert.equal(event.data, Array(20).fill('a'.repeat(60000)).join('\n'));
  assert.equal(await stream.read(), null); assert.equal(response.trailers.state, 'complete');
});

test('SSE close interrupts pending reads and graceful shutdown can resume after its deadline', async (t) => {
  const releases = new Map();
  const {client, url} = await peer(t, (request, response) => {
    response.writeHead(200, {'content-type': 'text/event-stream'}); response.flushHeaders();
    releases.set(request.url, () => response.end('data: done\n\n'));
  });
  const response = await client.get(url + '/drain', {protocol: 'http1', context: 'raw', timeouts: {totalMs: null}});
  const stream = response.events();
  const reading = stream.read(); await assert.rejects(stream.read(), {code: 'ConcurrentRead'});
  await assert.rejects(client.close({timeoutMs: 0}), {code: 'Timeout'});
  releases.get('/drain')(); assert.equal((await reading).data, 'done'); assert.equal(await stream.read(), null);
  await client.close({timeoutMs: 5000});

  const other = new Client({profile, route: 'direct'}); t.after(() => other.destroy());
  for (const mode of ['close', 'signal']) {
    const controller = new AbortController();
    const response = await other.get(url + '/' + mode, {...options, signal: controller.signal});
    const stream = response.events(); const pending = stream.read();
    const rejected = assert.rejects(pending, {code: 'Cancelled'});
    if (mode === 'close') stream.close(); else controller.abort();
    await rejected; assert.equal(response.trailers.state, 'unavailable');
  }
});

test('SSE cancellation preserves a live HTTP/2 sibling and subsequent connection reuse', async (t) => {
  const sessions = new Set(), observed = new Map(), releases = new Map(), resets = new Map();
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem')});
  server.on('session', (session) => {sessions.add(session); session.on('error', () => {});});
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {}); const target = headers[':path']; observed.set(target, stream.session);
    stream.respond({':status': 200, 'content-type': 'text/event-stream'});
    if (target.startsWith('/healthy')) releases.set(target, () => stream.end('data: healthy\n\n'));
    else if (target === '/after') stream.end('data: after\n\n');
    else {resets.set(target, new Promise((resolve) => stream.once('close', () => resolve(stream.rstCode)))); stream.write(': waiting\n');}
  });
  const port = await listen(t, server); t.after(() => {for (const session of sessions) session.destroy();});
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')]});
  t.after(() => client.destroy());
  const url = `https://127.0.0.1:${port}`; const exact = {protocol: 'http2', context: 'raw', timeoutMs: 10000};
  for (const mode of ['close', 'signal', 'total', 'idle']) {
    const healthy = (await client.get(url + '/healthy-' + mode, exact)).events();
    const controller = new AbortController();
    const selected = (await client.get(url + '/' + mode, {...exact, signal: controller.signal,
      timeoutMs: undefined, timeouts: {totalMs: mode === 'total' ? 2000 : null, readIdleMs: mode === 'idle' ? 1000 : null}})).events();
    assert.equal(observed.get('/' + mode), observed.get('/healthy-' + mode));
    const reading = selected.read();
    const cancelled = assert.rejects(reading, ['total', 'idle'].includes(mode)
      ? {code: 'Timeout', timeoutPhase: mode === 'total' ? 'total' : 'readIdle'} : {code: 'Cancelled'});
    if (mode === 'close') selected.close(); else if (mode === 'signal') controller.abort();
    await cancelled; assert.equal(await resets.get('/' + mode), http2.constants.NGHTTP2_CANCEL);
    releases.get('/healthy-' + mode)(); assert.equal((await healthy.read()).data, 'healthy'); assert.equal(await healthy.read(), null);
  }
  const after = (await client.get(url + '/after', exact)).events();
  assert.equal((await after.read()).data, 'after'); assert.equal(await after.read(), null); assert.equal(sessions.size, 1);
});
