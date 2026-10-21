'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
const fs = require('node:fs/promises');
const http = require('node:http');
const http2 = require('node:http2');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');
const {Client, AttemptBudget, PhantomError} = require('..');
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'POST', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const field = (name, value) => ({name, value: Buffer.from(value)});
const headers = (boundary = 'b') => [field('X-Before', 'first'), field('Content-Type', `multipart/form-data; boundary=${boundary}`), field('X-After', 'last')];
function source(chunks) {
  let index = 0, settle;
  const closed = new Promise((resolve) => {settle = resolve;});
  return {closed, pulls: 0, closes: 0, [Symbol.asyncIterator]() {return this;}, async next() {
    this.pulls++; return index === chunks.length ? {done: true} : {done: false, value: chunks[index++]};
  }, async return() {this.closes++; settle(); return {done: true};}};
}
async function peer(t, handler) {
  const server = http.createServer(handler), sockets = new Set(), errors = [];
  server.on('connection', (socket) => {sockets.add(socket); socket.on('error', (error) => {
    if (!['ECONNRESET', 'ECONNABORTED', 'EPIPE'].includes(error.code)) errors.push(error);
  }); socket.on('close', () => sockets.delete(socket));});
  server.on('clientError', (error, socket) => {if (!['ECONNRESET', 'ECONNABORTED', 'EPIPE', 'HPE_INVALID_EOF_STATE'].includes(error.code)) errors.push(error); socket.destroy();});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); assert.deepEqual(errors, []);});
  return {server, url: `http://127.0.0.1:${server.address().port}`};
}

test('streaming multipart uses literal ordered core framing, lazy files and seventy sources', {timeout: 30000}, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-multipart-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const filename = path.join(directory, 'part.bin'); await fs.writeFile(filename, Buffer.from([0, 255]));
  const observed = [];
  const {url} = await peer(t, (request, response) => {
    const chunks = []; request.on('data', (data) => chunks.push(data));
    request.on('end', () => {observed.push({body: Buffer.concat(chunks), headers: request.rawHeaders, framing: request.headers}); response.end('ok');});
  });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const streams = Array.from({length: 70}, () => source([Buffer.from('z')]));
  const parts = [{name: 'x', text: 'one\nline'}, {name: 'x', file: {path: filename, maximumBytes: 2}, filename: 'a"b'}];
  parts.push(...streams.map((stream) => ({name: 'x', stream})));
  const prefix = Buffer.from('--b\r\nContent-Disposition: form-data; name="x"\r\n\r\none\r\nline\r\n'
    + '--b\r\nContent-Disposition: form-data; name="x"; filename="a%22b"\r\nContent-Type: application/octet-stream\r\n\r\n');
  const expected = Buffer.concat([prefix, Buffer.from([0, 255]), Buffer.from('\r\n'),
    ...streams.map(() => Buffer.from('--b\r\nContent-Disposition: form-data; name="x"\r\nContent-Type: application/octet-stream\r\n\r\nz\r\n')), Buffer.from('--b--\r\n')]);
  const response = await client.request(url, {...options, headers: headers(), multipart: {boundary: 'b', maximumBytes: expected.length, parts}});
  assert.equal(await response.text(2), 'ok');
  assert.equal(observed.length, 1); assert.deepEqual(observed[0].body, expected);
  assert.equal(observed[0].framing['transfer-encoding'], 'chunked'); assert.equal(observed[0].framing['content-length'], undefined);
  assert.ok(observed[0].headers.indexOf('X-Before') < observed[0].headers.indexOf('Content-Type'));
  assert.ok(observed[0].headers.indexOf('Content-Type') < observed[0].headers.indexOf('X-After'));
  assert.ok(streams.every((stream) => stream.pulls === 2 && stream.closes === 1));
});

test('multipart preflight keeps budgets and unclaimed sources; one-shot replay never sends twice', {timeout: 30000}, async (t) => {
  const sent = [], {url} = await peer(t, (request, response) => {
    sent.push(request.url); request.resume(); request.on('end', () => {response.writeHead(307, {location: '/unexpected'}).end();});
  });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const budget = new AttemptBudget(2), unclaimed = source([]);
  const descriptor = {boundary: 'b', maximumBytes: 4096, parts: [{name: 'x', stream: unclaimed}]};
  for (const invalid of [{body: Buffer.alloc(0)}, {bodyLength: 0}, {file: {path: 'private', maximumBytes: 1}}]) {
    await assert.rejects(client.request(url, {...options, multipart: descriptor, ...invalid, attemptBudget: budget}), {code: 'InvalidArgument'});
  }
  assert.equal(unclaimed.closes, 0); assert.equal(unclaimed.pulls, 0);
  for (const invalidHeaders of [[], headers('wrong'), [...headers(), field('content-type', 'multipart/form-data; boundary=b')]]) {
    const stream = source([]);
    await assert.rejects(client.request(url, {...options, headers: invalidHeaders, multipart: {boundary: 'b', maximumBytes: 4096, parts: [{name: 'x', stream}]}, attemptBudget: budget}),
      (error) => error instanceof PhantomError && error.code === 'InvalidHeader');
  }
  assert.equal(budget.remaining, 2); assert.deepEqual(sent, []);
  const stream = source([Buffer.from('one-shot')]), once = {boundary: 'b', maximumBytes: 4096, parts: [{name: 'x', stream}]};
  await assert.rejects(client.request(url + '/redirect', {...options, headers: headers(), multipart: once, attemptBudget: budget,
    redirectPolicy: {mode: 'limited', maximumHops: 1}}), {code: 'RequestBody'});
  await assert.rejects(client.request(url, {...options, headers: headers(), multipart: once}), {code: 'InvalidOperation'});
  await client.close(); assert.equal(stream.closes, 1); assert.deepEqual(sent, ['/redirect']); assert.equal(budget.remaining, 1);
});

test('HTTP/1 multipart rejects explicit length before admission without sending request bytes', {timeout: 30000}, async (t) => {
  const sockets = new Set(), errors = []; let received = 0;
  const server = net.createServer((socket) => {
    sockets.add(socket); socket.on('data', (data) => {received += data.length;});
    socket.on('error', (error) => {if (!['ECONNRESET', 'ECONNABORTED', 'EPIPE'].includes(error.code)) errors.push(error);});
    socket.on('close', () => sockets.delete(socket));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); if (server.listening) await new Promise((resolve) => server.close(resolve));});
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const budget = new AttemptBudget(2), stream = source([]);
  await assert.rejects(client.request(`http://127.0.0.1:${server.address().port}`, {
    ...options, headers: [...headers(), field('Content-Length', '1')],
    multipart: {boundary: 'b', maximumBytes: 4096, parts: [{name: 'x', stream}]}, attemptBudget: budget,
  }), (error) => error instanceof PhantomError && error.code === 'Http1');
  await client.close(); await new Promise((resolve) => server.close(resolve));
  assert.equal(budget.remaining, 2); assert.equal(received, 0); assert.deepEqual(errors, []);
  await stream.closed; assert.equal(stream.closes, 1);
});

test('multipart caps and split boundary collisions fail as typed core errors', {timeout: 30000}, async (t) => {
  const {url} = await peer(t, (request) => request.resume());
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  for (const [chunks, maximumBytes, kind] of [
    [[Buffer.alloc(1000, 120)], 110, 'too_large'],
    [[Buffer.from('prefix--'), Buffer.from('b-secret')], 4096, 'boundary_collision'],
  ]) {
    const stream = source(chunks);
    await assert.rejects(client.request(url, {...options, headers: headers(), multipart: {boundary: 'b', maximumBytes, parts: [{name: 'x', stream}]}}),
      (error) => error instanceof PhantomError && error.code === 'PreparedBody' && error.kind === kind && !String(error).includes('secret'));
    await stream.closed; assert.equal(stream.closes, 1);
  }
});

test('Expect early final sends no multipart data and cleans all unstarted sources', {timeout: 30000}, async (t) => {
  const {server, url} = await peer(t, () => assert.fail('Expect request reached ordinary handler'));
  let received = 0, sawHead = false;
  server.on('checkContinue', (request, response) => {
    sawHead = true; request.on('data', (data) => {received += data.length;});
    response.writeHead(417, {'content-length': 0, connection: 'close'}).end();
  });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const first = source([Buffer.from('private')]), later = source([]);
  const response = await client.request(url, {...options, headers: headers(), expectContinueMs: 30000,
    multipart: {boundary: 'b', maximumBytes: 4096, parts: [{name: 'x', stream: first}, {name: 'y', stream: later}, {name: 'z', file: {path: path.join(os.tmpdir(), 'not-opened-phantom-multipart'), maximumBytes: 1}}]}});
  assert.equal(response.status, 417); await response.bytes(0);
  assert.equal(sawHead, true); assert.equal(received, 0); assert.ok(first.pulls <= 1); assert.equal(later.pulls, 0);
  assert.equal(first.closes, 1); assert.equal(later.closes, 1);
});

test('HTTP/2 multipart abort, close and unread deadline preserve a live sibling and connection', {timeout: 30000}, async (t) => {
  const fixture = (name) => require('node:fs').readFileSync(path.join(__dirname, 'fixtures', name));
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem'), settings: {initialWindowSize: 0}});
  const sessions = new Set(), selected = new Map(), sources = [], errors = []; let healthySession, releaseHealthy;
  server.on('session', (session) => {sessions.add(session);});
  server.on('stream', (stream, head) => {
    const target = head[':path'];
    if (target === '/healthy') {healthySession = stream.session; stream.respond({':status': 200}); releaseHealthy = () => stream.end('healthy'); return;}
    if (target === '/warm' || target === '/reuse') {stream.respond({':status': 200}); stream.end('ok'); return;}
    let received = 0; stream.on('data', (data) => {received += data.length;}); stream.on('error', (error) => {errors.push({error, stream});});
    const session = stream.session, closed = new Promise((resolve) => stream.on('close', () => resolve({reset: stream.rstCode, received})));
    selected.set(target, {session, closed}); stream.respond({':status': 200});
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const session of sessions) session.destroy(); await new Promise((resolve) => server.close(resolve));});
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')], timeouts: {totalMs: 5000}});
  t.after(() => client.close()); const url = `https://127.0.0.1:${server.address().port}`, get = {method: 'GET', protocol: 'http2', context: 'raw'};
  assert.equal(await (await client.request(url + '/warm', get)).text(2), 'ok');
  for (const mode of ['abort', 'close', 'total']) {
    const stream = source([Buffer.alloc(1024)]), later = source([]), controller = new AbortController();
    sources.push({stream, later});
    const response = await client.request(url + '/' + mode, {...get, method: 'POST', signal: controller.signal,
      headers: [{name: 'content-type', value: Buffer.from('multipart/form-data; boundary=b')}],
      multipart: {boundary: 'b', maximumBytes: 4096, parts: [{name: 'x', stream}, {name: 'y', stream: later}]}});
    const healthy = await client.request(url + '/healthy', {...get, timeouts: {totalMs: null}});
    assert.equal(selected.get('/' + mode).session, healthySession);
    if (mode === 'abort') controller.abort();
    if (mode === 'close') response.close();
    const closed = await selected.get('/' + mode).closed;
    assert.equal(closed.reset, http2.constants.NGHTTP2_CANCEL); assert.equal(closed.received, 0);
    releaseHealthy(); assert.equal(await healthy.text(7), 'healthy');
    if (mode === 'total') await assert.rejects(response.read(), (error) => error.code === 'Timeout' && error.timeoutPhase === 'total');
    else response.close();
    assert.equal(await (await client.request(url + '/reuse', get)).text(2), 'ok');
  }
  await client.close(); assert.equal(sessions.size, 1);
  assert.ok(errors.every(({error, stream}) => error.code === 'ERR_HTTP2_STREAM_ERROR' && stream.rstCode === http2.constants.NGHTTP2_CANCEL));
  for (const {stream, later} of sources) {assert.equal(stream.closes, 1); assert.equal(later.closes, 1); assert.equal(later.pulls, 0);}
});
