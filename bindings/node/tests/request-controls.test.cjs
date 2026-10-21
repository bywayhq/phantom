'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
const http = require('node:http');
const net = require('node:net');
const {test} = require('node:test');
const {Client, AttemptBudget, PhantomError} = require('..');

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'POST', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const field = (name, value, sensitive = false) => ({name, value: Buffer.from(value), sensitive});

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); });
  return `http://127.0.0.1:${server.address().port}`;
}

test('static HTTP/1 trailers preserve exact chunked wire order, case and duplicate positions', {timeout: 30000}, async (t) => {
  let recorded;
  const received = new Promise((resolve) => { recorded = resolve; });
  const tail = Buffer.from('0\r\nX-Repeat: first\r\nx-middle: between\r\nX-Repeat: last\r\n\r\n');
  const server = net.createServer((socket) => {
    let wire = Buffer.alloc(0);
    socket.on('data', (bytes) => {
      wire = Buffer.concat([wire, bytes]);
      if (wire.length >= tail.length && wire.subarray(-tail.length).equals(tail)) {
        recorded(wire);
        socket.end('HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n');
      }
    });
  });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const response = await client.request(url, {...options, body: Buffer.from('abc'),
    headers: [field('X-First', 'head')],
    trailers: [field('X-Repeat', 'first'), field('x-middle', 'between', true), field('X-Repeat', 'last')]});
  await response.bytes(0);
  const wire = await received;
  const split = wire.indexOf('\r\n\r\n'); const head = wire.subarray(0, split).toString('latin1');
  assert.match(head, /\r\nTransfer-Encoding: chunked/i); assert.doesNotMatch(head, /\r\nContent-Length:/i);
  assert.ok(head.indexOf('X-First: head') < head.toLowerCase().indexOf('transfer-encoding:'));
  assert.equal(wire.subarray(split + 4).toString('latin1'), '3\r\nabc\r\n' + tail.toString('latin1'));
});

test('100 Continue gates origin body bytes and preserves the caller Expect position', {timeout: 30000}, async (t) => {
  let release, observed;
  const headSeen = new Promise((resolve) => { observed = resolve; });
  const server = http.createServer();
  server.on('checkContinue', (request, response) => {
    let body = '';
    request.on('data', (bytes) => { body += bytes.toString(); });
    request.on('end', () => response.end(body));
    release = () => { assert.equal(body, ''); response.writeContinue(); };
    observed(request.rawHeaders);
  });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const pending = client.request(url, {...options, body: Buffer.from('payload'), expectContinueMs: 4000n,
    headers: [field('X-Before', 'first'), field('Expect', '100-continue'), field('X-After', 'last')]});
  const head = await headSeen;
  assert.ok(head.indexOf('X-Before') < head.indexOf('Expect')); assert.ok(head.indexOf('Expect') < head.indexOf('X-After'));
  await new Promise((resolve) => setImmediate(resolve)); release();
  assert.equal(await (await pending).text(7), 'payload');
});

test('an early final expectation response sends no origin body and settles producer cleanup', {timeout: 30000}, async (t) => {
  let originBytes = 0, pulls = 0, returned = 0;
  const server = http.createServer();
  server.on('checkContinue', (request, response) => {
    request.on('data', (bytes) => { originBytes += bytes.length; });
    response.writeHead(417, {'content-length': '0', connection: 'close'}); response.end();
  });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct'});
  t.after(() => client.close());
  const body = {[Symbol.asyncIterator]() { return this; },
    async next() { pulls++; return {done: false, value: Buffer.alloc(65536)}; },
    async return() { returned++; return {done: true}; }};
  const response = await client.request(url, {...options, body, expectContinueMs: 4000});
  assert.equal(response.status, 417); await response.bytes(0); await client.close();
  assert.equal(originBytes, 0); assert.ok(pulls <= 1); assert.equal(returned, 1);
});

test('zero wait sends normally and invalid fields fail before shared attempt admission', {timeout: 30000}, async (t) => {
  let accepted = 0;
  const server = http.createServer();
  server.on('checkContinue', (request, response) => {
    accepted++; let data = ''; request.on('data', (bytes) => { data += bytes; });
    request.on('end', () => response.end(data));
  });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const response = await client.request(url, {...options, body: Buffer.from('zero'), expectContinueMs: 0n});
  assert.equal(await response.text(4), 'zero');
  const budget = new AttemptBudget(1);
  for (const [invalid, code] of [
    [{expectContinueMs: 1, headers: [field('Expect', 'private-invalid')]}, 'InvalidHeader'],
    [{expectContinueMs: 1, headers: [field('Expect', '100-continue'), field('expect', '100-continue')]}, 'InvalidHeader'],
    [{trailers: [field('x-invalid', 'private\r\nvalue')]}, 'Http1'],
    [{protocol: 'http2', trailers: [field('X-Upper', 'private')]}, 'Http2'],
  ]) {
    await assert.rejects(client.request(url, {...options, body: Buffer.from('data'), ...invalid, attemptBudget: budget}),
      (error) => error instanceof PhantomError && error.code === code && !String(error).includes('private'));
    assert.equal(budget.remaining, 1);
  }
  assert.equal(accepted, 1);
});
