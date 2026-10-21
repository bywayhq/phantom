'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
const http = require('node:http');
const {test} = require('node:test');
const {inspect} = require('node:util');
const {Client, PreparedBody, AttemptBudget, PhantomError} = require('..');

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'POST', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const field = (name, value) => ({name, value: Buffer.from(value)});

async function peer(t) {
  const requests = [], sockets = new Set();
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      requests.push({method: request.method, head: request.rawHeaders, body: Buffer.concat(chunks)});
      if (request.url === '/redirect') response.writeHead(307, {location: '/final'}).end();
      else response.end('ok');
    });
  });
  server.on('connection', (socket) => {sockets.add(socket); socket.on('close', () => sockets.delete(socket));});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve));});
  return {url: `http://127.0.0.1:${server.address().port}`, requests};
}

function headers(body) {return [field('X-Before', 'first'), field('Content-Type', body.contentType), field('X-After', 'last')];}

test('native form encoding preserves duplicate order and reuses bytes across requests and 307', {timeout: 30000}, async (t) => {
  const expected = Buffer.from('tag=first&tag=last&space=a+b&literal=%2B');
  const body = await PreparedBody.form([['tag', 'first'], ['tag', 'last'], ['space', 'a b'], ['literal', '+']], {maximumBytes: expected.length});
  assert.equal(body.contentType, 'application/x-www-form-urlencoded;charset=UTF-8');
  assert.equal(body.byteLength, BigInt(expected.length)); assert.ok(Object.isFrozen(body));
  const {url, requests} = await peer(t);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  for (const target of ['/', '/redirect']) {
    const response = await client.request(url + target, {...options, body, headers: headers(body), redirectPolicy: {mode: 'limited', maximumHops: 1}});
    assert.equal(await response.text(2), 'ok');
  }
  assert.equal(requests.length, 3);
  for (const request of requests) {
    assert.equal(request.method, 'POST'); assert.deepEqual(request.body, expected);
    assert.ok(request.head.indexOf('X-Before') < request.head.indexOf('Content-Type'));
    assert.ok(request.head.indexOf('Content-Type') < request.head.indexOf('X-After'));
  }
  await assert.rejects(PreparedBody.form([['tag', 'first'], ['tag', 'last'], ['space', 'a b'], ['literal', '+']],
    {maximumBytes: expected.length - 1}), {code: 'PreparedBody', kind: 'too_large'});
});

test('native multipart owns bytes before yielding and preserves exact framing and metadata', {timeout: 30000}, async (t) => {
  const original = Buffer.from([0, 255, 13, 10]);
  const expected = Buffer.concat([
    Buffer.from('--a:b\r\nContent-Disposition: form-data; name="item"\r\n\r\none\r\nline\r\n'
      + '--a:b\r\nContent-Disposition: form-data; name="item"; filename="a%22b.txt"\r\nContent-Type: application/custom\r\n\r\n'),
    original, Buffer.from('\r\n--a:b--\r\n'),
  ]);
  const pending = PreparedBody.multipart([{name: 'item', text: 'one\nline'},
    {name: 'item', bytes: original, filename: 'a"b.txt', contentType: 'application/custom'}], {boundary: 'a:b', maximumBytes: expected.length});
  original.fill(42);
  const body = await pending;
  assert.equal(body.contentType, 'multipart/form-data; boundary="a:b"'); assert.equal(body.byteLength, BigInt(expected.length));
  await assert.rejects(PreparedBody.multipart([{name: 'item', text: 'one\nline'},
    {name: 'item', bytes: Buffer.from([0, 255, 13, 10]), filename: 'a"b.txt', contentType: 'application/custom'}],
    {boundary: 'a:b', maximumBytes: expected.length - 1}), {code: 'PreparedBody', kind: 'too_large'});
  const {url, requests} = await peer(t);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  assert.equal(await (await client.request(url, {...options, body, headers: headers(body)})).text(2), 'ok');
  assert.deepEqual(requests[0].body, expected);
  assert.doesNotMatch(inspect(body, {showHidden: true}), /a:b|item|custom/);
});

test('preparation failures and Content-Type placement reject before HTTP attempt admission', {timeout: 30000}, async (t) => {
  for (const [parts, boundary, kind] of [
    [[{name: 'private\u0000', text: 'x'}], 'b', 'invalid_name'],
    [[{name: 'x', bytes: Buffer.from('private--b')}], 'b', 'boundary_collision'],
    [[{name: 'x', text: 'x', filename: 'private\u0000'}], 'b', 'invalid_filename'],
    [[{name: 'x', text: 'x', contentType: 'private;invalid'}], 'b', 'invalid_content_type'],
    [[], 'private boundary', 'invalid_boundary'],
  ]) {
    await assert.rejects(PreparedBody.multipart(parts, {boundary, maximumBytes: 1024}),
      (error) => error instanceof PhantomError && error.code === 'PreparedBody' && error.kind === kind && !String(error).includes('private'));
  }
  const body = await PreparedBody.form([], {maximumBytes: 0}); assert.equal(body.byteLength, 0n);
  const {url, requests} = await peer(t);
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  const budget = new AttemptBudget(1);
  for (const invalid of [[], [field('Content-Type', 'wrong/private')], [field('Content-Type', body.contentType), field('content-type', body.contentType)]]) {
    await assert.rejects(client.request(url, {...options, body, headers: invalid, attemptBudget: budget}), {code: 'InvalidHeader'});
    assert.equal(budget.remaining, 1);
  }
  assert.equal(requests.length, 0);
  assert.equal(await (await client.request(url, {...options, body, bodyLength: 0, headers: headers(body), attemptBudget: budget})).text(2), 'ok');
  assert.equal(budget.remaining, 0);
});
