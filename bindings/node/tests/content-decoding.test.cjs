'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const http = require('node:http');
const { test } = require('node:test');
const { gzipSync, brotliCompressSync, deflateSync } = require('node:zlib');
const { Client, PhantomError } = require('..');

const profile = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const advertised = (maximumDecodedBytes) => ({mode: 'advertised', maximumDecodedBytes});
const header = (name, value) => ({name, value: Buffer.from(value)});
const code = (expected) => (error) => error instanceof PhantomError && error.code === expected;

async function peer(t, handler) {
  const server = http.createServer(handler);
  const sockets = new Set();
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const client = new Client({profile, route: 'direct'});
  t.after(() => client.close());
  return {client, url: `http://127.0.0.1:${server.address().port}`};
}

test('advertised decoding preserves ordered wire fields and reports the selected chain', {timeout: 30000}, async (t) => {
  const payload = Buffer.from('a decoded response');
  const encoded = brotliCompressSync(gzipSync(payload));
  const observed = [];
  const {client, url} = await peer(t, (request, response) => {
    observed.push(request.rawHeaders);
    response.writeHead(200, {'content-encoding': 'gzip, br', 'content-length': encoded.length});
    response.end(encoded);
  });
  const headers = [header('x-first', 'one'), header('accept-encoding', 'gzip, br'), header('x-last', 'two')];
  const raw = await client.request(url, {...options, headers});
  assert.deepEqual(await raw.bytes(encoded.length), encoded);
  assert.deepEqual(raw.decodedContentCodings, []);
  const policy = advertised(payload.length);
  const pending = client.request(url, {...options, headers, contentDecoding: policy});
  policy.maximumDecodedBytes = 0;
  const decoded = await pending;
  assert.deepEqual(await decoded.bytes(payload.length), payload);
  assert.deepEqual(decoded.decodedContentCodings, ['gzip', 'br']);
  assert.equal(Object.isFrozen(decoded.decodedContentCodings), true);
  assert.throws(() => { decoded.decodedContentCodings = []; }, TypeError);
  assert.deepEqual(observed[1], observed[0], 'decoding cannot add or reorder request fields');
  assert.equal(decoded.headers.find((field) => field.name.toLowerCase() === 'content-length').value.toString(), String(encoded.length));
  assert.equal(decoded.headers.find((field) => field.name.toLowerCase() === 'content-encoding').value.toString(), 'gzip, br');
});

test('decoded stream bounds, explicit none and exact u64 choices retain body semantics', {timeout: 30000}, async (t) => {
  const {client, url} = await peer(t, (request, response) => {
    if (request.url === '/empty') { response.writeHead(204, {'content-encoding': 'unsupported'}); response.end(); return; }
    response.writeHead(200, {'content-encoding': 'deflate'});
    response.end(deflateSync(Buffer.from('abcd')));
  });
  const headers = [header('accept-encoding', 'deflate')];
  const response = await client.request(url, {...options, headers, contentDecoding: advertised(4n)});
  assert.equal((await response.read(1)).toString(), 'a');
  assert.equal(await response.text(3), 'bcd');
  assert.deepEqual(response.decodedContentCodings, ['deflate']);
  const short = await client.request(url, {...options, headers, contentDecoding: advertised(3)});
  await assert.rejects(short.bytes(4), code('ResponseBodyLimit'));
  const zero = await client.request(url, {...options, headers, contentDecoding: advertised(0)});
  await assert.rejects(zero.bytes(4), code('ResponseBodyLimit'));
  const empty = await client.request(url + '/empty', {...options, contentDecoding: advertised(0n)});
  assert.equal((await empty.bytes(0)).length, 0);
  assert.deepEqual(empty.decodedContentCodings, []);
  const huge = await client.request(url, {...options, headers, contentDecoding: advertised(18446744073709551615n)});
  assert.equal(await huge.text(4), 'abcd');
  const disabled = await client.request(url, {...options, headers, contentDecoding: {mode: 'none'}});
  assert.deepEqual(await disabled.bytes(100), deflateSync(Buffer.from('abcd')));
  assert.deepEqual(disabled.decodedContentCodings, []);
});

test('unadvertised and malformed codings fail on body read and invalid advertising sends nothing', {timeout: 30000}, async (t) => {
  let requests = 0;
  const {client, url} = await peer(t, (request, response) => {
    requests++;
    response.writeHead(200, {'content-encoding': 'gzip'});
    response.end(request.url === '/bad' ? Buffer.from('not a gzip stream') : gzipSync(Buffer.from('ok')));
  });
  const unadvertised = await client.request(url, {...options, contentDecoding: advertised(100)});
  await assert.rejects(unadvertised.bytes(100), code('ContentDecoding'));
  const malformed = await client.request(url + '/bad', {...options,
    headers: [header('accept-encoding', 'gzip')], contentDecoding: advertised(100)});
  await assert.rejects(malformed.bytes(100), code('ContentDecoding'));
  await assert.rejects(client.request(url, {...options,
    headers: [header('accept-encoding', 'gzip;q=invalid')], contentDecoding: advertised(100)}), code('InvalidHeader'));
  assert.equal(requests, 2);
});

test('decoding records reject ambiguous values without invoking getters or sending', {timeout: 30000}, async (t) => {
  let requests = 0;
  let getters = 0;
  const {client, url} = await peer(t, (_request, response) => { requests++; response.end(); });
  const accessor = {mode: 'advertised', get maximumDecodedBytes() { getters++; return 1; }};
  for (const contentDecoding of [null, {}, {mode: 'none', maximumDecodedBytes: 0},
    advertised(-1), advertised(true), advertised(1.5), advertised(Number.MAX_SAFE_INTEGER + 1),
    advertised(-1n), advertised(18446744073709551616n), {mode: 'advertised'},
    {...advertised(1), unknown: true}, accessor, new Proxy(advertised(1), {})]) {
    await assert.rejects(client.request(url, {...options, contentDecoding}), code('InvalidArgument'));
  }
  assert.equal(getters, 0);
  assert.equal(requests, 0);
});
