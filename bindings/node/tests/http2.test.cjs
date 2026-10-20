'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const http2 = require('node:http2');
const path = require('node:path');
const os = require('node:os');
const { test } = require('node:test');
const { Client, PhantomError } = require('..');
const { gzipSync } = require('node:zlib');

const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const profile = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';

test('decoded overflow and cancellation preserve a live HTTP/2 sibling and its session', {timeout: 30000}, async (t) => {
  const sessions = new Set();
  const observed = new Map();
  const finishes = new Map();
  const resets = new Map();
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem')});
  server.on('session', (session) => { sessions.add(session); session.on('error', () => {}); });
  server.on('stream', (stream, headers) => {
    const target = headers[':path'];
    stream.on('error', () => {});
    observed.set(target, stream.session);
    if (target.startsWith('/healthy')) {
      stream.respond({':status': 200});
      finishes.set(target, () => stream.end('healthy'));
    } else {
      resets.set(target, new Promise((resolve) => stream.once('close', () => resolve(stream.rstCode))));
      stream.respond({':status': 200, 'content-encoding': 'gzip'});
      const encoded = gzipSync(Buffer.alloc(65536, 0x61));
      stream.write(target === '/overflow' ? encoded : encoded.subarray(0, 10));
    }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const session of sessions) session.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')]});
  t.after(() => client.close());
  const url = `https://127.0.0.1:${server.address().port}`;
  const options = {method: 'GET', protocol: 'http2', context: 'raw', timeoutMs: 5000};
  for (const target of ['/overflow', '/cancel']) {
    const controller = new AbortController();
    const selected = await client.request(url + target, {...options, signal: controller.signal,
      headers: [{name: 'accept-encoding', value: Buffer.from('gzip')}],
      contentDecoding: {mode: 'advertised', maximumDecodedBytes: 8n}});
    const healthyPath = '/healthy' + target;
    const healthy = await client.request(url + healthyPath, options);
    assert.equal(observed.get(target), observed.get(healthyPath));
    const reading = selected.bytes(100);
    if (target === '/cancel') controller.abort();
    await assert.rejects(reading, (error) => error instanceof PhantomError
      && error.code === (target === '/cancel' ? 'Cancelled' : 'ResponseBodyLimit'));
    assert.equal(await resets.get(target), http2.constants.NGHTTP2_CANCEL);
    finishes.get(healthyPath)();
    assert.equal(await healthy.text(7), 'healthy');
  }
  assert.equal(sessions.size, 1);
});

for (const [method, overflow] of [['read', false], ['bytes', false], ['text', false], ['json', false], ['bytes', true]]) {
test(`${overflow ? 'overflowing' : 'cancelling'} an HTTP/2 ${method} preserves another live stream on the same session`, { timeout: 30000 }, async (t) => {
  const sessions = new Set();
  const server = http2.createSecureServer({ key: fixture('key.pem'), cert: fixture('certificate.pem') });
  server.on('session', (session) => { sessions.add(session); session.on('error', () => {}); });
  const observed = new Map();
  let complete;
  let cancelled;
  let sendOverflow;
  const streamClosed = new Promise((resolve) => { cancelled = resolve; });
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {});
    observed.set(headers[':path'], stream.session);
    stream.respond({ ':status': 200, 'x-observed': 'h2' });
    if (headers[':path'] === '/cancel') {
      stream.on('close', () => cancelled(stream.rstCode));
      sendOverflow = () => stream.write('overflow');
    }
    else complete = () => stream.end('healthy');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const session of sessions) session.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const client = new Client({ profile, route: 'direct', additionalRoots: [fixture('certificate.der')] });
  t.after(() => client.close());
  const url = `https://127.0.0.1:${server.address().port}`;
  const controller = new AbortController();
  const options = { method: 'GET', protocol: 'http2', context: 'raw', timeoutMs: 5000 };
  const cancelledResponse = await client.request(url + '/cancel', { ...options, signal: controller.signal });
  const healthy = await client.request(url + '/healthy', options);
  assert.equal(observed.get('/cancel'), observed.get('/healthy'));
  const reading = cancelledResponse[method](overflow ? 0 : 1024);
  if (overflow) sendOverflow();
  else controller.abort();
  await assert.rejects(reading, (error) => error instanceof PhantomError && error.code === (overflow ? 'ResponseBodyLimit' : 'Cancelled'));
  assert.equal(await streamClosed, http2.constants.NGHTTP2_CANCEL);
  complete();
  assert.equal((await healthy.bytes(7)).toString(), 'healthy');
  assert.equal(sessions.size, 1);
});
}

test('zero-window HTTP/2 file upload cancellation retains the reusable session', { timeout: 30000 }, async (t) => {
  const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'phantom-node-h2-'));
  t.after(() => fs.promises.rm(directory, {recursive: true, force: true}));
  const filename = path.join(directory, 'upload.bin');
  await fs.promises.writeFile(filename, Buffer.alloc(131072, 0x61));
  const sessions = new Set();
  const server = http2.createSecureServer({ key: fixture('key.pem'), cert: fixture('certificate.pem'), settings: {initialWindowSize: 0} });
  server.on('session', (session) => { sessions.add(session); session.on('error', () => {}); });
  let received = 0;
  let uploaded;
  let rejected;
  const headers = new Promise((resolve) => { uploaded = resolve; });
  const reset = new Promise((resolve) => { rejected = resolve; });
  server.on('stream', (stream, request) => {
    stream.on('error', () => {});
    if (request[':path'] === '/upload') {
      stream.on('data', (data) => { received += data.length; });
      stream.on('close', () => rejected(stream.rstCode));
      uploaded();
    } else { stream.respond({':status': 200}); stream.end('ok'); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const session of sessions) session.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')]});
  t.after(() => client.close());
  const url = `https://127.0.0.1:${server.address().port}`;
  const options = {method: 'GET', protocol: 'http2', context: 'raw', timeoutMs: 5000};
  assert.equal((await (await client.request(url + '/warm', options)).bytes(2)).toString(), 'ok');
  const controller = new AbortController();
  const pending = client.request(url + '/upload', {...options, method: 'POST', file: {path: filename, maximumBytes: 131072}, signal: controller.signal});
  await headers;
  assert.equal(received, 0, 'the peer grants no stream upload credit');
  controller.abort();
  await assert.rejects(pending, (error) => error instanceof PhantomError && error.code === 'Cancelled');
  assert.equal(await reset, http2.constants.NGHTTP2_CANCEL);
  assert.equal(received, 0);
  assert.equal((await (await client.request(url + '/healthy', options)).bytes(2)).toString(), 'ok');
  assert.equal(sessions.size, 1);
});
