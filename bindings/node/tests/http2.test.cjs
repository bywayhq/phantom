'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const http2 = require('node:http2');
const path = require('node:path');
const os = require('node:os');
const { test } = require('node:test');
const { Client, PhantomError } = require('..');

const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const profile = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';

for (const method of ['read', 'text', 'json']) {
test(`cancelling an HTTP/2 ${method} preserves another live stream on the same session`, { timeout: 30000 }, async (t) => {
  const sessions = new Set();
  const server = http2.createSecureServer({ key: fixture('key.pem'), cert: fixture('certificate.pem') });
  server.on('session', (session) => { sessions.add(session); session.on('error', () => {}); });
  const observed = new Map();
  let complete;
  let cancelled;
  const streamClosed = new Promise((resolve) => { cancelled = resolve; });
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {});
    observed.set(headers[':path'], stream.session);
    stream.respond({ ':status': 200, 'x-observed': 'h2' });
    if (headers[':path'] === '/cancel') stream.on('close', () => cancelled(stream.rstCode));
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
  const reading = cancelledResponse[method](1024);
  controller.abort();
  await assert.rejects(reading, (error) => error instanceof PhantomError && error.code === 'Cancelled');
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
