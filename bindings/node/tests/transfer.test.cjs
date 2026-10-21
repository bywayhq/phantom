'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
const http = require('node:http');
const {test} = require('node:test');
const {gzipSync} = require('node:zlib');
const {Client, PhantomError, TransferControl} = require('..');
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const code = (expected) => (error) => error instanceof PhantomError && error.code === expected;
async function peer(t, handler) {
  const server = http.createServer(handler), sockets = new Set();
  server.on('connection', (socket) => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  return {client, url: `http://127.0.0.1:${server.address().port}`};
}

test('shared caps apply across clients without changing uncontrolled requests', {timeout: 30000}, async (t) => {
  const {client, url} = await peer(t, (_request, response) => response.end('body'));
  const other = new Client({profile, route: 'direct'}); t.after(() => other.close());
  const control = new TransferControl({downloadBytes: 4n});
  const outcomes = await Promise.allSettled([client, other].map(async (owner) => {
    const response = await owner.request(url, {...options, transferControl: control});
    return response.text(4);
  }));
  assert.equal(outcomes.filter((result) => result.status === 'fulfilled' && result.value === 'body').length, 1);
  const failed = outcomes.find((result) => result.status === 'rejected'); assert.ok(failed); assert.ok(code('Transfer')(failed.reason));
  assert.deepEqual(control.snapshot(), {uploadReservedBytes: 0n, uploadBodyBytes: 0n,
    downloadReservedBytes: 4n, downloadEncodedBytes: 4n, downloadDecodedBytes: 4n});
  const zero = new TransferControl({downloadBytes: 0});
  await assert.rejects((await client.request(url, {...options, transferControl: zero})).bytes(4), code('Transfer'));
  assert.equal(zero.snapshot().downloadReservedBytes, 0n);
  assert.equal(await (await client.request(url, options)).text(4), 'body');
});

test('gzip counters separate encoded body from decoded frames and collection cursor', {timeout: 30000}, async (t) => {
  const payload = Buffer.alloc(1000, 0x61), encoded = gzipSync(payload);
  const {client, url} = await peer(t, (_request, response) => {
    response.writeHead(200, {'content-encoding': 'gzip', 'content-length': encoded.length}); response.end(encoded);
  });
  const control = new TransferControl({downloadBytes: encoded.length});
  const response = await client.request(url, {...options, transferControl: control,
    headers: [{name: 'accept-encoding', value: Buffer.from('gzip')}], contentDecoding: {mode: 'advertised', maximumDecodedBytes: 1000}});
  assert.equal((await response.read(1)).toString(), 'a');
  assert.deepEqual(await response.bytes(999), payload.subarray(1));
  const counts = control.snapshot();
  assert.equal(counts.downloadReservedBytes, BigInt(encoded.length));
  assert.equal(counts.downloadEncodedBytes, BigInt(encoded.length)); assert.equal(counts.downloadDecodedBytes, 1000n);
});

test('upload caps count a preserved redirect body again and zero denies nonempty data', {timeout: 30000}, async (t) => {
  const received = [];
  const {client, url} = await peer(t, (request, response) => {
    const chunks = []; request.on('error', () => {});
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      received.push({url: request.url, body: Buffer.concat(chunks).toString()});
      if (request.url === '/first') { response.writeHead(307, {location: '/last'}); response.end(); }
      else response.end('ok');
    });
  });
  const control = new TransferControl({uploadBytes: 8n});
  const request = {...options, method: 'POST', body: Buffer.from('data'), redirectPolicy: {mode: 'limited', maximumHops: 1}};
  assert.equal(await (await client.request(url + '/first', {...request, transferControl: control})).text(2), 'ok');
  assert.deepEqual(received, [{url: '/first', body: 'data'}, {url: '/last', body: 'data'}]);
  assert.equal(control.snapshot().uploadReservedBytes, 8n); assert.equal(control.snapshot().uploadBodyBytes, 8n);
  const zero = new TransferControl({uploadBytes: 0});
  await assert.rejects(client.request(url + '/zero', {...request, transferControl: zero}), code('Transfer'));
  assert.equal(zero.snapshot().uploadBodyBytes, 0n);
  const capped = new TransferControl({uploadBytes: 4});
  await assert.rejects(client.request(url + '/first', {...request, transferControl: capped}), code('Transfer'));
  assert.equal(capped.snapshot().uploadBodyBytes, 4n);
  assert.equal(received.filter((entry) => entry.url === '/last').length, 1);
});
