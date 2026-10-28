'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const http = require('node:http');
const http2 = require('node:http2');
const path = require('node:path');
const { test } = require('node:test');
const { Worker } = require('node:worker_threads');

const { Client, Profile } = require('..');

const profile = process.platform === 'win32' ? 'chrome-156-windows'
  : process.platform === 'darwin' ? 'chrome-156-macos' : 'chrome-156-linux';

async function listen(t, server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => {
    server.closeAllConnections?.();
    return new Promise((resolve) => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

test('reconnecting SSE preserves ordered managed IDs and keeps admitted reconnects alive during graceful close', {timeout: 30000}, async (t) => {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request);
    if (requests.length === 3) {
      response.writeHead(204).end();
      return;
    }
    response.writeHead(200, {'content-type': 'text/event-stream'});
    if (requests.length === 1) {
      const bytes = Buffer.from(': comment\r\nid: saved\r\nretry: 0\r\nevent: update\r\ndata: café\r\ndata: two\r\n\r\n');
      const split = bytes.indexOf(Buffer.from('é')) + 1;
      response.write(bytes.subarray(0, split));
      response.end(bytes.subarray(split));
    } else {
      response.end('id:\ndata: second\n\n');
    }
  });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct', context: 'raw', headers: [
    {name: 'X-Default', value: Buffer.from('retained')},
  ]});
  t.after(() => client.destroy());
  const source = await client.eventSource(url + '/events', {
    protocol: 'http1', maximumReconnects: 2, initialRetryMs: 5000, minimumRetryMs: 1,
    headers: [
      {name: 'Accept', value: Buffer.from('text/event-stream')},
      {lastEventId: 'Last-Event-ID'}, {name: 'X-Tail', value: Buffer.from('last')},
    ],
  });
  assert.equal(source.status, 200);
  assert.equal(source.protocol, 'http1');
  assert.equal(source.url, url + '/events');
  assert.equal(source.headers.find((header) => header.name.toLowerCase() === 'content-type').value.toString(), 'text/event-stream');
  assert.deepEqual(await source.read(), {data: 'café\ntwo', event: 'update', id: 'saved'});
  assert.equal(source.lastEventId, 'saved');
  assert.equal(source.retryMs, 1n);
  await assert.rejects(client.close({timeoutMs: 0}), {code: 'Timeout'});
  assert.deepEqual(await source.read(), {data: 'second', event: 'message', id: ''});
  assert.equal(await source.read(), null);
  assert.equal(source.lastEventId, '');
  assert.equal(source.reconnects, 2);
  assert.equal(source.closed, true);
  assert.equal(requests.length, 3);
  assert.equal(requests[0].headers['last-event-id'], undefined);
  assert.equal(requests[1].headers['last-event-id'], 'saved');
  assert.equal(requests[2].headers['last-event-id'], undefined);
  const names = requests[1].rawHeaders.filter((_, index) => index % 2 === 0);
  assert(names.indexOf('X-Default') < names.indexOf('Accept'));
  assert(names.indexOf('Accept') < names.indexOf('Last-Event-ID'));
  assert(names.indexOf('Last-Event-ID') < names.indexOf('X-Tail'));
  await client.close();
});

test('SSE response validation, limits and reconnect exhaustion stay typed and terminal', {timeout: 30000}, async (t) => {
  const server = http.createServer((request, response) => {
    if (request.url === '/stop') return response.writeHead(204).end();
    if (request.url === '/status') return response.writeHead(403).end('denied');
    if (request.url === '/type') return response.writeHead(200, {'content-type': 'application/json'}).end('{}');
    if (request.url === '/encoding') return response.writeHead(200, {'content-type': 'text/event-stream', 'content-encoding': 'gzip'}).end();
    response.writeHead(200, {'content-type': 'text/event-stream'});
    if (request.url === '/utf8') return response.end(Buffer.from([100, 97, 116, 97, 58, 32, 255, 10, 10]));
    if (request.url === '/large') return response.end(('data: ' + 'x'.repeat(2048) + '\n').repeat(64) + '\n');
    response.end('data: value\n\n');
  });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct', context: 'raw'});
  t.after(() => client.destroy());
  for (const [pathname, kind] of [['/status', 'UnexpectedStatus'], ['/type', 'InvalidContentType'], ['/encoding', 'UnsupportedContentEncoding']]) {
    await assert.rejects(client.eventSource(url + pathname, {protocol: 'http1'}), {code: 'Sse', kind});
  }
  const stopped = await client.eventSource(url + '/stop', {protocol: 'http1'});
  assert.equal(stopped.status, 204);
  assert.equal(stopped.closed, true);
  assert.equal(await stopped.read(), null);

  for (const [limits, kind] of [[{maximumLineBytes: 4}, 'LineTooLong'], [{maximumEventBytes: 4}, 'EventTooLarge']]) {
    const source = await client.eventSource(url + '/limited', {protocol: 'http1', limits});
    await assert.rejects(source.read(), {code: 'Sse', kind});
    assert.equal(await source.read(), null);
  }
  const utf8 = await client.eventSource(url + '/utf8', {protocol: 'http1', maximumReconnects: 0});
  assert.equal((await utf8.read()).data, '\uFFFD');
  await assert.rejects(utf8.read(), {code: 'Sse', kind: 'ReconnectLimit'});
  assert.equal(await utf8.read(), null);
  const large = await client.eventSource(url + '/large', {protocol: 'http1'});
  assert.equal((await large.read()).data, Array(64).fill('x'.repeat(2048)).join('\n'));
  large.close();
});

test('SSE inherits the selected client template through forks and restoration', {timeout: 30000}, async (t) => {
  const observed = [];
  const server = http.createServer((request, response) => {
    observed.push(request.headers);
    response.writeHead(200, {'content-type': 'text/event-stream'}).end('data: one\n\n');
  });
  const url = await listen(t, server);
  const client = new Client({profile: Profile.fromCatalog(profile, 'navigation'), route: 'direct'});
  const key = Buffer.alloc(32, 9);
  const restored = await client.restoreSession(await client.exportSession(key), key);
  const fork = client.fork();
  t.after(async () => {for (const owner of [client, restored, fork]) await owner.destroy();});
  for (const owner of [client, restored, fork]) {
    const source = await owner.eventSource(url + '/events', {protocol: 'http1'});
    assert.equal((await source.read()).data, 'one');
    source.close();
    assert.equal(observed.at(-1)['sec-fetch-dest'], 'document');
    assert.equal(observed.at(-1).accept, 'text/event-stream');
    assert.equal(observed.at(-1)['cache-control'], 'no-cache');
  }
});

test('cancelling a pending HTTP/2 event read preserves sibling streams and connection reuse', {timeout: 30000}, async (t) => {
  const sessions = new Set();
  let cancelled;
  const streamCancelled = new Promise((resolve) => {cancelled = resolve;});
  const server = http2.createServer();
  server.on('session', (session) => {sessions.add(session); session.on('error', () => {});});
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {});
    if (headers[':path'] === '/events') {
      stream.respond({':status': 200, 'content-type': 'text/event-stream'});
      stream.write('data: first\n\n');
      stream.once('close', cancelled);
    } else {
      stream.respond({':status': 200});
      stream.end('ok');
    }
  });
  t.after(() => {for (const session of sessions) session.destroy();});
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct', context: 'raw', protocol: 'http2'});
  t.after(() => client.destroy());
  const controller = new AbortController();
  const source = await client.eventSource(url + '/events', {protocol: 'http2', signal: controller.signal});
  assert.equal((await source.read()).data, 'first');
  const pending = source.read();
  assert.equal(await (await client.get(url + '/sibling')).text(2), 'ok');
  controller.abort();
  await assert.rejects(pending, {code: 'Cancelled'});
  await streamCancelled;
  assert.equal(await (await client.get(url + '/reused')).text(2), 'ok');
  assert.equal(sessions.size, 1);
});

test('close interrupts reconnect backoff and client destroy interrupts an opening', {timeout: 30000}, async (t) => {
  let requested;
  const openingReceived = new Promise((resolve) => {requested = resolve;});
  const server = http.createServer((request, response) => {
    if (request.url === '/opening') {requested(); return;}
    response.writeHead(200, {'content-type': 'text/event-stream'}).end('data: one\n\n');
  });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct', context: 'raw'});
  t.after(() => client.destroy());
  const source = await client.eventSource(url + '/backoff', {protocol: 'http1', initialRetryMs: 60000});
  assert.equal((await source.read()).data, 'one');
  const pending = source.read();
  source.close();
  await assert.rejects(pending, {code: 'Cancelled'});
  assert.equal(await source.read(), null);
  const opening = client.eventSource(url + '/opening', {protocol: 'http1'});
  const rejected = assert.rejects(opening, {code: 'Cancelled'});
  await openingReceived;
  await client.destroy();
  await rejected;
});

test('worker teardown releases an idle reconnecting SSE response', {timeout: 30000}, async (t) => {
  let disconnected;
  const closed = new Promise((resolve) => {disconnected = resolve;});
  const server = http.createServer((request, response) => {
    response.writeHead(200, {'content-type': 'text/event-stream'});
    response.flushHeaders();
    response.once('close', disconnected);
  });
  const url = await listen(t, server);
  const worker = new Worker(`const {parentPort, workerData} = require('node:worker_threads');
    const {Client} = require(workerData.module);
    (async () => {const client = new Client({profile: workerData.profile, route: 'direct', context: 'raw'});
      global.source = await client.eventSource(workerData.url, {protocol: 'http1'}); parentPort.postMessage('open');})();`,
  {eval: true, workerData: {module: path.resolve(__dirname, '..'), profile, url}});
  t.after(() => worker.terminate());
  assert.deepEqual(await once(worker, 'message'), ['open']);
  await worker.terminate();
  await closed;
});
