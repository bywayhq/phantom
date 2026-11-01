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

function hookGate() {
  let resolve;
  const promise = new Promise(yes => { resolve = yes; });
  return {promise, resolve};
}

function hookAbort(signal) {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), {once: true}));
}

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


test('source hooks run client first on every GET with fresh managed IDs and inherited defaults', {timeout: 30000}, async t => {
  const records = [], calls = [];
  const url = await listen(t, http.createServer((request, response) => {
    records.push(request.rawHeaders);
    response.writeHead(200, {'content-type': 'text/event-stream'});
    response.end('id: saved\ndata: ready\n\n');
  }));
  const client = new Client({profile, route: 'direct', context: 'raw', headerHooks: [context => {
    calls.push('client'); context.append({name: 'x-client', value: Buffer.from('first')});
  }]});
  t.after(() => client.destroy());
  const key = Buffer.alloc(32, 7);
  const fork = client.fork(), restored = await client.restoreSession(await client.exportSession(key), key);
  t.after(() => fork.destroy()); t.after(() => restored.destroy());
  const ids = [];
  for (const owner of [client, fork, restored]) {
    const source = await owner.eventSource(url, {protocol: 'http1', initialRetryMs: 0, maximumReconnects: 1, headerHooks: [context => {
      calls.push('source');
      assert.equal(context.headers.at(-1).name, 'x-client');
      ids.push(context.headers.find(field => field.name.toLowerCase() === 'last-event-id')?.value.toString());
      context.append({name: 'x-source', value: Buffer.from('second')});
    }]});
    assert.equal((await source.read()).data, 'ready');
    assert.equal((await source.read()).data, 'ready');
    await source.closeAsync();
  }
  assert.deepEqual(calls, Array(6).fill(['client', 'source']).flat());
  assert.deepEqual(ids, [undefined, 'saved', undefined, 'saved', undefined, 'saved']);
  assert.equal(records.length, 6);
  for (const fields of records) assert(fields.indexOf('x-client') < fields.indexOf('x-source'));
  let called = false;
  const source = await client.eventSource(url, {protocol: 'http1', skipClientHeaderHooks: true, headerHooks: [() => { called = true; }]});
  assert(called); assert.equal(calls.length, 12); await source.closeAsync();
});

test('source callback errors and protected managed ID edits fail before any wire send', {timeout: 30000}, async t => {
  let sent = 0;
  const url = await listen(t, http.createServer((_request, response) => { sent++; response.end(); }));
  const client = new Client({profile, route: 'direct', context: 'raw'});
  t.after(() => client.destroy());
  for (const original of [new Error('host secret'), undefined, null]) {
    await assert.rejects(client.eventSource(url, {protocol: 'http1', maximumReconnects: 3, initialRetryMs: 0,
      headerHooks: [() => { throw original; }]}), error => {
      assert.equal(error.code, 'Sse'); assert.equal(error.kind, 'Request');
      assert.equal(error.cause.code, 'HeaderHook'); assert(Object.hasOwn(error.cause, 'cause'));
      assert.equal(error.cause.cause, original); return true;
    });
  }
  for (const operation of ['append', 'set', 'remove']) {
    await assert.rejects(client.eventSource(url, {protocol: 'http1', headerHooks: [context => {
      if (operation === 'remove') context.remove('Last-Event-ID');
      else context[operation]({name: 'last-event-id', value: Buffer.from('forged')});
    }]}), error => error.code === 'Sse' && error.cause.code === 'HeaderHook');
  }
  assert.equal(sent, 0);
});

test('a timed-out initial source callback cleans up before the next GET succeeds', {timeout: 30000}, async t => {
  let sent = 0, calls = 0, cleaned = false;
  const url = await listen(t, http.createServer((_request, response) => {
    sent++; response.writeHead(200, {'content-type': 'text/event-stream'}).end('data: recovered\n\n');
  }));
  const client = new Client({profile, route: 'direct', context: 'raw'});
  t.after(() => client.destroy());
  const source = await client.eventSource(url, {protocol: 'http1', timeouts: {totalMs: 500}, initialRetryMs: 0, maximumReconnects: 1,
    headerHooks: [async context => {
      if (++calls === 1) { try { await hookAbort(context.signal); } finally { cleaned = true; } }
      else { assert(cleaned); context.append({name: 'x-ready', value: Buffer.from('yes')}); }
    }]});
  assert.equal((await source.read()).data, 'recovered');
  assert.equal(source.reconnects, 1); assert.equal(sent, 1); assert.equal(calls, 2);
  await source.closeAsync();
});

test('per-read cancellation retains a reconnect hook and real HTTP2 sibling body', {timeout: 30000}, async t => {
  const sessions = new Set(), records = [];
  let sibling;
  const server = http2.createServer();
  server.on('session', session => { sessions.add(session); session.on('error', () => {}); session.on('close', () => sessions.delete(session)); });
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {});
    records.push(headers[':path']);
    if (headers[':path'] === '/sibling') { sibling = stream; stream.respond({':status': 200}); stream.write('first'); }
    else if (headers[':path'] === '/release') { sibling.end('tail'); stream.respond({':status': 200}); stream.end('ok'); }
    else { stream.respond({':status': 200, 'content-type': 'text/event-stream'}); stream.end('data: ready\n\n'); }
  });
  t.after(() => { for (const session of sessions) session.destroy(); });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct', protocol: 'http2', context: 'raw'});
  t.after(() => client.destroy());
  const response = await client.get(url + '/sibling');
  assert.equal((await response.read(5)).toString(), 'first');
  const entered = hookGate(), release = hookGate(); let calls = 0, finished = false;
  const source = await client.eventSource(url + '/events', {protocol: 'http2', initialRetryMs: 0, maximumReconnects: 1,
    headerHooks: [async () => { if (++calls === 2) { entered.resolve(); await release.promise; finished = true; } }]});
  t.after(() => { release.resolve(); source.close(); response.close(); });
  assert.equal((await source.read()).data, 'ready');
  const controller = new AbortController();
  const pending = source.read({signal: controller.signal});
  await entered.promise; controller.abort();
  await assert.rejects(pending, {code: 'Cancelled'});
  assert.equal(source.closed, false); assert.equal(finished, false);
  release.resolve();
  assert.equal((await source.read()).data, 'ready'); assert.equal(calls, 2); assert(finished);
  await source.closeAsync();
  const released = await client.get(url + '/release'); assert.equal(await released.text(2), 'ok');
  assert.equal((await response.read(4)).toString(), 'tail'); assert.equal(await response.read(1), null);
  assert.deepEqual(records, ['/sibling', '/events', '/events', '/release']);
});

test('source close and client shutdown retain actual callback cleanup and late undefined once', {timeout: 30000}, async t => {
  const url = await listen(t, http.createServer((_request, response) => {
    response.writeHead(200, {'content-type': 'text/event-stream'}).end('data: first\n\n');
  }));
  const entered = hookGate(), cleaning = hookGate(), release = hookGate();
  let calls = 0, exited = false, aborts = 0;
  const client = new Client({profile, route: 'direct', context: 'raw'});
  t.after(() => { release.resolve(); return client.destroy(); });
  const source = await client.eventSource(url, {protocol: 'http1', initialRetryMs: 0, headerHooks: [async context => {
    if (++calls === 2) {
      context.signal.addEventListener('abort', () => { aborts++; }); entered.resolve();
      try { await hookAbort(context.signal); }
      finally { cleaning.resolve(); await release.promise; exited = true; throw undefined; }
    }
  }]});
  assert.equal((await source.read()).data, 'first');
  const reading = source.read(); const observed = assert.rejects(reading, {code: 'Cancelled'});
  await entered.promise;
  const closing = source.closeAsync({timeoutMs: 20});
  await cleaning.promise; await assert.rejects(closing, {code: 'Timeout'});
  assert.equal(exited, false); assert.equal(aborts, 1);
  await assert.rejects(client.close({timeoutMs: 0}), {code: 'Timeout'});
  source.close(); release.resolve();
  await assert.rejects(source.closeAsync(), error => error.code === 'HeaderHookCleanup' && Object.hasOwn(error, 'cause') && error.cause === undefined);
  await observed; assert(exited); assert.equal(aborts, 1);
  await source.closeAsync(); await client.close();
});

test('source field allowance resets for a new managed ID without growing between callbacks', {timeout: 30000}, async t => {
  const records = [], counts = [];
  const url = await listen(t, http.createServer((request, response) => {
    records.push(request.headers); response.writeHead(200, {'content-type': 'text/event-stream'}).end('id: saved\ndata: ok\n\n');
  }));
  const client = new Client({profile, route: 'direct', context: 'raw'});
  t.after(() => client.destroy());
  const headers = [{name: 'accept', value: Buffer.from('text/event-stream')}, ...Array.from({length: 255}, (_, i) => ({name: `x-${i}`, value: Buffer.from('a')}))];
  const source = await client.eventSource(url, {protocol: 'http1', headers, initialRetryMs: 0, maximumReconnects: 1, headerHooks: [context => {
    counts.push(context.headers.length); context.remove('x-254'); context.append({name: 'x-254', value: Buffer.from('a')});
  }, context => { for (let i = 32; i < 255; i++) context.remove(`x-${i}`); }]});
  assert.equal((await source.read()).data, 'ok'); assert.equal((await source.read()).data, 'ok');
  assert.deepEqual(counts, [256, 257]); assert.equal(records.length, 2);
  assert.equal(records[1]['last-event-id'], 'saved');
  assert.equal(records[0]['x-31'], 'a'); assert.equal(records[0]['x-32'], undefined);
  await source.closeAsync();
  await assert.rejects(client.eventSource(url, {protocol: 'http1', headers, headerHooks: [context => {
    context.remove('x-254');
  }, context => {
    context.append({name: 'x-254', value: Buffer.from('a')}); context.append({name: 'x-overflow', value: Buffer.from('no')});
  }]}), error => error.code === 'Sse' && error.cause.code === 'HeaderHook');
  assert.equal(records.length, 2);
});


test('EventSource hooks run once across an HTTP2 redirect and leave the connection reusable', {timeout: 30000}, async t => {
  const sessions = new Set(), records = [], calls = [];
  const server = http2.createServer();
  server.on('session', session => { sessions.add(session); session.on('error', () => {}); });
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {}); records.push(headers);
    if (headers[':path'] === '/redirect') stream.respond({':status': 302, location: '/events'});
    else stream.respond({':status': 200, 'content-type': 'text/event-stream'});
    stream.end(headers[':path'] === '/redirect' ? '' : 'data: ready\n\n');
  });
  t.after(() => { for (const session of sessions) session.destroy(); });
  const url = await listen(t, server);
  const client = new Client({profile, route: 'direct', protocol: 'http2', context: 'raw', redirectPolicy: {mode: 'limited', maximumHops: 1}, headerHooks: [context => {
    calls.push('client'); context.append({name: 'x-client', value: Buffer.from('first')});
  }]});
  t.after(() => client.destroy());
  const source = await client.eventSource(url + '/redirect', {protocol: 'http2', headerHooks: [context => {
    calls.push('source'); context.append({name: 'x-source', value: Buffer.from('second')});
  }]});
  assert.equal((await source.read()).data, 'ready'); assert.equal(source.url, url + '/events');
  await source.closeAsync();
  const reused = await client.get(url + '/reuse', {skipClientHeaderHooks: true}); await reused.bytes(1024);
  assert.deepEqual(calls, ['client', 'source']);
  assert.deepEqual(records.map(h => h[':path']), ['/redirect', '/events', '/reuse']);
  for (const headers of records.slice(0, 2)) { assert.equal(headers['x-client'], 'first'); assert.equal(headers['x-source'], 'second'); }
  assert.equal(sessions.size, 1);
});
