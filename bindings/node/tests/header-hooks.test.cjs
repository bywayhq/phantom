'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const http = require('node:http');
const http2 = require('node:http2');
const {test} = require('node:test');

const {AttemptBudget, Client, PreparedBody} = require('..');

const profile = process.platform === 'win32' ? 'chrome-156-windows'
  : process.platform === 'darwin' ? 'chrome-156-macos' : 'chrome-156-linux';
const field = (name, value, sensitive) => ({name, value: Buffer.from(value), sensitive});
function deferred() {
  let resolve;
  const promise = new Promise((yes) => {resolve = yes;});
  return {promise, resolve};
}

async function peer(t, handler) {
  const server = http.createServer(handler);
  const sockets = new Set();
  server.on('connection', (socket) => {sockets.add(socket); socket.on('close', () => sockets.delete(socket));});
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function client(t, options = {}) {
  const owner = new Client({profile, route: 'direct', protocol: 'http1', context: 'raw', ...options});
  t.after(() => owner.close());
  return owner;
}

test('awaited hooks run once in order and registered credentials stay stripped on cross-origin redirects', {timeout: 30000}, async (t) => {
  const observed = [];
  const destination = await peer(t, (request, response) => {
    observed.push(request.headers); response.end('ok');
  });
  const origin = await peer(t, (request, response) => {
    observed.push(request.headers); response.writeHead(302, {location: destination}); response.end();
  });
  const calls = [];
  const owner = client(t, {redirectPolicy: {mode: 'limited', maximumHops: 1, credentialHeaders: ['x-secret']}, headerHooks: [async (context) => {
    calls.push('client');
    assert.equal(context.url, origin + '/');
    context.append(field('X-Secret', 'private', true));
    context.append(field('X-Dupe', 'old'));
  }]});
  const response = await owner.get(origin + '/', {headerHooks: [(context) => {
    calls.push('request');
    context.set(field('x-dupe', 'replacement'));
    context.append(field('X-After', 'last'));
  }]});
  assert.equal(await response.text(2), 'ok');
  assert.deepEqual(calls, ['client', 'request']);
  assert.equal(observed.length, 2);
  assert.equal(observed[0]['x-secret'], 'private');
  assert.equal(observed[1]['x-secret'], undefined);
  assert.equal(observed[1]['x-dupe'], 'replacement');
  assert.equal(observed[1]['x-after'], 'last');
});

test('hooks see prepared-body content type and retain their host cause without spending an attempt', {timeout: 30000}, async (t) => {
  let sent = 0;
  const url = await peer(t, (_request, response) => {sent++; response.end();});
  const owner = client(t);
  const original = new Error('host failure');
  const budget = new AttemptBudget(1);
  const body = await PreparedBody.form([['a', 'b']], {maximumBytes: 64});
  await assert.rejects(owner.post(url, {body, headers: [field('Content-Type', body.contentType)], attemptBudget: budget, headerHooks: [(context) => {
    assert.equal(context.method, 'POST');
    assert.equal(context.headers.find((header) => header.name.toLowerCase() === 'content-type').value.toString(), body.contentType);
    throw original;
  }]}), (error) => error === original);
  assert.equal(budget.remaining, 1);
  assert.equal(sent, 0);
});

test('total deadlines cancel a pending callback before admitting an HTTP attempt', {timeout: 30000}, async (t) => {
  let sent = 0;
  const url = await peer(t, (_request, response) => {sent++; response.end();});
  const owner = client(t);
  const entered = deferred(), aborted = deferred();
  const budget = new AttemptBudget(1);
  const send = owner.get(url, {timeouts: {totalMs: 300}, attemptBudget: budget, headerHooks: [async (context) => {
    context.signal.addEventListener('abort', () => aborted.resolve(), {once: true});
    entered.resolve();
    await aborted.promise;
    context.signal.throwIfAborted();
  }]});
  await entered.promise;
  await assert.rejects(send, {code: 'Timeout', timeoutPhase: 'total'});
  await aborted.promise;
  assert.equal(budget.remaining, 1);
  assert.equal(sent, 0);
});

test('cancelled callbacks keep shutdown custody until the host actually returns', {timeout: 30000}, async (t) => {
  let sent = 0;
  const url = await peer(t, (_request, response) => {sent++; response.end();});
  const owner = client(t, {maximumActiveRequests: 1});
  const entered = deferred(), release = deferred();
  const controller = new AbortController();
  const send = owner.get(url, {signal: controller.signal, headerHooks: [async () => {
    entered.resolve(); await release.promise;
  }]});
  await entered.promise;
  controller.abort();
  await assert.rejects(send, {code: 'Cancelled'});
  await assert.rejects(owner.close({timeoutMs: 50}), {code: 'Timeout'});
  assert.equal(sent, 0);
  release.resolve();
  await owner.close();
});

test('a pending hook does not block another stream on the existing HTTP/2 connection', {timeout: 30000}, async (t) => {
  const sessions = new Set();
  const streaming = deferred(), finishBody = deferred();
  const server = http2.createServer();
  server.on('session', (session) => {sessions.add(session); session.on('error', () => {});});
  server.on('stream', (stream, headers) => {
    if (headers[':path'] === '/stream') {
      stream.respond({':status': 200}); stream.write('a'); streaming.resolve();
      finishBody.promise.then(() => stream.end('b'));
    } else {stream.respond({':status': 200}); stream.end('ok');}
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const session of sessions) session.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const owner = client(t, {protocol: 'http2'});
  const url = `http://127.0.0.1:${server.address().port}`;
  const response = await owner.get(url + '/stream');
  await streaming.promise;
  const entered = deferred(), release = deferred();
  const pending = owner.get(url + '/hook', {headerHooks: [async () => {entered.resolve(); await release.promise;}]});
  await entered.promise;
  finishBody.resolve();
  assert.equal(await response.text(2), 'ab');
  release.resolve();
  assert.equal(await (await pending).text(2), 'ok');
  assert.equal(sessions.size, 1);
});
