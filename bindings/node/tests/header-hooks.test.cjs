'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const http = require('node:http');
const http2 = require('node:http2');
const {test} = require('node:test');

const {AttemptBudget, Client, PreparedBody, Profile} = require('..');

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

test('ordered hooks preserve the original prepared-field allowance without allowing growth', {timeout: 30000}, async (t) => {
  let sent = 0;
  const received = [];
  const sessions = new Set();
  const server = http2.createServer({maxHeaderListPairs: 512});
  server.on('session', (session) => {sessions.add(session); session.on('error', () => {});});
  server.on('stream', (stream, headers, _flags, rawHeaders) => {
    sent++;
    received.push(rawHeaders);
    assert.equal(headers['content-type'], 'application/x-www-form-urlencoded;charset=UTF-8');
    assert.equal(headers['content-length'], '3');
    assert.equal(headers['x-field-0'], 'restored');
    stream.on('data', () => {});
    stream.on('end', () => {stream.respond({':status': 200}); stream.end('ok');});
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const session of sessions) session.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  const owner = client(t, {profile: Profile.fromCatalog('chrome-156-windows'), context: 'fetchUpload', protocol: 'http2'});
  const body = await PreparedBody.form([['a', 'b']], {maximumBytes: 64});
  const headers = [field('origin', url), field('referer', url),
    ...Array.from({length: 254}, (_, index) => field(`x-field-${index}`, 'value'))];
  const response = await owner.post(url, {body, headers, headerHooks: [(context) => {
    assert.equal(context.headers.length, 258);
    context.remove('x-field-0');
    context.remove('x-field-1');
  }, (context) => {
    assert.equal(context.headers.length, 256);
    context.append(field('x-field-0', 'restored'));
    context.append(field('x-field-1', 'value'));
  }, (context) => {
    assert.equal(context.headers.length, 258);
    // Keep the protocol's independent 100-field wire limit after testing the hook allowance.
    for (let index = 32; index < 254; index++) context.remove(`x-field-${index}`);
  }]});
  assert.equal(await response.text(2), 'ok');
  const baseline = [field('origin', url), field('referer', url),
    ...Array.from({length: 30}, (_, index) => field(`x-field-${index + 2}`, 'value')),
    field('x-field-0', 'restored'), field('x-field-1', 'value')];
  assert.equal(await (await owner.post(url, {body, headers: baseline})).text(2), 'ok');
  assert.deepEqual(received[0], received[1]);
  const budget = new AttemptBudget(1);
  await assert.rejects(owner.post(url, {body, headers, attemptBudget: budget,
    headerHooks: [(context) => {context.append(field('x-extra', 'no'));}]}), {code: 'HeaderHook'});
  assert.equal(budget.remaining, 1);
  assert.equal(sent, 2);
});

test('logical hooks observe one final head across retries and redirects', {timeout: 30000}, async t => {
  const calls = []; let attempts = 0;
  const destination = await peer(t, (_request, response) => {response.setHeader('x-dupe', ['one', 'two']); response.end('body');});
  const origin = await peer(t, (_request, response) => {
    if (++attempts === 1) {response.writeHead(503); response.end();}
    else {response.writeHead(302, {location: destination + '/'}); response.end();}
  });
  const owner = client(t, {redirectPolicy: {mode: 'limited', maximumHops: 1},
    retryPolicy: {statusRetry: {statuses: [503], maximum: 1, delayMs: 0}, maximumRetries: 1}, requestHooks: {
      async onRequest(context) {await Promise.resolve(); calls.push('client request'); assert.equal(context.url, origin + '/');},
      onResponse(context) {calls.push('client response'); assert.equal(context.url, destination + '/'); assert.equal(context.redirects, 1);},
      onError() {assert.fail('successful logical request entered error phase');},
    }});
  const response = await owner.get(origin + '/', {requestHooks: {
    onRequest() {calls.push('request request');},
    onResponse(context) {
      calls.push('request response'); assert.equal(context.status, 200); assert(!('body' in context));
      assert.deepEqual(context.headers.filter(h => h.name === 'x-dupe').map(h => h.value.toString()), ['one', 'two']);
      const headers = context.headers; headers[0].value.fill(0); assert.notDeepEqual(context.headers[0].value, headers[0].value);
    },
  }});
  assert.equal(await response.text(16), 'body'); assert.equal(attempts, 2);
  assert.deepEqual(calls, ['client request', 'request request', 'client response', 'request response']);
});

test('request hook failure preserves primary and secondary thrown values without spending an attempt', {timeout: 30000}, async t => {
  let sent = 0, errors = 0; const original = new Error('request cause');
  const url = await peer(t, (_request, response) => {sent++; response.end();});
  const owner = client(t); const budget = new AttemptBudget(1);
  await assert.rejects(owner.get(url, {attemptBudget: budget, requestHooks: {
    onRequest() {throw original;},
    onError(context) {errors++; assert.equal(context.error.code, 'RequestHook'); assert.equal(context.error.cause, original); throw undefined;},
  }}), error => error.code === 'RequestHook' && error.cause === original && error.hookError.code === 'RequestHook'
    && Object.hasOwn(error.hookError, 'cause') && error.hookError.cause === undefined);
  assert.equal(errors, 1); assert.equal(sent, 0); assert.equal(budget.remaining, 1);
  await assert.rejects(owner.get(url, {requestHooks: {onRequest() {throw undefined;}}}), error =>
    error.code === 'RequestHook' && Object.hasOwn(error, 'cause') && error.cause === undefined && !Object.hasOwn(error, 'hookError'));
  assert.equal(sent, 0);
});

test('response hook failure drops its unread body without starting an error callback', {timeout: 30000}, async t => {
  let errors = 0; const original = new Error('response observer cause');
  const url = await peer(t, (_request, response) => {response.writeHead(200); response.write('unread');});
  const owner = client(t);
  await assert.rejects(owner.get(url, {requestHooks: {
    async onResponse(context) {assert.equal(context.status, 200); await Promise.resolve(); throw original;},
    onError() {errors++;},
  }}), error => error.code === 'RequestHook' && error.cause === original);
  assert.equal(errors, 0); await owner.close({timeoutMs: 3000});
});

test('error observer failure retains the original network category and both metadata and cause', {timeout: 30000}, async t => {
  const original = new Error('error observer cause'); let primary;
  const url = await peer(t, (request) => request.socket.destroy());
  const owner = client(t);
  await assert.rejects(owner.get(url, {requestHooks: {onError(context) {primary = context.error; throw original;}}}), error => {
    assert(primary); assert.equal(error.code, primary.code); assert.notEqual(error.code, 'RequestHook');
    assert.equal(error.protocol, primary.protocol); assert.equal(error.timeoutPhase, primary.timeoutPhase);
    assert.deepEqual(error.origin, primary.origin); assert.equal(error.hookError.code, 'RequestHook'); assert.equal(error.hookError.cause, original);
    return true;
  });
});

test('total deadline and cancellation retain actual logical callback cleanup without inventing terminal phases', {timeout: 30000}, async t => {
  let sent = 0, terminals = 0; const late = new Error('logical finalizer cause');
  const url = await peer(t, (_request, response) => {sent++; response.end();});
  const owner = client(t, {maximumActiveRequests: 1}); const entered = deferred(), aborted = deferred(), release = deferred();
  t.after(() => release.resolve()); const budget = new AttemptBudget(1);
  const send = owner.get(url, {attemptBudget: budget, timeouts: {totalMs: 300}, requestHooks: {async onRequest(context) {
    context.signal.addEventListener('abort', () => aborted.resolve(), {once: true}); entered.resolve();
    await aborted.promise; await release.promise; throw late;
  }}});
  await entered.promise; await assert.rejects(send, {code: 'Timeout', timeoutPhase: 'total'}); await aborted.promise;
  assert.equal(budget.remaining, 1); assert.equal(sent, 0);
  await assert.rejects(owner.get(url), {code: 'Capacity'});
  await assert.rejects(owner.close({timeoutMs: 30}), {code: 'Timeout'});
  release.resolve(); await assert.rejects(owner.close(), error => error.cause === late);
  await owner.close();
  const other = client(t); const controller = new AbortController(), waiting = deferred();
  const cancelled = other.get(url, {signal: controller.signal, requestHooks: {
    async onRequest(context) {waiting.resolve(); await new Promise(resolve => context.signal.addEventListener('abort', resolve, {once: true}));},
    onResponse() {terminals++;}, onError() {terminals++;},
  }});
  await waiting.promise; controller.abort(); await assert.rejects(cancelled, {code: 'Cancelled'}); await other.close(); assert.equal(terminals, 0);
});

test('custom lowercase methods stay header invocations beside logical callbacks', {timeout: 30000}, async t => {
  const server = http2.createServer(), sessions = new Set(), methods = [], calls = [];
  server.on('session', session => {sessions.add(session); session.on('error', () => {});});
  server.on('stream', (stream, headers) => {stream.on('error', () => {}); methods.push(headers[':method']); stream.respond({':status': 200}); stream.end('ok');});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const session of sessions) session.destroy(); await new Promise(resolve => server.close(resolve));});
  const owner = client(t, {protocol: 'http2'}), url = `http://127.0.0.1:${server.address().port}`;
  for (const method of ['request', 'response', 'error']) {
    const response = await owner.request(url, {method, headerHooks: [context => {assert.equal(context.method, method); context.append(field('x-tag', method)); calls.push('header');}],
      requestHooks: {onRequest() {calls.push('request');}, onResponse() {calls.push('response');}}});
    assert.equal(await response.text(2), 'ok');
  }
  assert.deepEqual(methods, ['request', 'response', 'error']); assert.deepEqual(calls, Array(3).fill(['request', 'header', 'response']).flat());
});

test('cancelled error observers retain both request and late observer failures for close', {timeout: 30000}, async t => {
  const original = new Error('request callback cause'), late = new Error('late error callback cause');
  let sent = 0;
  const url = await peer(t, (_request, response) => {sent++; response.end();});
  const owner = client(t), entered = deferred(), release = deferred(), controller = new AbortController();
  t.after(() => release.resolve());
  const budget = new AttemptBudget(1);
  const pending = owner.get(url, {signal: controller.signal, attemptBudget: budget, requestHooks: {
    onRequest() {throw original;},
    async onError(context) {
      assert.equal(context.error.cause, original); entered.resolve(); await release.promise; throw late;
    },
  }});
  await entered.promise; controller.abort(); await assert.rejects(pending, {code: 'Cancelled'});
  await assert.rejects(owner.close({timeoutMs: 30}), {code: 'Timeout'});
  release.resolve();
  await assert.rejects(owner.close(), error => error.cause === original && error.hookError?.cause === late);
  await owner.close(); assert.equal(sent, 0); assert.equal(budget.remaining, 1);
});

test('cancelled response observers preserve a live HTTP2 sibling body through EOS', {timeout: 30000}, async t => {
  const server = http2.createServer(), sessions = new Set(), tail = deferred(), entered = deferred(), release = deferred();
  t.after(() => {tail.resolve(); release.resolve();});
  server.on('session', session => {sessions.add(session); session.on('error', () => {});});
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {}); stream.respond({':status': 200});
    if (headers[':path'] === '/sibling') {stream.write('a'); tail.promise.then(() => stream.end('b'));}
    else stream.end('unused');
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const session of sessions) session.destroy(); await new Promise(resolve => server.close(resolve));});
  const owner = client(t, {protocol: 'http2'}), url = `http://127.0.0.1:${server.address().port}`;
  const sibling = await owner.get(url + '/sibling'); const body = sibling.text(2);
  const controller = new AbortController(); let terminals = 0;
  const pending = owner.get(url + '/hook', {signal: controller.signal, requestHooks: {
    async onResponse(context) {
      entered.resolve(); await new Promise(resolve => context.signal.addEventListener('abort', resolve, {once: true})); await release.promise;
    }, onError() {terminals++;},
  }});
  await entered.promise; controller.abort(); await assert.rejects(pending, {code: 'Cancelled'});
  tail.resolve(); assert.equal(await body, 'ab'); release.resolve();
  await owner.close(); assert.equal(terminals, 0); assert.equal(sessions.size, 1);
});
