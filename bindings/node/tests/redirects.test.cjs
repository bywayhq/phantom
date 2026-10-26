'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { inspect } = require('node:util');
const { gzipSync } = require('node:zlib');
const { Client, AttemptBudget, PhantomError } = require('..');

const profile = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const limited = (maximumHops) => ({mode: 'limited', maximumHops});
const code = (expected) => (error) => error instanceof PhantomError && error.code === expected;
const field = (name, value) => ({name, value: Buffer.from(value)});

async function peer(t, handler) {
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => handler(request, response, Buffer.concat(chunks)));
  });
  const sockets = new Set();
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function client(t, configuration = {}) {
  const owner = new Client({profile, route: 'direct', ...configuration});
  t.after(() => owner.close());
  return owner;
}

test('redirects inherit client policy, replace it per request and retain only requested history', {timeout: 30000}, async (t) => {
  const url = await peer(t, (request, response) => {
    if (request.url === '/a') response.writeHead(302, {location: 'b'});
    else if (request.url === '/b') response.writeHead(307, {location: '/end'});
    response.end('ok');
  });
  const raw = client(t);
  const stopped = await raw.request(url + '/a', options);
  assert.equal(stopped.status, 302); assert.equal(stopped.redirectHistory, null); stopped.close();
  const empty = await raw.request(url + '/a', {...options, redirectHistoryLimit: 1});
  assert.deepEqual(empty.redirectHistory, {entries: [], omittedHops: 0}); empty.close();
  const policy = limited(2);
  const owner = client(t, {redirectPolicy: policy});
  policy.maximumHops = 0;
  const response = await owner.request(url + '/a', {...options, redirectHistoryLimit: 1n});
  assert.equal(await response.text(2), 'ok');
  assert.equal(response.url, url + '/end'); assert.equal(response.redirects, 2);
  assert.deepEqual(response.redirectHistory, {entries: [{fromUrl: url + '/a', toUrl: url + '/b',
    method: 'GET', nextMethod: 'GET', status: 302}], omittedHops: 1});
  assert.equal(Object.isFrozen(response.redirectHistory), true);
  assert.equal(Object.isFrozen(response.redirectHistory.entries), true);
  assert.equal(Object.isFrozen(response.redirectHistory.entries[0]), true);
  assert.equal(inspect(response.redirectHistory).includes(url), false);
  assert.equal(inspect(response.redirectHistory.entries[0]).includes(url), false);
  assert.equal(JSON.parse(JSON.stringify(response.redirectHistory)).entries[0].fromUrl, url + '/a');
  assert.throws(() => { response.redirectHistory = null; }, TypeError);
  const disabled = await owner.request(url + '/a', {...options, redirectPolicy: {mode: 'none'}});
  assert.equal(disabled.status, 302); disabled.close();
  await assert.rejects(owner.request(url + '/a', {...options, redirectPolicy: limited(1)}), code('Redirect'));
  const inherited = await owner.request(url + '/a', {...options, redirectPolicy: limited(2n)});
  assert.equal(inherited.redirects, 2); assert.equal(inherited.redirectHistory, null); inherited.close();
  const worker = owner.fork();
  try {
    const forked = await worker.request(url + '/a', options);
    assert.equal(forked.redirects, 2); forked.close();
  } finally { await worker.close(); }
});

test('the core owns redirect method and replayable body changes', {timeout: 30000}, async (t) => {
  const observed = [];
  const url = await peer(t, (request, response, body) => {
    observed.push({target: request.url, method: request.method, body: body.toString()});
    if (request.url.startsWith('/status/')) response.writeHead(Number(request.url.slice(8)), {location: '/final'});
    response.end('ok');
  });
  const owner = client(t, {redirectPolicy: limited(1)});
  for (const status of [301, 302, 303, 307, 308]) {
    const response = await owner.request(url + '/status/' + status, {...options, method: 'POST',
      body: Buffer.from('payload'), redirectHistoryLimit: 1});
    assert.equal(await response.text(2), 'ok');
    const nextMethod = status < 307 ? 'GET' : 'POST';
    assert.deepEqual(observed.splice(0), [
      {target: '/status/' + status, method: 'POST', body: 'payload'},
      {target: '/final', method: nextMethod, body: status < 307 ? '' : 'payload'},
    ]);
    assert.equal(response.redirectHistory.entries[0].nextMethod, nextMethod);
  }
});

test('cross-origin credentials stay stripped even after returning to the original origin', {timeout: 30000}, async (t) => {
  const observed = [];
  let first;
  const second = await peer(t, (request, response) => {
    observed.push({...request.headers});
    response.writeHead(302, {location: first + '/final'}); response.end();
  });
  first = await peer(t, (request, response) => {
    observed.push({...request.headers});
    if (request.url === '/start') response.writeHead(302, {location: second + '/middle'});
    response.end('ok');
  });
  const response = await client(t).request(first + '/start', {...options,
    redirectPolicy: {...limited(2), credentialHeaders: ['x-api-key']},
    headers: [field('authorization', 'Bearer private'), field('cookie', 'private=value'), field('X-Api-Key', 'custom-secret')]});
  assert.equal(await response.text(2), 'ok');
  assert.equal(observed[0].authorization, 'Bearer private'); assert.equal(observed[0].cookie, 'private=value');
  assert.equal(observed[0]['x-api-key'], 'custom-secret');
  for (const hop of observed.slice(1)) {
    assert.equal(hop.authorization, undefined); assert.equal(hop.cookie, undefined);
    assert.equal(hop['x-api-key'], undefined);
  }
  assert.equal(observed.length, 3);
});

test('invalid destinations and exhausted budgets cannot send another hop', {timeout: 30000}, async (t) => {
  const observed = [];
  const url = await peer(t, (request, response) => {
    observed.push(request.url);
    const location = request.url === '/multiple' ? ['/one', '/two']
      : request.url === '/scheme' ? 'ftp://private.invalid/path?secret'
      : request.url === '/invalid' ? 'http://[' : '/next';
    response.writeHead(302, request.url === '/missing' ? {} : {location}); response.end();
  });
  const owner = client(t, {redirectPolicy: limited(3)});
  for (const target of ['/multiple', '/scheme', '/invalid']) {
    await assert.rejects(owner.request(url + target, options), (error) => code('Redirect')(error)
      && !error.message.includes(url) && !error.message.includes('secret'));
  }
  assert.deepEqual(observed, ['/multiple', '/scheme', '/invalid']);
  const missing = await owner.request(url + '/missing', options);
  assert.equal(missing.status, 302); missing.close();
  const budget = new AttemptBudget(1);
  await assert.rejects(owner.request(url + '/budget', {...options, attemptBudget: budget}), code('AttemptBudgetExhausted'));
  assert.equal(budget.remaining, 0);
  assert.deepEqual(observed, ['/multiple', '/scheme', '/invalid', '/missing', '/budget']);
});

test('one-shot file redirects fail before replay and decoding applies only to the final response', {timeout: 30000}, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-node-redirect-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const filename = path.join(directory, 'upload'); await fs.writeFile(filename, 'one-shot');
  const observed = [];
  const url = await peer(t, (request, response) => {
    observed.push(request.url);
    if (request.url === '/file') { response.writeHead(307, {location: '/replay'}); response.end(); }
    else if (request.url === '/coded') {
      response.writeHead(302, {location: '/final', 'content-encoding': 'unsupported'}); response.end('ignored');
    } else { response.writeHead(200, {'content-encoding': 'gzip'}); response.end(gzipSync(Buffer.from('ok'))); }
  });
  const owner = client(t, {redirectPolicy: limited(1)});
  await assert.rejects(owner.request(url + '/file', {...options, method: 'POST',
    file: {path: filename, maximumBytes: 8}}), code('RequestBody'));
  assert.deepEqual(observed, ['/file']);
  const response = await owner.request(url + '/coded', {...options,
    headers: [field('accept-encoding', 'gzip')], contentDecoding: {mode: 'advertised', maximumDecodedBytes: 2}});
  assert.equal(await response.text(2), 'ok'); assert.deepEqual(response.decodedContentCodings, ['gzip']);
});

test('a total deadline and cancellation span redirect hops without resetting', {timeout: 30000}, async (t) => {
  let reached;
  const finalHead = new Promise((resolve) => { reached = resolve; });
  const timers = new Set();
  t.after(() => { for (const timer of timers) clearTimeout(timer); });
  const url = await peer(t, (request, response) => {
    if (request.url === '/warm') response.end('ok');
    else if (request.url === '/start') timers.add(setTimeout(() => {
      response.writeHead(302, {location: '/hold'}); response.end();
    }, 600));
    else { reached(); timers.add(setTimeout(() => response.end('late'), 600)); }
  });
  const owner = client(t, {redirectPolicy: limited(1)});
  assert.equal(await (await owner.request(url + '/warm', options)).text(2), 'ok');
  // Each hop can finish within one second, but both cannot share that deadline.
  const pending = assert.rejects(owner.request(url + '/start', {...options, timeoutMs: 1000}),
    (error) => code('Timeout')(error) && error.timeoutPhase === 'total');
  await finalHead;
  await pending;
  const cancelledHead = new Promise((resolve) => { reached = resolve; });
  const controller = new AbortController();
  const cancelled = owner.request(url + '/start', {...options, signal: controller.signal});
  await cancelledHead;
  controller.abort();
  await assert.rejects(cancelled, code('Cancelled'));
});

test('strict redirect records and history counts reject input before sending', {timeout: 30000}, async (t) => {
  let received = 0;
  let getters = 0;
  const url = await peer(t, (_request, response) => { received++; response.end(); });
  const owner = client(t);
  const accessor = {mode: 'limited', get maximumHops() { getters++; return 1; }};
  for (const redirectPolicy of [null, {}, {mode: 'none', maximumHops: 0}, limited(0), limited(-1),
    limited(1.5), limited(0n), limited(18446744073709551616n), limited(Number.MAX_SAFE_INTEGER + 1), {...limited(1), unknown: true},
    accessor, new Proxy(limited(1), {})]) {
    await assert.rejects(owner.request(url, {...options, redirectPolicy}), code('InvalidArgument'));
    assert.throws(() => new Client({profile, route: 'direct', redirectPolicy}), code('InvalidArgument'));
  }
  for (const redirectHistoryLimit of [0, -1, null, true, 0n, 18446744073709551616n, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(owner.request(url, {...options, redirectHistoryLimit}), code('InvalidArgument'));
  }
  assert.equal(received, 0); assert.equal(getters, 0);
});
