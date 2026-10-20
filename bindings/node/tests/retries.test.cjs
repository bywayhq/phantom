'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');
const {setTimeout: wait} = require('node:timers/promises');
const {Client, AttemptBudget, PhantomError} = require('..');

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const statusRetry = (maximum = 1) => ({statuses: [503], maximum, delayMs: 0});
const code = (expected) => (error) => error instanceof PhantomError && error.code === expected;

async function peer(t, handler) {
  const observed = [];
  const sockets = new Set();
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      observed.push({url: request.url, method: request.method, body: Buffer.concat(chunks).toString(),
        connection: request.socket.remotePort});
      handler(request, response, observed);
    });
  });
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return {url: `http://127.0.0.1:${server.address().port}`, observed};
}

function client(t, retryPolicy) {
  const owner = new Client({profile, route: 'direct', retryPolicy});
  t.after(() => owner.close());
  return owner;
}

test('retry defaults, client snapshots, request replacement and shared caller caps use the core', {timeout: 30000}, async (t) => {
  const counts = new Map();
  const server = await peer(t, (request, response) => {
    const count = (counts.get(request.url) ?? 0) + 1; counts.set(request.url, count);
    response.writeHead(count <= 2 ? 503 : 200); response.end('ok');
  });
  const policy = {connectionFailures: {maximum: 2n, delayMs: 0.25, maximumDelayMs: 1, fullJitter: true},
    reusedConnectionReplay: true, unprocessedReplays: 2n, http2Fallback: false,
    statusRetry: {...statusRetry(2n), maximumDelayMs: 1, fullJitter: true, retryAfterLimitMs: 10}};
  const owner = client(t, policy);
  policy.statusRetry.statuses[0] = 421; policy.statusRetry.maximum = 0;
  for (const [target, override, expected, attempts] of [
    ['/inherit', undefined, 200, 3], ['/none', {}, 503, 1],
    ['/zero', {statusRetry: statusRetry(5), maximumRetries: 0n}, 503, 1],
    ['/cap', {statusRetry: statusRetry(5), maximumRetries: 1}, 503, 2],
  ]) {
    const response = await owner.request(server.url + target, {...options, retryPolicy: override});
    assert.equal(response.status, expected); assert.equal(await response.text(2), 'ok');
    assert.equal(counts.get(target), attempts);
    assert.equal(response.connectionRetries, 0, 'status retries are not setup retries');
  }
  const raw = await client(t).request(server.url + '/default', options);
  assert.equal(raw.status, 503); raw.close(); assert.equal(counts.get('/default'), 1);
  const fork = owner.fork();
  try {
    const response = await fork.request(server.url + '/fork', options);
    assert.equal(response.status, 200); assert.equal(await response.text(2), 'ok');
    assert.equal(counts.get('/fork'), 3);
  } finally { await fork.close(); }
});

test('status retries replay idempotent bytes while unsafe methods and one-shot files return their response', {timeout: 30000}, async (t) => {
  const server = await peer(t, (request, response, observed) => {
    const count = observed.filter((entry) => entry.url === request.url).length;
    response.writeHead(count === 1 ? 503 : 200); response.end('ok');
  });
  const owner = client(t, {statusRetry: statusRetry()});
  for (const method of ['PUT', 'POST']) {
    const response = await owner.request(server.url + '/' + method, {...options, method, body: Buffer.from('payload')});
    assert.equal(response.status, method === 'PUT' ? 200 : 503); assert.equal(await response.text(2), 'ok');
    const requests = server.observed.filter((entry) => entry.url === '/' + method);
    assert.equal(requests.length, method === 'PUT' ? 2 : 1);
    assert.equal(requests.every((entry) => entry.body === 'payload' && entry.method === method), true);
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-node-retry-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const filename = path.join(directory, 'body'); await fs.writeFile(filename, 'one-shot');
  const response = await owner.request(server.url + '/file', {...options, method: 'PUT', file: {path: filename, maximumBytes: 8}});
  assert.equal(response.status, 503); response.close();
  assert.equal(server.observed.filter((entry) => entry.url === '/file').length, 1);
});

test('Retry-After is opt-in and bounded without replacing the configured status schedule', {timeout: 30000}, async (t) => {
  const counts = new Map();
  const server = await peer(t, (request, response) => {
    const count = (counts.get(request.url) ?? 0) + 1; counts.set(request.url, count);
    response.writeHead(count === 1 ? 503 : 200, {'retry-after': request.url === '/zero' ? '0' : '1'}); response.end('ok');
  });
  const owner = client(t);
  for (const [target, retryAfterLimitMs, expected, attempts] of [
    ['/ignored', undefined, 200, 2], ['/refused', 0, 503, 1], ['/zero', 0, 200, 2],
  ]) {
    const response = await owner.request(server.url + target, {...options,
      retryPolicy: {statusRetry: {...statusRetry(), retryAfterLimitMs}}});
    assert.equal(response.status, expected); response.close(); assert.equal(counts.get(target), attempts);
  }
});

test('reused-connection replay is explicitly enabled and retains the original route', {timeout: 30000}, async (t) => {
  const server = await peer(t, (request, response, observed) => {
    if (request.url.startsWith('/reset') && observed.filter((entry) => entry.url === request.url).length === 1) request.socket.destroy();
    else response.end('ok');
  });
  for (const enabled of [false, true]) {
    const owner = client(t, {reusedConnectionReplay: enabled, maximumRetries: 1});
    const warm = await owner.request(server.url + '/warm', options); assert.equal(await warm.text(2), 'ok');
    const target = '/reset-' + enabled;
    if (!enabled) await assert.rejects(owner.request(server.url + target, options), (error) => error instanceof PhantomError);
    else assert.equal(await (await owner.request(server.url + target, options)).text(2), 'ok');
    const requests = server.observed.filter((entry) => entry.url === target);
    assert.equal(requests.length, enabled ? 2 : 1);
    assert.equal(requests[0].connection, server.observed.filter((entry) => entry.url === '/warm').at(-1).connection);
    if (enabled) assert.notEqual(requests[0].connection, requests[1].connection);
  }
});

test('shared attempt exhaustion, an insufficient deadline and cancellation prevent another retry send', {timeout: 30000}, async (t) => {
  let received;
  let first = new Promise((resolve) => { received = resolve; });
  const server = await peer(t, (_request, response) => { response.writeHead(503); response.end('ok'); received(); });
  const owner = client(t, {statusRetry: {...statusRetry(3), delayMs: 5000, maximumDelayMs: 8000}});
  await assert.rejects(owner.request(server.url + '/budget', {...options, attemptBudget: new AttemptBudget(1),
    retryPolicy: {statusRetry: statusRetry(3)}}), code('AttemptBudgetExhausted'));
  const response = await owner.request(server.url + '/deadline', {...options, timeoutMs: 1000});
  assert.equal(response.status, 503); response.close();
  first = new Promise((resolve) => { received = resolve; });
  const controller = new AbortController();
  const pending = owner.request(server.url + '/cancel', {...options, timeoutMs: undefined,
    timeouts: {totalMs: null}, signal: controller.signal});
  await first; await wait(50); controller.abort();
  await assert.rejects(pending, code('Cancelled'));
  assert.deepEqual(server.observed.map((entry) => entry.url), ['/budget', '/deadline', '/cancel']);
  const healthy = await owner.request(server.url + '/healthy', {...options, retryPolicy: {}});
  assert.equal(healthy.status, 503); healthy.close();
});

test('strict retry records, exact counts, statuses and delays fail before network work', {timeout: 30000}, async (t) => {
  const server = await peer(t, (_request, response) => response.end());
  const owner = client(t);
  let getters = 0;
  const statuses = [503]; Object.defineProperty(statuses, '0', {get() { getters++; return 503; }});
  const invalid = [null, [], {unknown: true}, {reusedConnectionReplay: 1}, {http2Fallback: 'yes'},
    {maximumRetries: -1}, {maximumRetries: 18446744073709551616n}, {unprocessedReplays: 0},
    {connectionFailures: {maximum: 1}}, {connectionFailures: {maximum: 0, delayMs: 0}},
    {connectionFailures: {maximum: 1, delayMs: true}}, {connectionFailures: {maximum: 1, delayMs: Infinity}},
    {connectionFailures: {maximum: 1, delayMs: -1}}, {connectionFailures: {maximum: 1, delayMs: 2, maximumDelayMs: 1}},
    {statusRetry: {...statusRetry(), statuses: []}}, {statusRetry: {...statusRetry(), statuses: [421]}},
    {statusRetry: {...statusRetry(), statuses}}, {statusRetry: {...statusRetry(), statuses: new Proxy([503], {})}},
    {statusRetry: {...statusRetry(), retryAfterLimitMs: NaN}}, new Proxy({}, {}),
    {get statusRetry() { getters++; return statusRetry(); }}];
  for (const retryPolicy of invalid) {
    await assert.rejects(owner.request(server.url, {...options, retryPolicy}), (error) => error instanceof PhantomError);
    assert.throws(() => new Client({profile, route: 'direct', retryPolicy}), (error) => error instanceof PhantomError);
  }
  assert.equal(server.observed.length, 0); assert.equal(getters, 0);
});
