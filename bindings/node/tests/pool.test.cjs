'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
const http = require('node:http');
const {setImmediate: tick} = require('node:timers/promises');
const {test} = require('node:test');
const {Client, RequestDiagnostics} = require('..');

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 10000};

async function peer(t, handler) {
  const sockets = new Set(), server = http.createServer(handler);
  server.on('connection', (socket) => {sockets.add(socket); socket.once('close', () => sockets.delete(socket));});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve));});
  return `http://127.0.0.1:${server.address().port}`;
}

async function read(client, url) {
  const response = await client.request(url, options);
  try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
}

test('pool retention evicts an origin while retaining same-origin reuse', {timeout: 30000}, async (t) => {
  const seen = [];
  const handler = (request, response) => {seen.push(request.socket); response.end('ok');};
  const first = await peer(t, handler), second = await peer(t, handler);
  const client = new Client({profile, route: 'direct', pool: {maxRetainedHttp1Connections: 1}});
  try {
    for (const url of [first, first, second, first]) await read(client, url);
    assert.equal(seen.length, 4); assert.equal(seen[0], seen[1]); assert.notEqual(seen[0], seen[3]);
    const fork = client.fork(); await client.close();
    try {
      const start = seen.length;
      for (const url of [first, first, second, first]) await read(fork, url);
      assert.equal(seen[start], seen[start + 1]); assert.notEqual(seen[start], seen[start + 3]);
    } finally {await fork.close();}
  } finally {await client.close();}
});

test('native pool admission caps active bodies and cancellation releases a waiting slot', {timeout: 30000}, async (t) => {
  let hits = 0;
  const url = await peer(t, (request, response) => {
    hits++;
    if (request.url === '/held') {
      response.writeHead(200, {'Content-Length': '2'}); response.write('a');
    } else response.end('ok');
  });
  const client = new Client({profile, route: 'direct', maximumActiveRequests: 8,
    pool: {maxConcurrentHttp1RequestsPerOrigin: 2, maxPendingHttp1RequestsPerOrigin: 1}});
  const held = [], controller = new AbortController();
  try {
    for (let index = 0; index < 2; index++) held.push(await client.request(url + '/held', {
      ...options, timeoutMs: undefined, timeouts: {connectMs: 10000, responseHeadMs: 10000, totalMs: null},
    }));
    await assert.rejects(client.request(url + '/blocked', {...options, timeouts: {poolAdmissionMs: 0}}),
      {code: 'Timeout', timeoutPhase: 'poolAdmission'});
    const diagnostics = new RequestDiagnostics();
    const queued = client.request(url + '/queued', {...options, diagnostics, signal: controller.signal});
    const rejected = assert.rejects(queued, {code: 'Cancelled'});
    const deadline = performance.now() + 10000;
    while (!diagnostics.snapshot()?.events.some((event) => event.phase === 'pool_admission' && event.outcome === 'pending')) {
      assert(performance.now() < deadline, 'waiting request never entered pool admission'); await tick();
    }
    // The phase starts before the waiting permit is claimed. Probe without
    // waiting until the occupied pending slot rejects another request.
    for (;;) {
      let failure;
      try {
        const unexpected = await client.request(url + '/overflow', {...options, timeouts: {poolAdmissionMs: 0}});
        unexpected.close(); assert.fail('overflow request reached the peer');
      } catch (error) {failure = error;}
      if (failure.code === 'Capacity') break;
      assert.equal(failure.code, 'Timeout'); assert.equal(failure.timeoutPhase, 'poolAdmission');
      assert(performance.now() < deadline, 'pending request bound was not enforced'); await tick();
    }
    controller.abort(); await rejected;
    assert.equal(hits, 2);
    for (const response of held) {assert.equal((await response.read(1)).toString(), 'a'); response.close();}
    await read(client, url + '/healthy'); assert.equal(hits, 3);
  } finally {
    controller.abort(); for (const response of held) response.close(); await client.close();
  }
});

test('core rejects unsupported H3 connection bounds without inventing an H2 cap', () => {
  assert.throws(() => new Client({profile, route: 'direct', pool: {maxHttp3ConnectionsPerOrigin: 9}}), {code: 'InvalidPolicy'});
  const client = new Client({profile, route: 'direct', pool: {maxHttp2ConnectionsPerOrigin: 9, negotiatedSetupWaitLimitMs: 0}});
  return client.close();
});
