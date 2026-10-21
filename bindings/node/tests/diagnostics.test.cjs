'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
const http = require('node:http');
const {test} = require('node:test');
const {Client, RequestDiagnostics} = require('..');

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};

async function peer(t, handler) {
  const sockets = new Set(), server = http.createServer(handler);
  server.on('connection', (socket) => {sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve));});
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  return {client, url: `http://127.0.0.1:${server.address().port}`};
}
const bodyEvent = (trace) => trace.snapshot().events.find((event) => event.phase === 'response_body');

test('a live timeline distinguishes response head, EOF and partial abandonment', {timeout: 30000}, async (t) => {
  const releases = new Map();
  const {client, url} = await peer(t, (request, response) => {
    response.writeHead(200, {'content-length': '4'}); response.flushHeaders();
    releases.set(request.url, () => response.end('body'));
  });
  const trace = new RequestDiagnostics(); assert.equal(trace.snapshot(), null);
  const response = await client.request(url + '/complete', {...options, diagnostics: trace});
  try {
    const before = trace.snapshot();
    assert.equal(before.outcome, 'response_head'); assert.equal(before.admittedAttempts, 1n);
    assert.equal(typeof before.sendElapsedNs, 'bigint');
    assert.equal(bodyEvent(trace).outcome, 'pending'); assert.equal(bodyEvent(trace).finishedNs, null);
    const connection = before.events.find((event) => event.phase === 'connection_use').connection;
    assert.equal(connection.endpointScope, 'tcp_socket'); assert.equal(connection.reused, false);
    assert.equal(connection.originTls.state, 'not_used'); assert.equal(connection.originTls.info, null);
    assert.ok(connection.peerAddress.endsWith(':' + new URL(url).port));
    releases.get('/complete')(); assert.equal(await response.text(4), 'body');
    const after = trace.snapshot();
    assert.equal(after.outcome, 'response_head'); assert.equal(after.sendElapsedNs, before.sendElapsedNs);
    assert.equal(bodyEvent(trace).outcome, 'completed'); assert.equal(typeof bodyEvent(trace).finishedNs, 'bigint');
    assert.ok(Object.isFrozen(after.events));
  } finally {response.close();}
  const partial = new RequestDiagnostics();
  const abandoned = await client.request(url + '/abandon', {...options, diagnostics: partial});
  abandoned.close();
  assert.equal(partial.snapshot().outcome, 'response_head'); assert.equal(bodyEvent(partial).outcome, 'abandoned');
  const small = new RequestDiagnostics({maximumEvents: 1});
  const limited = await client.request(url + '/limited', {...options, diagnostics: small}); limited.close();
  const snapshot = small.snapshot();
  assert.equal(snapshot.events.length, 1); assert.equal(snapshot.events[0].id, 0n);
  assert.ok(snapshot.droppedEvents > 0n); assert.equal(snapshot.admittedAttempts, 1n);
});

test('failed and cancelled sends retain their timeline and owners cannot be reused', {timeout: 30000}, async (t) => {
  let arrived;
  const headers = new Promise((resolve) => {arrived = resolve;});
  let raceRequests = 0;
  const {client, url} = await peer(t, (request, response) => {
    if (request.url === '/fail') request.socket.destroy();
    else if (request.url === '/race') {raceRequests++; response.end('race');}
    else arrived();
  });
  const failed = new RequestDiagnostics();
  await assert.rejects(client.request(url + '/fail', {...options, diagnostics: failed}));
  assert.equal(failed.snapshot().outcome, 'failed');
  const cancelled = new RequestDiagnostics(), controller = new AbortController();
  const pending = client.request(url + '/cancel', {...options, signal: controller.signal, diagnostics: cancelled});
  const rejection = assert.rejects(pending, {code: 'Cancelled'});
  await headers; assert.equal(cancelled.snapshot().outcome, 'pending'); controller.abort(); await rejection;
  assert.equal(cancelled.snapshot().outcome, 'cancelled');
  const sibling = client.fork(); t.after(() => sibling.close());
  const attempts = await Promise.allSettled([client, sibling].map((owner) => owner.request(url + '/duplicate', {...options, diagnostics: failed})));
  assert.equal(attempts.filter((result) => result.status === 'rejected' && result.reason.code === 'DiagnosticsAlreadyUsed').length, 2);
  const shared = new RequestDiagnostics();
  const raced = await Promise.allSettled([client, sibling].map((owner) => owner.request(url + '/race', {...options, diagnostics: shared})));
  assert.equal(raced.filter((result) => result.status === 'rejected' && result.reason.code === 'DiagnosticsAlreadyUsed').length, 1);
  const winner = raced.find((result) => result.status === 'fulfilled');
  assert.ok(winner); assert.equal(await winner.value.text(4), 'race'); assert.equal(raceRequests, 1);
  const fresh = new RequestDiagnostics();
  await assert.rejects(client.request(url + '/invalid', {...options, method: 'bad method', diagnostics: fresh}));
  assert.equal(fresh.snapshot(), null);
});
