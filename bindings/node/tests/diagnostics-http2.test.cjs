'use strict';
const assert = require('node:assert/strict');
const {once, errorMonitor} = require('node:events');
const {inspect} = require('node:util');
const fs = require('node:fs');
const http2 = require('node:http2');
const path = require('node:path');
const {test} = require('node:test');
const {Client, RequestDiagnostics} = require('..');
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';

test('selected cancellation retains diagnostics and a live same-session TLS sibling', {timeout: 30000}, async (t) => {
  const sessions = new Set(), streams = new Map(); let finishHealthy, selectedReset;
  const peerEvents = [], started = process.hrtime.bigint();
  const record = (event, fields = {}) => {
    if (peerEvents.length < 32) peerEvents.push({event, elapsedNs: String(process.hrtime.bigint() - started), ...fields});
  };
  const errorCode = (error) => typeof error.code === 'string' ? error.code.slice(0, 64) : null;
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem')});
  server.on('listening', () => record('listening', {port: server.address().port}));
  server.on('close', () => record('server_close'));
  server.on(errorMonitor, (error) => record('server_error', {code: errorCode(error)}));
  server.on('connection', (socket) => {
    record('tcp_connection', {localPort: socket.localPort, remotePort: socket.remotePort});
    socket.on(errorMonitor, (error) => record('tcp_error', {code: errorCode(error)}));
    socket.on('close', (hadError) => record('tcp_close', {hadError}));
  });
  server.on('secureConnection', (socket) => record('tls_connection', {alpn: socket.alpnProtocol}));
  server.on('session', (session) => {
    sessions.add(session); record('h2_session');
    session.on('error', (error) => record('h2_error', {code: errorCode(error)}));
    session.on('close', () => record('h2_close'));
  });
  server.on('stream', (stream, headers) => {
    stream.on('error', (error) => record('stream_error', {code: errorCode(error)}));
    const target = headers[':path']; streams.set(target, stream.session);
    record('h2_stream', {id: stream.id, target: String(target).slice(0, 64)});
    stream.respond({':status': 200});
    if (target === '/healthy') finishHealthy = () => stream.end('healthy');
    else if (target === '/selected') selectedReset = new Promise((resolve) => stream.once('close', () => resolve(stream.rstCode)));
    else stream.end('reuse');
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {for (const session of sessions) session.destroy(); await new Promise((resolve) => server.close(resolve));});
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')]}); t.after(() => client.close());
  const url = `https://127.0.0.1:${server.address().port}`;
  const options = {method: 'GET', protocol: 'http2', context: 'raw', timeoutMs: 10000};
  const healthyTrace = new RequestDiagnostics(), trace = new RequestDiagnostics();
  let healthy;
  try {
    healthy = await client.request(url + '/healthy', {...options, diagnostics: healthyTrace});
  } catch (error) {
    try {
      const snapshot = healthyTrace.snapshot();
      const timeline = snapshot == null ? null : {
        outcome: snapshot.outcome, sendElapsedNs: snapshot.sendElapsedNs,
        droppedEvents: snapshot.droppedEvents, admittedAttempts: snapshot.admittedAttempts,
        events: snapshot.events.slice(0, 32).map((event) => ({
          id: event.id, hop: event.hop, admission: event.admission, protocol: event.protocol,
          phase: event.phase, outcome: event.outcome,
          startedNs: event.startedNs, finishedNs: event.finishedNs,
        })),
      };
      const details = inspect({peerEvents, healthyTrace: timeline}, {
        depth: 6, maxArrayLength: 32, maxStringLength: 256, breakLength: 120,
      });
      t.diagnostic(details.slice(0, 16384));
    } catch {
      t.diagnostic('first-request diagnostics unavailable');
    }
    throw error;
  }
  const controller = new AbortController();
  const selected = await client.request(url + '/selected', {...options, signal: controller.signal, diagnostics: trace});
  try {
    assert.equal(streams.get('/healthy'), streams.get('/selected'));
    const connection = trace.snapshot().events.find((event) => event.phase === 'connection_use').connection;
    assert.equal(connection.reused, true); assert.equal(connection.originTls.state, 'established');
    assert.equal(connection.originTls.info.peerVerified, true);
    assert.deepEqual(connection.originTls.info.alpn, Buffer.from('h2'));
    assert.ok(connection.originTls.info.peerCertificatesDer.some((der) => der.equals(fixture('certificate.der'))));
    assert.equal(healthyTrace.snapshot().events.find((event) => event.phase === 'response_body').outcome, 'pending');
    const read = selected.read(); const rejected = assert.rejects(read, {code: 'Cancelled'});
    controller.abort(); await rejected;
    assert.equal(await selectedReset, http2.constants.NGHTTP2_CANCEL);
    assert.equal(trace.snapshot().outcome, 'response_head');
    assert.equal(trace.snapshot().events.find((event) => event.phase === 'response_body').outcome, 'abandoned');
    finishHealthy(); assert.equal(await healthy.text(7), 'healthy');
    assert.equal(healthyTrace.snapshot().events.find((event) => event.phase === 'response_body').outcome, 'completed');
    const reused = await client.request(url + '/reuse', options); assert.equal(await reused.text(5), 'reuse');
    assert.equal(streams.get('/reuse'), streams.get('/selected')); assert.equal(sessions.size, 1);
  } finally {selected.close(); healthy.close();}
});
