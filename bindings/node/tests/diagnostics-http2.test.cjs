'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
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
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem')});
  server.on('session', (session) => {sessions.add(session); session.on('error', () => {});});
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {}); const target = headers[':path']; streams.set(target, stream.session);
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
  const healthy = await client.request(url + '/healthy', {...options, diagnostics: healthyTrace});
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
