'use strict';
const assert = require('node:assert/strict');
const {once} = require('node:events');
const fs = require('node:fs');
const http2 = require('node:http2');
const path = require('node:path');
const {test} = require('node:test');
const {Client, PhantomError, TransferControl} = require('..');
const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
async function reserved(control) {
  const deadline = Date.now() + 5000;
  while (control.snapshot().downloadReservedBytes === 0n) {
    if (Date.now() >= deadline) throw new Error('paced response was not admitted');
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

test('paced cancellation retains its reservation and a live HTTP/2 sibling', {timeout: 30000}, async (t) => {
  const sessions = new Set(), observed = new Map(), releases = new Map(), resets = new Map();
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem')});
  server.on('session', (session) => { sessions.add(session); session.on('error', () => {}); });
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {}); const target = headers[':path']; observed.set(target, stream.session);
    stream.respond({':status': 200});
    if (target.startsWith('/healthy')) releases.set(target, () => stream.end('healthy'));
    else {
      resets.set(target, new Promise((resolve) => stream.once('close', () => resolve(stream.rstCode))));
      // Keep the stream open so dropping its paced reader must send CANCEL.
      stream.write(Buffer.alloc(1024, 0x61));
    }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const session of sessions) session.destroy(); await new Promise((resolve) => server.close(resolve)); });
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')]}); t.after(() => client.close());
  const url = `https://127.0.0.1:${server.address().port}`;
  const options = {method: 'GET', protocol: 'http2', context: 'raw', timeouts: {totalMs: null}};
  for (const mode of ['cancel', 'total', 'cap']) {
    const control = new TransferControl(mode === 'cap' ? {downloadBytes: 0} : {downloadBytesPerSecond: 1});
    const controller = new AbortController();
    const healthy = await client.request(url + '/healthy-' + mode, options);
    const selected = await client.request(url + '/' + mode, {...options, transferControl: control, signal: controller.signal,
      timeouts: {totalMs: mode === 'total' ? 3000 : null, readIdleMs: mode === 'total' ? 500 : null}});
    assert.equal(observed.get('/' + mode), observed.get('/healthy-' + mode));
    const reading = selected.bytes(2048);
    // Attach the rejection observer before waiting for the native reservation.
    const rejected = assert.rejects(reading, (error) => error instanceof PhantomError
      && error.code === (mode === 'total' ? 'Timeout' : mode === 'cap' ? 'Transfer' : 'Cancelled')
      && (mode !== 'total' || error.timeoutPhase === 'total'));
    if (mode !== 'cap') {
      await reserved(control);
      assert.equal(control.snapshot().downloadEncodedBytes, 0n);
      if (mode === 'cancel') controller.abort();
    }
    await rejected;
    assert.equal(await resets.get('/' + mode), http2.constants.NGHTTP2_CANCEL);
    const counts = control.snapshot();
    assert.equal(counts.downloadReservedBytes, mode === 'cap' ? 0n : 1024n);
    assert.equal(counts.downloadEncodedBytes, 0n); assert.equal(counts.downloadDecodedBytes, 0n);
    releases.get('/healthy-' + mode)(); assert.equal(await healthy.text(7), 'healthy');
  }
  assert.equal(sessions.size, 1);
});
