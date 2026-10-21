'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const fs = require('node:fs');
const http2 = require('node:http2');
const net = require('node:net');
const path = require('node:path');
const {test} = require('node:test');
const {gzipSync} = require('node:zlib');
const {Client, PhantomError} = require('..');

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const fields = Buffer.concat([Buffer.from('X-A: first\r\nx-b: '), Buffer.from([0x80]), Buffer.from('middle\r\nx-a: last\r\n\r\n')]);
const expected = [{name: 'X-A', value: Buffer.from('first'), sensitive: false},
  {name: 'x-b', value: Buffer.concat([Buffer.from([0x80]), Buffer.from('middle')]), sensitive: false},
  {name: 'x-a', value: Buffer.from('last'), sensitive: false}];

async function rawPeer(t, respond) {
  let connections = 0;
  const sockets = new Set();
  const server = net.createServer((socket) => {
    connections++; sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    let pending = Buffer.alloc(0);
    socket.on('data', (data) => {
      pending = Buffer.concat([pending, data]);
      const end = pending.indexOf('\r\n\r\n');
      if (end !== -1) {
        const target = pending.toString('ascii', 0, end).split(' ')[1];
        pending = pending.subarray(end + 4);
        respond(socket, target);
      }
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const client = new Client({profile, route: 'direct'}); t.after(() => client.close());
  return {client, url: `http://127.0.0.1:${server.address().port}`, connections: () => connections};
}
const head = Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n');
const chunk = (bytes) => Buffer.concat([Buffer.from(bytes.length.toString(16) + '\r\n'), bytes, Buffer.from('\r\n')]);

test('HTTP/1 trailers retain raw spelling, interleaved duplicates and bytes through EOF and reuse', {timeout: 30000}, async (t) => {
  const {client, url, connections} = await rawPeer(t, (socket, target) => {
    const wire = Buffer.concat([head, chunk(Buffer.from('abc')), Buffer.from('0\r\n'), fields]);
    if (target === '/fragmented') {
      // Split across trailer name, value and final CRLF boundaries.
      const cuts = [head.length + 8, wire.length - fields.length + 2, wire.length - 3];
      let offset = 0;
      const send = () => {
        const end = cuts.shift() ?? wire.length;
        socket.write(wire.subarray(offset, end)); offset = end;
        if (offset !== wire.length) setImmediate(send);
      };
      send();
    } else socket.write(wire);
  });
  for (const target of ['/fragmented', '/coalesced']) {
    const response = await client.request(url + target, options);
    assert.deepEqual(response.trailers, {state: 'pending', headers: null});
    assert.equal((await response.read(1)).toString(), 'a');
    assert.equal(response.trailers.state, 'pending');
    assert.equal(await response.text(2), 'bc');
    assert.deepEqual(response.trailers, {state: 'complete', headers: expected});
    const snapshot = response.trailers;
    snapshot.headers[0].value.fill(0);
    response.close();
    assert.deepEqual(response.trailers.headers, expected);
  }
  assert.equal(connections(), 1, 'validated EOF must preserve HTTP/1 connection reuse');
});

test('empty completion and post-EOF parsing errors differ from limit, decoder and truncated failures', {timeout: 30000}, async (t) => {
  const {client, url} = await rawPeer(t, (socket, target) => {
    if (target === '/empty') { socket.write(Buffer.concat([head, Buffer.from('0\r\n\r\n')])); return; }
    if (target === '/truncated') { socket.end(Buffer.concat([head, chunk(Buffer.from('a')), Buffer.from('0\r\nX-A: unfinished')])); return; }
    if (target === '/malformed') { socket.end(Buffer.concat([head, chunk(Buffer.from('a')), Buffer.from('0\r\nBad Name: x\r\n\r\n')])); return; }
    if (target.startsWith('/gzip')) {
      const encoded = gzipSync(Buffer.from('abc'));
      if (target === '/gzip') encoded[encoded.length - 8] ^= 1;
      socket.write(Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n'), chunk(encoded), Buffer.from('0\r\n'), fields])); return;
    }
    socket.write(Buffer.concat([head, chunk(target === '/utf8' ? Buffer.from([0xff]) : Buffer.from('!')), Buffer.from('0\r\n'), fields]));
  });
  const empty = await client.request(url + '/empty', options);
  assert.deepEqual(empty.trailers, {state: 'pending', headers: null});
  assert.equal((await empty.bytes(0)).length, 0);
  assert.deepEqual(empty.trailers, {state: 'complete', headers: []});
  for (const [target, method, code] of [['/utf8', 'text', 'TextDecode'], ['/json', 'json', 'JsonDecode']]) {
    const response = await client.request(url + target, options);
    await assert.rejects(response[method](1), (error) => error.code === code);
    assert.deepEqual(response.trailers.headers, expected);
    response.close(); assert.equal(response.trailers.state, 'complete');
  }
  const decoded = await client.request(url + '/gzip-ok', {...options,
    headers: [{name: 'accept-encoding', value: Buffer.from('gzip')}],
    contentDecoding: {mode: 'advertised', maximumDecodedBytes: 3}});
  assert.equal(await decoded.text(3), 'abc');
  assert.deepEqual(decoded.trailers, {state: 'complete', headers: expected});
  for (const target of ['/limit', '/truncated', '/malformed', '/gzip']) {
    const response = await client.request(url + target, {...options, ...(target === '/gzip' ? {
      headers: [{name: 'accept-encoding', value: Buffer.from('gzip')}],
      contentDecoding: {mode: 'advertised', maximumDecodedBytes: 3},
    } : {})});
    await assert.rejects(response.bytes(target === '/limit' ? 0 : 100), (error) => error instanceof PhantomError
      && error.code === (target === '/limit' ? 'ResponseBodyLimit' : target === '/gzip' ? 'ContentDecoding' : 'Http1'));
    assert.deepEqual(response.trailers, {state: 'unavailable', headers: null});
    response.close(); assert.equal(response.trailers.state, 'unavailable');
  }
});

test('HTTP/2 trailer completion and cancelled live siblings retain independent stream state', {timeout: 30000}, async (t) => {
  const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
  const sessions = new Set(), observed = new Map(), releases = new Map(), resets = new Map();
  const server = http2.createSecureServer({key: fixture('key.pem'), cert: fixture('certificate.pem')});
  server.on('session', (session) => { sessions.add(session); session.on('error', () => {}); });
  server.on('stream', (stream, headers) => {
    stream.on('error', () => {}); observed.set(headers[':path'], stream.session);
    stream.respond({':status': 200}, {waitForTrailers: true});
    stream.on('wantTrailers', () => stream.sendTrailers({'x-a': ['first', 'last'], 'x-b': 'middle'}));
    releases.set(headers[':path'], () => headers[':path'] === '/limit' ? stream.write('overflow') : stream.end('healthy'));
    resets.set(headers[':path'], new Promise((resolve) => stream.once('close', () => resolve(stream.rstCode))));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const session of sessions) session.destroy(); await new Promise((resolve) => server.close(resolve)); });
  const client = new Client({profile, route: 'direct', additionalRoots: [fixture('certificate.der')]});
  t.after(() => client.close());
  const url = `https://127.0.0.1:${server.address().port}`;
  const request = {...options, protocol: 'http2', timeouts: {totalMs: null}}; delete request.timeoutMs;
  for (const mode of ['abort', 'close', 'limit']) {
    const controller = new AbortController();
    const selected = await client.request(url + '/' + mode, {...request, signal: controller.signal});
    const healthy = await client.request(url + '/healthy-' + mode, request);
    assert.equal(observed.get('/' + mode), observed.get('/healthy-' + mode));
    assert.equal(selected.trailers.state, 'pending');
    assert.equal(healthy.trailers.state, 'pending');
    if (mode === 'abort') {
      const reading = selected.read(); controller.abort();
      await assert.rejects(reading, (error) => error.code === 'Cancelled');
    } else if (mode === 'limit') {
      const reading = selected.bytes(0);
      releases.get('/limit')();
      await assert.rejects(reading, (error) => error.code === 'ResponseBodyLimit');
    } else selected.close();
    assert.equal(await resets.get('/' + mode), http2.constants.NGHTTP2_CANCEL);
    assert.deepEqual(selected.trailers, {state: 'unavailable', headers: null});
    releases.get('/healthy-' + mode)();
    assert.equal(await healthy.text(7), 'healthy');
    assert.deepEqual(healthy.trailers, {state: 'complete', headers: [
      {name: 'x-a', value: Buffer.from('first'), sensitive: false}, {name: 'x-a', value: Buffer.from('last'), sensitive: false}, {name: 'x-b', value: Buffer.from('middle'), sensitive: false},
    ]});
    healthy.close(); assert.equal(healthy.trailers.state, 'complete');
  }
  assert.equal(sessions.size, 1);
});
