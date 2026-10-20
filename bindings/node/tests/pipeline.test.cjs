'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { Writable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { test } = require('node:test');
const { Client, PhantomError } = require('..');

const profile = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = { method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000 };

function observeClose(socket) {
  return new Promise((resolve) => {
    const closed = () => { clearTimeout(timer); resolve(null); };
    const timer = setTimeout(() => {
      socket.removeListener('close', closed);
      resolve(new Error('peer socket stayed open'));
    }, 5000);
    socket.once('close', closed);
  });
}

async function peer(t, handler) {
  const sockets = new Set();
  const server = http.createServer(handler);
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  const client = new Client({ profile, route: 'direct', maximumActiveRequests: 1 });
  t.after(() => client.close());
  return { client, url: `http://127.0.0.1:${server.address().port}` };
}

test('pipeline downloads the response to a file without body collection', { timeout: 30000 }, async (t) => {
  const payload = Buffer.alloc(196613, 0x61);
  const { client, url } = await peer(t, (_req, res) => res.end(payload));
  const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'phantom-pipeline-'));
  t.after(() => fs.promises.rm(directory, { recursive: true, force: true }));
  const output = path.join(directory, 'download.bin');
  const response = await client.request(url, options);
  try {
    await pipeline(response, fs.createWriteStream(output));
  } finally { response.close(); }
  assert.deepEqual(await fs.promises.readFile(output), payload);
});

test('pipeline waits for writable drain before pulling another chunk', { timeout: 30000 }, async (t) => {
  const payload = Buffer.alloc(196613, 0x62);
  const { client, url } = await peer(t, (_req, res) => res.end(payload));
  const response = await client.request(url, options);
  let pulls = 0;
  const read = response.read.bind(response);
  response.read = (maximum) => { pulls++; return read(maximum); };
  let started;
  const firstWrite = new Promise((resolve) => { started = resolve; });
  let release;
  let written = 0;
  const sink = new Writable({
    highWaterMark: 1,
    write(chunk, _encoding, callback) {
      written += chunk.length;
      if (release === undefined) {
        release = callback;
        started();
      } else callback();
    },
  });
  const completion = pipeline(response, sink);
  // Attach a handler before checking the gated writer, even if a check fails.
  const outcome = completion.then(() => null, (error) => error);
  try {
    try {
      await Promise.race([
        firstWrite,
        outcome.then((error) => { throw error ?? new Error('pipeline completed without writing'); }),
      ]);
      await new Promise(setImmediate);
      assert.equal(pulls, 1);
    } finally { release?.(); }
    const error = await outcome;
    if (error) throw error;
    assert.equal(written, payload.length);
  } finally {
    response.close();
    await outcome;
  }
});

test('pipeline output failure closes an unfinished response and releases admission', { timeout: 30000 }, async (t) => {
  let socket;
  const { client, url } = await peer(t, (req, res) => {
    if (req.url === '/healthy') return res.end('ok');
    socket = req.socket;
    res.writeHead(200); res.write('unfinished');
  });
  const response = await client.request(url, options);
  const closed = observeClose(socket);
  const failure = new Error('controlled output failure');
  const sink = new Writable({ write(_chunk, _encoding, callback) { callback(failure); } });
  try {
    await assert.rejects(pipeline(response, sink), (error) => error === failure);
    assert.equal(await closed, null);
    assert.equal((await (await client.request(url + '/healthy', options)).bytes(2)).toString(), 'ok');
  } finally { response.close(); }
});

test('aborted pipeline settles a pending read and closes the peer response', { timeout: 30000 }, async (t) => {
  let socket;
  const { client, url } = await peer(t, (req, res) => {
    if (req.url === '/healthy') return res.end('ok');
    socket = req.socket;
    res.writeHead(200); res.flushHeaders();
  });
  const controller = new AbortController();
  const response = await client.request(url, { ...options, signal: controller.signal });
  const closed = observeClose(socket);
  const read = response.read.bind(response);
  let reading;
  const started = new Promise((resolve) => { reading = resolve; });
  response.read = (maximum) => { const pending = read(maximum); reading(); return pending; };
  const sink = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const outcome = pipeline(response, sink, { signal: controller.signal }).then(() => null, (error) => error);
  try {
    await Promise.race([
      started,
      outcome.then((error) => { throw error ?? new Error('pipeline completed without reading'); }),
    ]);
    controller.abort();
    const error = await outcome;
    assert.ok(error?.name === 'AbortError' || (error instanceof PhantomError && error.code === 'Cancelled'));
    assert.equal(await closed, null);
    assert.equal((await (await client.request(url + '/healthy', options)).bytes(2)).toString(), 'ok');
  } finally { response.close(); await outcome; }
});
