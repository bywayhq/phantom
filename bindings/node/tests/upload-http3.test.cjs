'use strict';

const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const {test} = require('node:test');
const {Client, PhantomError} = require('..');

async function bounded(promise, label, milliseconds = 10000) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

test('HTTP/3 upload abort preserves a live sibling and reuses its connection', {timeout: 30000}, async () => {
  const python = process.env.PHANTOM_H3_PEER_PYTHON;
  const script = process.env.PHANTOM_H3_PEER_SCRIPT;
  assert.ok(python && script, 'independent HTTP/3 peer paths are required');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-node-h3-'));
  const peer = spawn(python, [script, '--directory', directory], {stdio: ['pipe', 'pipe', 'pipe']});
  const lines = readline.createInterface({input: peer.stdout, terminal: false})[Symbol.asyncIterator]();
  let stderr = '', stderrOverflow = false;
  peer.stderr.on('data', (data) => {
    if (stderr.length + data.length > 65536) stderrOverflow = true;
    else stderr += data.toString();
  });
  const exit = new Promise((resolve) => {
    peer.once('error', (error) => resolve({error}));
    peer.once('close', (code, signal) => resolve({code, signal}));
  });
  async function event(expected) {
    const line = await bounded(lines.next(), `missing peer event ${expected}`);
    assert.equal(line.done, false);
    assert.ok(Buffer.byteLength(line.value) <= 1024);
    assert.deepEqual(JSON.parse(line.value), {event: expected});
  }
  async function receipt(name) {
    const data = await fs.readFile(path.join(directory, name));
    assert.ok(data.length <= 65536);
    return JSON.parse(data.toString());
  }
  let client, selected, healthy;
  let pulls = 0, returns = 0, release, entered;
  const pending = new Promise((resolve) => { entered = resolve; });
  const source = {
    [Symbol.asyncIterator]() { return this; },
    async next() {
      pulls++;
      if (pulls === 1) return {done: false, value: Buffer.alloc(1024, 85)};
      assert.equal(pulls, 2);
      entered();
      return new Promise((resolve) => { release = resolve; });
    },
    async return() {
      returns++;
      release?.({done: true});
      return {done: true};
    },
  };
  try {
    await event('ready');
    const ready = await receipt('ready.json');
    client = new Client({profile: 'chrome/154.0.8037.97/windows-11-26200/r1',
      route: 'direct', additionalRoots: [Buffer.from(ready.root_der)], timeouts: {totalMs: 10000}});
    const options = {method: 'GET', protocol: 'http3', context: 'raw'};
    const warm = await client.request(ready.url + '/warm', options);
    assert.equal(await warm.text(2), 'ok');
    const controller = new AbortController();
    selected = await client.request(ready.url + '/upload', {...options, method: 'POST', body: source, signal: controller.signal});
    assert.equal((await selected.read(1)).toString(), 'a');
    await bounded(pending, 'producer was not pending');
    healthy = await client.request(ready.url + '/healthy', options);
    await event('live');
    controller.abort();
    await assert.rejects(selected.read(), (error) => error instanceof PhantomError && error.code === 'Cancelled');
    await event('cancelled');
    assert.equal(await healthy.text(7), 'healthy');
    const reuse = await client.request(ready.url + '/reuse', options);
    assert.equal(await reuse.text(2), 'ok');
    await event('complete');
    // Client shutdown joins cooperative iterator cleanup, without closing the peer early.
    assert.equal(pulls, 2);
    const result = await receipt('result.json');
    assert.equal(result.connections, 1);
    assert.equal(result.protocol, 'h3');
    assert.equal(result.upload_bytes, 1024);
    assert.deepEqual(result.cancellations, {reset_stream: 0x10c, stop_sending: 0x10c});
    assert.equal(result.healthy_released, true);
    assert.equal(new Set(Object.values(result.streams)).size, 4);
    peer.stdin.end('stop\n');
    const stopped = await bounded(exit, 'HTTP/3 peer did not settle', 8000);
    assert.deepEqual(stopped, {code: 0, signal: null}, stderr);
    await client.close();
    assert.equal(returns, 1);
  } finally {
    const cleanupErrors = [];
    for (const response of [selected, healthy]) {
      try { response?.close(); } catch (error) { cleanupErrors.push(error); }
    }
    release?.({done: true});
    if (!peer.stdin.destroyed) peer.stdin.end();
    try {
      const stopped = await bounded(exit, 'HTTP/3 peer did not settle', 8000);
      assert.deepEqual(stopped, {code: 0, signal: null}, stderr);
      assert.equal(stderrOverflow, false);
    } catch (error) {
      peer.kill(); await exit; throw error;
    } finally {
      try { if (client) await client.close(); } catch (error) { cleanupErrors.push(error); }
      await fs.rm(directory, {recursive: true, force: true});
      if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'HTTP/3 test cleanup failed');
    }
  }
});
