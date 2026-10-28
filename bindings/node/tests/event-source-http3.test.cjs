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

for (const reject of [undefined, 'initial', 'reconnect']) {
  const name = reject === undefined ? 'reconnect preserves a live sibling and reuses one connection' : `${reject} rejection is terminal`;
  test(`HTTP/3 EventSource ${name}`, {timeout: 30000}, async () => {
    const python = process.env.PHANTOM_H3_PEER_PYTHON;
    const script = process.env.PHANTOM_EVENTS_H3_PEER_SCRIPT;
    assert.ok(python && script, 'independent HTTP/3 EventSource peer paths are required');
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-node-events-h3-'));
    const peer = spawn(python, [script, '--directory', directory, ...(reject === undefined ? [] : ['--reject', reject])], {stdio: ['pipe', 'pipe', 'pipe']});
    const lines = readline.createInterface({input: peer.stdout, terminal: false})[Symbol.asyncIterator]();
    let stderr = '', stderrOverflow = false;
    peer.stderr.on('data', (data) => {
      if (Buffer.byteLength(stderr) + data.length > 65536) stderrOverflow = true;
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
    function rejected(error) {
      assert(error instanceof PhantomError);
      assert.equal(error.code, 'Sse');
      assert.equal(error.kind, 'UnexpectedStatus');
      assert(!String(error).includes('private'));
      return true;
    }
    let client, source, healthy, primary;
    try {
      await event('ready');
      const ready = await receipt('ready.json');
      client = new Client({profile: 'chrome/154.0.8037.97/windows-11-26200/r1',
        route: 'direct', context: 'raw', protocol: 'http3',
        additionalRoots: [Buffer.from(ready.root_der)], timeouts: {totalMs: 10000}});
      const opening = client.eventSource(ready.url + '/events', {
        protocol: 'http3', initialRetryMs: 0, minimumRetryMs: 200, maximumReconnects: 3,
      });
      if (reject === 'initial') {
        await assert.rejects(opening, rejected);
      } else {
        source = await opening;
        assert.equal(source.status, 200);
        assert.equal(source.protocol, 'http3');
        assert.equal(source.url, ready.url + '/events');
        assert.deepEqual(await source.read(), {data: 'first', event: 'message', id: '7'});
        if (reject === 'reconnect') {
          await assert.rejects(source.read(), rejected);
          assert.equal(await source.read(), null);
          assert.equal(source.reconnects, 1);
          assert.equal(source.closed, true);
        } else {
          healthy = await client.get(ready.url + '/healthy');
          await event('live');
          assert.deepEqual(await source.read(), {data: 'second', event: 'message', id: '9'});
          assert.equal(await source.read(), null);
          assert.equal(source.lastEventId, '9');
          assert.equal(source.reconnects, 2);
          assert.equal(source.retryMs, 200n);
          assert.equal(source.closed, true);
          assert.equal(await healthy.text(7), 'healthy');
        }
      }
      if (reject !== undefined) await event('rejected');
      const reused = await client.get(ready.url + '/reuse');
      try { assert.equal(await reused.text(2), 'ok'); }
      finally { reused.close(); }
      await event('complete');
      const result = await receipt('result.json');
      const expected = reject === 'initial' ? ['/events', '/reuse']
        : reject === 'reconnect' ? ['/events', '/events', '/reuse']
          : ['/events', '/healthy', '/events', '/events', '/reuse'];
      assert.equal(result.connections, 1);
      assert.deepEqual(result.requests.map((request) => request.path), expected);
      assert.equal(new Set(result.requests.map((request) => request.stream)).size, expected.length);
      assert.deepEqual(result.requests.filter((request) => request.path === '/events').map((request) =>
        request.headers.filter(([name]) => name === 'last-event-id').map(([, value]) => value)),
      reject === 'initial' ? [[]] : reject === 'reconnect' ? [[], ['7']] : [[], ['7'], ['9']]);
      assert.equal(result.healthy_released, reject === undefined);
      peer.stdin.end('stop\n');
      assert.deepEqual(await bounded(exit, 'HTTP/3 EventSource peer did not settle', 8000), {code: 0, signal: null}, stderr);
      assert.equal(stderrOverflow, false);
      await assert.rejects(fs.stat(path.join(directory, 'error.json')), {code: 'ENOENT'});
      await client.close();
    } catch (error) {
      primary = error;
    } finally {
      const cleanup = [];
      for (const response of [source, healthy]) {
        try { response?.close(); } catch (error) { cleanup.push(error); }
      }
      if (!peer.stdin.destroyed) peer.stdin.end();
      try {
        assert.deepEqual(await bounded(exit, 'HTTP/3 EventSource peer did not settle', 8000), {code: 0, signal: null}, stderr);
        assert.equal(stderrOverflow, false);
      } catch (error) {
        cleanup.push(error);
        peer.kill();
        try { await bounded(exit, 'HTTP/3 EventSource peer did not stop', 5000); }
        catch (error) { cleanup.push(error); }
      }
      try { if (client) await client.destroy(); } catch (error) { cleanup.push(error); }
      try { await fs.rm(directory, {recursive: true, force: true}); } catch (error) { cleanup.push(error); }
      if (primary && cleanup.length) throw new AggregateError([primary, ...cleanup], 'HTTP/3 EventSource test and cleanup failed');
      if (primary) throw primary;
      if (cleanup.length) throw new AggregateError(cleanup, 'HTTP/3 EventSource cleanup failed');
    }
  });
}
