'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const {test} = require('node:test');

// Load the actual facade against a demand-controlled safe native boundary.
function facade() {
  const uploads = [];
  const response = {status: 200, protocol: 'http1', url: 'http://example.test/', redirects: 0,
    connectionRetries: 0, decodedContentCodings: [], redirectHistory: null, headers: [], close() {}, async collect() { return Buffer.alloc(0); }};
  class Upload {
    constructor(length) { this.length = length; this.chunks = []; this.readyWaiters = []; this.closed = false; this.done = false;
      this.terminal = new Promise((resolve) => { this.terminate = resolve; }); uploads.push(this); }
    ready() { if (this.closed) return Promise.resolve(false); return new Promise((resolve) => this.readyWaiters.push(resolve)); }
    grant() { assert.equal(this.readyWaiters.length, 1); this.readyWaiters.shift()(true); }
    write(value) { assert.ok(value.length <= 65536); this.chunks.push(Buffer.from(value)); }
    end() { this.ended = true; }
    fail() { this.failed = true; this.stop(); }
    stop() { this.closed = true; this.terminate(); for (const resolve of this.readyWaiters.splice(0)) resolve(false); }
    stopped() { return this.terminal; }
    settled() { this.done = true; }
  }
  const owner = {request(...args) { owner.args = args; return Promise.resolve(response); }, async close() { for (const upload of uploads) upload.stop(); }};
  const native = {NativeEnvironment: class { client() { return owner; } }, NativeCancellation: class { cancel() {} }, NativeUpload: Upload};
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = new Module(filename, module);
  loaded.filename = filename; loaded.paths = module.paths;
  loaded.require = (id) => id === './phantom.node' ? native : Module.createRequire(filename)(id);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return {...loaded.exports, uploads, owner};
}
const tick = () => new Promise((resolve) => setImmediate(resolve));
const options = {method: 'POST', protocol: 'http1', context: 'raw'};

test('pump pulls only with credit, splits owned frames, and stops before another source pull', async () => {
  const {Client, uploads} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  let pulls = 0, returned = 0;
  const buffer = Buffer.alloc(100000, 0x61);
  const source = { [Symbol.asyncIterator]() { return this; }, async next() { pulls++; return {done: false, value: buffer}; }, async return() { returned++; return {done: true}; } };
  const response = await client.request('http://example.test', {...options, body: source, bodyLength: 100000n});
  const upload = uploads[0];
  assert.equal(pulls, 0); assert.equal(upload.length, 100000n);
  upload.grant(); await tick();
  assert.equal(pulls, 1); assert.equal(upload.chunks.length, 1); assert.equal(upload.chunks[0].length, 65536);
  buffer[0] = 0x7a; assert.equal(upload.chunks[0][0], 0x61);
  upload.grant(); await tick();
  assert.equal(upload.chunks[1].length, 34464); assert.equal(pulls, 1);
  response.close(); await client.close();
  assert.equal(returned, 1); assert.equal(upload.done, true);
});

test('blocked iterator cleanup retains pending ownership after bounded close times out', async () => {
  const {Client, uploads, PhantomError} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  let finishNext, finishReturn, returning = false;
  const source = { [Symbol.asyncIterator]() { return this; }, next() { return new Promise((resolve) => { finishNext = resolve; }); },
    return() { returning = true; return new Promise((resolve) => { finishReturn = resolve; }); } };
  const response = await client.request('http://example.test', {...options, body: source});
  const upload = uploads[0]; upload.grant(); await tick();
  response.close(); await tick();
  assert.equal(returning, true); assert.equal(upload.done, false);
  await assert.rejects(client.close({timeoutMs: 1}), (error) => error instanceof PhantomError && error.code === 'Timeout');
  assert.equal(upload.done, false);
  finishNext({done: true}); finishReturn({done: true});
  await client.close(); assert.equal(upload.done, true);
});

test('empty chunks reuse credit and source or cleanup exceptions are redacted', async () => {
  const {Client, uploads, PhantomError} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  let calls = 0;
  const source = { [Symbol.asyncIterator]() { return this; }, async next() { if (++calls === 1) return {done: false, value: Buffer.alloc(0)}; throw new Error('secret-next'); }, async return() { throw new Error('secret-return'); } };
  await client.request('http://example.test', {...options, body: source});
  const upload = uploads[0]; upload.grant(); await tick();
  assert.equal(calls, 2); assert.equal(upload.failed, true); assert.equal(upload.done, true);
  await assert.rejects(client.close(), (error) => error instanceof PhantomError && error.code === 'UploadSource' && !error.message.includes('secret'));
});

test('a normal native close racing write or EOF does not become a source failure', async () => {
  for (const operation of ['write', 'end']) {
    const {Client, uploads} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
    let returned = 0;
    const source = { [Symbol.asyncIterator]() { return this; }, async next() { return operation === 'end' ? {done: true} : {done: false, value: Buffer.from('data')}; }, async return() { returned++; return {done: true}; } };
    const response = await client.request('http://example.test', {...options, body: source});
    const upload = uploads[0];
    upload[operation] = () => { throw new Error('PHANTOM:UploadClosed:upload is closed'); };
    upload.grant(); await tick();
    assert.notEqual(upload.failed, true); assert.equal(returned, 1);
    response.close(); await client.close();
  }
});

test('a producer cannot self-wait on its own client shutdown', async () => {
  const {Client, uploads, PhantomError} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  const rejected = (error) => error instanceof PhantomError && error.code === 'InvalidOperation';
  let returned = false;
  const source = { [Symbol.asyncIterator]() { return this; }, async next() { await assert.rejects(client.close(), rejected); return {done: false, value: Buffer.from('a')}; },
    async return() { await assert.rejects(client.close(), rejected); returned = true; return {done: true}; } };
  const response = await client.request('http://example.test', {...options, body: source});
  uploads[0].grant(); await tick(); response.close(); await client.close();
  assert.equal(returned, true); assert.notEqual(uploads[0].failed, true);
});

test('an endless empty producer cooperates with environment cancellation', async () => {
  const {Client, uploads} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  let pulls = 0, returned = false;
  const source = { [Symbol.asyncIterator]() { return this; }, async next() { pulls++; return {done: false, value: Buffer.alloc(0)}; }, async return() { returned = true; return {done: true}; } };
  const response = await client.request('http://example.test', {...options, body: source});
  uploads[0].grant(); setImmediate(() => response.close());
  await tick(); await client.close();
  assert.ok(pulls > 0 && pulls <= 32); assert.equal(returned, true);
});
