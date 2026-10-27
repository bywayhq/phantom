'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { loadFacade } = require('./load-facade.cjs');
const {test} = require('node:test');
const {inspect} = require('node:util');

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
  const loaded = {exports: loadFacade(filename, native)};
  return {...loaded.exports, uploads, owner, nativeResponse: response};
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

test('client shutdown spends one timeout across native drain and upload cleanup', async () => {
  const {Client, uploads, owner} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  const source = {[Symbol.asyncIterator]() {return this;}, async next() {return {done: true};},
    return() {return new Promise((resolve) => setTimeout(() => resolve({done: true}), 25));}};
  await client.request('http://example.test', {...options, body: source});
  owner.close = async () => {await new Promise((resolve) => setTimeout(resolve, 60)); uploads[0].stop();};
  await assert.rejects(client.close({timeoutMs: 50}), {code: 'Timeout'});
  await client.close(); assert.equal(uploads[0].done, true);
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
  const source = { [Symbol.asyncIterator]() { return this; }, async next() { await assert.rejects(client.close(), rejected); await assert.rejects(client.destroy(), rejected); return {done: false, value: Buffer.from('a')}; },
    async return() { await assert.rejects(client.close(), rejected); await assert.rejects(client.destroy(), rejected); returned = true; return {done: true}; } };
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

function redacted(error) {
  for (const text of [String(error), inspect(error), inspect(error, {showHidden: true}), JSON.stringify(error)]) {
    assert.ok(!text.includes('secret-'), text);
  }
}

test('request upload failures preserve exact source and later cleanup causes', async () => {
  const {Client, uploads, owner, PhantomError} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const original = new Error('secret-source'), cleanupError = {message: 'secret-cleanup'};
  let failRequest, rejectReturn;
  owner.request = () => new Promise((_, reject) => { failRequest = reject; });
  const source = { [Symbol.asyncIterator]() { return this; }, async next() { throw original; },
    return() { return new Promise((_, reject) => { rejectReturn = reject; }); } };
  const pending = client.request('http://example.test', {...options, body: source});
  const upload = uploads[0];
  upload.fail = () => { upload.stop(); failRequest(new Error('PHANTOM_REQUEST:RequestBody:http2::upload failed')); };
  let received;
  const rejected = assert.rejects(pending, (error) => {
    assert.ok(error instanceof PhantomError); assert.equal(error.code, 'UploadSource');
    assert.equal(error.protocol, 'http2'); assert.equal(error.cause, original);
    assert.equal(error.cleanupError, undefined); redacted(error);
    assert.ok(inspect(error).includes("code: 'UploadSource', protocol: 'http2'"));
    received = error; return true;
  });
  upload.grant(); await rejected;
  rejectReturn(cleanupError); await tick();
  assert.equal(received.cleanupError, cleanupError); redacted(received);
  await assert.rejects(client.close(), (error) => {
    assert.equal(error.cause, original); assert.equal(error.cleanupError, cleanupError); redacted(error); return true;
  });
});

test('post-head reads translate core body failures and preserve native error metadata', async () => {
  for (const [method, nativeCode, expectedCode, phase] of [
    ['read', 'RequestBody', 'UploadSource', ''], ['bytes', 'RequestBody', 'UploadSource', ''],
    ['read', 'UploadSource', 'UploadSource', ''], ['bytes', 'Timeout', 'Timeout', 'total'],
    ['read', 'Cancelled', 'Cancelled', ''],
  ]) {
    const {Client, uploads, nativeResponse} = facade();
    const client = new Client({profile: 'exact', route: 'direct'});
    const original = {message: 'secret-source'}, cleanupError = new Error('secret-return');
    const source = { [Symbol.asyncIterator]() { return this; }, async next() { throw original; }, async return() { throw cleanupError; } };
    const response = await client.request('http://example.test', {...options, body: source});
    uploads[0].grant(); await tick();
    nativeResponse[method === 'bytes' ? 'collect' : 'read'] = async () => { throw new Error(`PHANTOM_REQUEST:${nativeCode}:http2:${phase}:request failed`); };
    await assert.rejects(response[method](16), (error) => {
      assert.equal(error.code, expectedCode); assert.equal(error.protocol, 'http2');
      assert.equal(error.timeoutPhase, phase || undefined);
      assert.equal(error.cause, original); assert.equal(error.cleanupError, cleanupError); redacted(error); return true;
    });
    await assert.rejects(client.close(), (error) => error.cleanupError === cleanupError);
  }
});

test('post-head core body failures stay primary without a producer failure', async () => {
  for (const cleanupFails of [false, true]) {
    const {Client, uploads, nativeResponse} = facade();
    const client = new Client({profile: 'exact', route: 'direct'});
    const cleanupError = new Error('secret-cleanup');
    const source = { [Symbol.asyncIterator]() { return this; }, async next() { assert.fail('source was not pulled'); },
      async return() { if (cleanupFails) throw cleanupError; return {done: true}; } };
    const response = await client.request('http://example.test', {...options, body: source});
    uploads[0].stop(); await tick();
    nativeResponse.read = async () => { throw new Error('PHANTOM_REQUEST:RequestBody:http2::request failed'); };
    await assert.rejects(response.read(), (error) => {
      assert.equal(error.code, 'RequestBody'); assert.equal(error.protocol, 'http2');
      assert.equal(error.cleanupError, cleanupFails ? cleanupError : undefined); redacted(error); return true;
    });
    if (cleanupFails) await assert.rejects(client.close(), (error) => error.cleanupError === cleanupError);
    else await client.close();
  }
});

test('request cancellation and timeouts keep native category with explicit upload causes', async () => {
  for (const [name, phase] of [['Cancelled', ''], ['Timeout', 'connect']]) {
    const {Client, uploads, owner} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
    const original = new Error('secret-source'); let failRequest;
    owner.request = () => new Promise((_, reject) => { failRequest = reject; });
    const source = { [Symbol.asyncIterator]() { return this; }, async next() { throw original; } };
    const pending = client.request('http://example.test', {...options, body: source});
    const upload = uploads[0];
    upload.fail = () => { upload.stop(); failRequest(new Error(`PHANTOM_REQUEST:${name}:http3:${phase}:request failed`)); };
    const rejected = assert.rejects(pending, (error) => {
      assert.equal(error.code, name); assert.equal(error.protocol, 'http3'); assert.equal(error.timeoutPhase, phase || undefined);
      assert.equal(error.cause, original); redacted(error);
      const summary = inspect(error, {showHidden: true});
      assert.ok(summary.includes(`code: '${name}'`)); assert.ok(summary.includes("protocol: 'http3'"));
      assert.ok(summary.includes(`timeoutPhase: ${phase ? "'connect'" : 'undefined'}`)); return true;
    });
    upload.grant(); await rejected; await client.close();
  }
});

test('successful body completion stays successful while close reports cleanup identity', async () => {
  const {Client, uploads} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  const cleanupError = new Error('secret-return'); let returned = false;
  const source = { [Symbol.asyncIterator]() { return this; }, async next() { return {done: false, value: Buffer.from('x')}; },
    async return() { returned = true; throw cleanupError; } };
  const response = await client.request('http://example.test', {...options, body: source});
  assert.deepEqual(await response.bytes(0), Buffer.alloc(0));
  await assert.rejects(client.close(), (error) => {
    assert.equal(error.code, 'UploadSource'); assert.equal(error.cause, cleanupError);
    assert.equal(error.cleanupError, cleanupError); redacted(error); return true;
  });
  assert.equal(returned, true); assert.equal(uploads[0].done, true);
});

test('arbitrary thrown upload values remain explicit and are not formatted', async () => {
  for (const original of ['secret-string', undefined, {[inspect.custom]() { throw new Error('secret-inspect'); }}]) {
    const {Client, uploads, nativeResponse} = facade();
    const client = new Client({profile: 'exact', route: 'direct'});
    const source = { [Symbol.asyncIterator]() { return this; }, async next() { throw original; } };
    const response = await client.request('http://example.test', {...options, body: source});
    uploads[0].grant(); await tick();
    nativeResponse.read = async () => { throw new Error('PHANTOM:UploadSource:upload source failed'); };
    await assert.rejects(response.read(), (error) => {
      assert.equal(Object.hasOwn(error, 'cause'), true); assert.equal(error.cause, original);
      redacted(error); return true;
    });
    await client.close();
  }
});

test('cleanup-only failures do not replace unrelated primary native failures', async () => {
  for (const name of ['Connect', 'Tls', 'AttemptBudgetExhausted']) {
    const {Client, uploads, owner} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
    const cleanupError = new Error('secret-return'); let failRequest;
    owner.request = () => new Promise((_, reject) => { failRequest = reject; });
    const source = { [Symbol.asyncIterator]() { return this; }, async next() { assert.fail('setup did not request source bytes'); },
      async return() { throw cleanupError; } };
    const pending = client.request('http://example.test', {...options, body: source});
    uploads[0].stop(); await tick();
    assert.equal(uploads[0].done, true);
    const rejected = assert.rejects(pending, (error) => {
      assert.equal(error.code, name); assert.equal(error.protocol, 'http2');
      assert.equal(error.cause, cleanupError); assert.equal(error.cleanupError, cleanupError);
      assert.ok(inspect(error).includes(`code: '${name}'`)); redacted(error); return true;
    });
    failRequest(new Error(`PHANTOM_REQUEST:${name}:http2::request failed`)); await rejected;
    await assert.rejects(client.close(), (error) => error.code === 'UploadSource' && error.cleanupError === cleanupError);
  }
});
