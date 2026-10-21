'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const {Readable} = require('node:stream');
const {test} = require('node:test');
const {inspect} = require('node:util');

// Exercise the real facade with independent, explicit native demand.
function facade() {
  const uploads = [];
  class Upload {
    constructor() {
      this.writes = []; this.ends = []; this.credits = []; this.indices = [];
      this.terminal = new Promise((resolve) => { this.terminate = resolve; }); uploads.push(this);
    }
    configureMultipart(boundary, fields, maximum) { this.boundary = boundary; this.fields = fields; this.maximum = maximum; }
    nextPart() { return this.closed ? Promise.resolve(null) : new Promise((resolve) => this.indices.push(resolve)); }
    select(index) { this.index = index; assert.equal(this.indices.length, 1); this.indices.shift()(index); }
    ready() { return this.closed ? Promise.resolve(false) : new Promise((resolve) => this.credits.push(resolve)); }
    grant() { assert.equal(this.credits.length, 1); this.credits.shift()(true); }
    write(bytes) { assert.ok(bytes.length <= 65536); this.writes.push([this.index, Buffer.from(bytes)]); }
    end() { this.ends.push(this.index); }
    stop() { this.closed = true; this.terminate(); for (const resolve of this.indices.splice(0)) resolve(null); for (const resolve of this.credits.splice(0)) resolve(false); }
    stopped() { return this.terminal; }
    fail() { this.failed = true; this.stop(); }
    settled() { this.done = true; }
  }
  const response = {status: 200, protocol: 'http2', url: 'https://example.test', redirects: 0, connectionRetries: 0,
    headers: [], decodedContentCodings: [], redirectHistory: null,
    trailers: {state: 'pending', headers: null},
    close() { if (this.trailers.state === 'pending') this.trailers = {state: 'unavailable', headers: null}; },
    async read() { this.trailers = {state: 'complete', headers: []}; return null; },
    async collect() { this.trailers = {state: 'complete', headers: []}; return Buffer.from('ok'); },
  };
  const owner = {calls: 0, request(...args) { this.calls++; this.args = args; return Promise.resolve(response); }, async close() { for (const upload of uploads) upload.stop(); }};
  const native = {NativeEnvironment: class {client() {return owner;}}, NativeCancellation: class {cancel() {}}, NativeUpload: Upload};
  const filename = path.resolve(__dirname, '../index.cjs'), loaded = new Module(filename, module);
  loaded.filename = filename; loaded.paths = module.paths;
  loaded.require = (id) => id === './phantom.node' ? native : id === 'node:fs'
    ? {...fs, existsSync: (file) => file === path.join(path.dirname(filename), 'phantom.node') || fs.existsSync(file)} : Module.createRequire(filename)(id);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return {...loaded.exports, owner, uploads};
}
const tick = () => new Promise((resolve) => setImmediate(resolve));
const request = {method: 'POST', protocol: 'http2', context: 'raw'};
const multipart = (parts) => ({boundary: 'b', maximumBytes: 10000000, parts});
function source(value = Buffer.from('x')) {
  return {pulls: 0, closes: 0, [Symbol.asyncIterator]() {return this;}, async next() {
    return ++this.pulls === 1 ? {done: false, value} : {done: true};
  }, async return() {this.closes++; return {done: true};}};
}

test('multipart selects only the demanded source and closes it before child EOF', async () => {
  const {Client, uploads} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  const sources = Array.from({length: 70}, () => source());
  const descriptor = multipart(sources.map((stream) => ({name: 'duplicate', stream})));
  const response = await client.request('https://example.test', {...request, multipart: descriptor});
  const upload = uploads[0]; assert.equal(sources.reduce((n, s) => n + s.pulls, 0), 0);
  for (let index = 0; index < sources.length; index++) {
    upload.select(index); await tick(); upload.grant(); await tick();
    assert.equal(sources[index].pulls, 1); assert.equal(sources[index].closes, 0);
    upload.grant(); await tick(); assert.equal(sources[index].closes, 1);
    assert.deepEqual(upload.ends, Array.from({length: index + 1}, (_, i) => i));
    assert.equal(upload.done, undefined);
    assert.ok(sources.slice(index + 1).every((s) => !s.pulls && !s.closes));
  }
  assert.equal(await response.read(), null); assert.equal(upload.done, true);
  assert.deepEqual(response.trailers, {state: 'complete', headers: []});
  await assert.rejects(client.request('https://example.test', {...request, multipart: descriptor}), {code: 'InvalidOperation'});
  await client.close();
});

test('count, duplicate, shape, conflict and owner checks precede multipart custody', async () => {
  const {Client, owner} = facade(), client = new Client({profile: 'exact', route: 'direct'}), stream = source();
  for (const options of [
    {multipart: multipart(Array(1025).fill({name: 'x', stream}))},
    {multipart: multipart([{name: 'x', stream}, {name: 'y', stream}])},
    {multipart: multipart([{name: 'x', stream}, {name: 'bad', text: 'x', bytes: Buffer.alloc(0)}])},
    {multipart: multipart([{name: 'x', stream}]), body: Buffer.alloc(0)},
    {multipart: multipart([{name: 'x', stream}]), bodyLength: 0},
    {multipart: multipart([{name: 'x', stream}]), attemptBudget: {}},
  ]) await assert.rejects(client.request('https://example.test', {...request, ...options}));
  assert.equal(owner.calls, 0); assert.equal(stream.pulls, 0); assert.equal(stream.closes, 0);
  await client.close();
});

test('multipart frames are copied in bounded chunks without later-part prefetch', async () => {
  const {Client, uploads} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  const input = Buffer.alloc(100000, 97), first = source(input), later = source();
  const response = await client.request('https://example.test', {...request, multipart: multipart([{name: 'x', stream: first}, {name: 'x', stream: later}])});
  const upload = uploads[0]; upload.select(0); await tick(); upload.grant(); await tick();
  assert.equal(upload.writes[0][1].length, 65536); input[0] = 98;
  assert.equal(upload.writes[0][1][0], 97); assert.equal(later.pulls, 0);
  upload.grant(); await tick(); assert.equal(upload.writes[1][1].length, 34464);
  response.close(); await client.close(); assert.equal(first.closes, 1); assert.equal(later.closes, 1); assert.equal(later.pulls, 0);
});

test('early success destroys an unstarted Readable and awaits every cleanup failure', async () => {
  const {Client, uploads} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  let reads = 0, destroyed = 0, release;
  const readable = new Readable({read() {reads++;}, destroy(error, callback) {destroyed++; callback(error);}});
  const first = source(), second = source();
  const errors = [new Error('secret-one'), {secret: 'secret-two'}];
  first.return = async () => {first.closes++; throw errors[0];};
  second.return = () => {second.closes++; return new Promise((_, reject) => {release = () => reject(errors[1]);});};
  const response = await client.request('https://example.test', {...request, multipart: multipart([{name: 'x', stream: first}, {name: 'y', stream: second}, {name: 'z', stream: readable}])});
  const collecting = response.bytes(2); let done = false; collecting.then(() => {done = true;}, () => {done = true;});
  await tick(); assert.equal(done, false); assert.equal(reads, 0); assert.equal(destroyed, 1); assert.equal(uploads[0].done, undefined);
  release();
  await assert.rejects(collecting, (error) => {
    assert.equal(error.code, 'UploadSource'); assert.deepEqual(error.cleanupError.errors, errors);
    for (const value of [String(error), inspect(error, {showHidden: true}), JSON.stringify(error)]) assert.doesNotMatch(value, /secret/);
    return true;
  });
  assert.deepEqual(response.trailers, {state: 'complete', headers: []});
  await assert.rejects(client.close(), {code: 'UploadSource'});
});

test('multipart cleanup cannot await its own response or client', async () => {
  const {Client} = facade(), client = new Client({profile: 'exact', route: 'direct'}), stream = source();
  let response;
  stream.return = async () => {
    await assert.rejects(response.bytes(2), {code: 'InvalidOperation'});
    await assert.rejects(client.close(), {code: 'InvalidOperation'});
    return {done: true};
  };
  response = await client.request('https://example.test', {...request, multipart: multipart([{name: 'x', stream}])});
  assert.equal(await response.read(), null); await client.close();
});

test('source throw retains original and all later close causes without formatting', async () => {
  const {Client, uploads} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  const first = source(), later = source(), original = new Error('secret-next'), cleanup = new Error('secret-close');
  first.next = async () => {throw original;}; later.return = async () => {throw cleanup;};
  const response = await client.request('https://example.test', {...request, multipart: multipart([{name: 'x', stream: first}, {name: 'y', stream: later}])});
  uploads[0].select(0); await tick(); uploads[0].grant(); await tick();
  await assert.rejects(response.bytes(2), (error) => error.code === 'UploadSource' && error.cause === original && error.cleanupError === cleanup);
  await assert.rejects(client.close(), {code: 'UploadSource'});
});

test('one-shot concurrent claim and unfinished cleanup retain the original owner', async () => {
  const {Client, uploads, owner} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  const stream = source(), later = source(); let releaseClose, releaseHead;
  stream.return = () => {stream.closes++; return new Promise((resolve) => {releaseClose = () => resolve({done: true});});};
  const originalRequest = owner.request.bind(owner);
  owner.request = (...args) => new Promise((resolve) => {releaseHead = () => resolve(originalRequest(...args));});
  const descriptor = multipart([{name: 'x', stream}, {name: 'y', stream: later}]);
  const pending = client.request('https://example.test', {...request, multipart: descriptor});
  await assert.rejects(client.request('https://example.test', {...request, multipart: descriptor}), {code: 'InvalidOperation'});
  assert.equal(uploads.length, 1); releaseHead(); const response = await pending;
  response.close(); await tick();
  assert.equal(stream.closes, 1); assert.equal(later.closes, 1); assert.equal(uploads[0].done, undefined);
  await assert.rejects(client.close({timeoutMs: 1}), {code: 'Timeout'});
  assert.equal(uploads[0].done, undefined);
  releaseClose(); await client.close(); assert.equal(uploads[0].done, true);
});
