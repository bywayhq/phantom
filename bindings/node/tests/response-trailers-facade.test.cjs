'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { loadFacade } = require('./load-facade.cjs');
const {test} = require('node:test');

function facade() {
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = {exports: loadFacade(filename, {NativeEnvironment: class {}})};
  return loaded.exports;
}

function body(Response, bytes = Buffer.from('!')) {
  let state = 'pending', reads = 0, snapshots = 0;
  const native = {
    status: 200, protocol: 'http1', url: 'http://peer/', redirects: 0, connectionRetries: 0,
    headers: [], decodedContentCodings: [], redirectHistory: null,
    get trailers() {
      snapshots++;
      return {state, headers: state === 'complete' ? [
        {name: 'X-A', value: Buffer.from('first'), sensitive: false}, {name: 'x-b', value: Buffer.from([0x80]), sensitive: true},
        {name: 'x-a', value: Buffer.from('last'), sensitive: false},
      ] : undefined};
    },
    async read() { reads++; state = 'complete'; return null; },
    async collect() { reads++; state = 'complete'; return bytes; },
    close() { if (state === 'pending') state = 'unavailable'; },
  };
  return {response: new Response(native, () => {}, {}), native,
    counts: () => ({reads, snapshots}), setState: (value) => { state = value; }};
}

test('trailer access never polls and returns detached frozen ordered snapshots', async () => {
  const {Response} = facade(); const {response, counts} = body(Response);
  assert.deepEqual(response.trailers, {state: 'pending', headers: null});
  assert.deepEqual(counts(), {reads: 0, snapshots: 1});
  assert.equal(await response.read(), null);
  const snapshot = response.trailers;
  assert.equal(snapshot.state, 'complete');
  assert.deepEqual(snapshot.headers.map((field) => field.name), ['X-A', 'x-b', 'x-a']);
  assert.deepEqual(snapshot.headers[1].value, Buffer.from([0x80]));
  assert.equal(snapshot.headers[1].sensitive, true);
  assert.ok(Object.isFrozen(snapshot) && Object.isFrozen(snapshot.headers) && Object.isFrozen(snapshot.headers[0]));
  assert.throws(() => { snapshot.headers[0].name = 'other'; }, TypeError);
  assert.throws(() => { response.trailers = {}; }, TypeError);
  snapshot.headers[0].value.fill(0);
  assert.equal(response.trailers.headers[0].value.toString(), 'first');
  response.close();
  assert.equal(response.trailers.state, 'complete');
  assert.equal(counts().reads, 1);
});

test('head fields preserve actual markers, raw values and order without polling', () => {
  const {Response} = facade(); const original = body(Response);
  original.native.headers = [
    {name: 'X-A', value: Buffer.from('first'), sensitive: false},
    {name: 'x-b', value: Buffer.from([0x80]), sensitive: true},
    {name: 'x-a', value: Buffer.from('last'), sensitive: false},
  ];
  const response = new Response(original.native, () => {}, {});
  assert.deepEqual(response.headers, original.native.headers);
  assert.ok(Object.isFrozen(response.headers) && Object.isFrozen(response.headers[0]));
  assert.equal(response.headers[1].sensitive, true);
  assert.throws(() => { response.headers[1].sensitive = false; }, TypeError);
  original.native.headers.pop();
  assert.equal(response.headers.length, 3);
  response.close();
  assert.equal(response.headers[1].sensitive, true);
  assert.deepEqual(original.counts(), {reads: 0, snapshots: 0});
});

test('post-EOF text and JSON failures retain completion while abandonment remains unavailable', async () => {
  const {Response} = facade();
  for (const [method, bytes, expected] of [['text', Buffer.from([0xff]), 'TextDecode'], ['json', Buffer.from('!'), 'JsonDecode']]) {
    const {response} = body(Response, bytes);
    await assert.rejects(response[method](1), (error) => error.code === expected);
    assert.equal(response.trailers.state, 'complete');
  }
  const {response, counts} = body(Response);
  response.close();
  assert.deepEqual(response.trailers, {state: 'unavailable', headers: null});
  assert.equal(counts().reads, 0);
});

test('unsupported native state is an explicit redacted error without reading', () => {
  const {Response} = facade(); const {response, setState, counts} = body(Response);
  setState('private-new-state');
  assert.throws(() => response.trailers, (error) => error.code === 'UnsupportedResponseTrailers' && !String(error).includes('private'));
  assert.equal(counts().reads, 0);
  response.close();
});
