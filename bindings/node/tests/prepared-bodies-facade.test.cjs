'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadFacade } = require('./load-facade.cjs');
const {inspect} = require('node:util');
const {test} = require('node:test');

function facade() {
  const calls = [], requests = [];
  const handle = {contentType: 'native/type', byteLength: 19n};
  const native = {
    preparedForm(fields, maximum) {calls.push({fields, maximum}); return Promise.resolve(handle);},
    preparedMultipart(boundary, fields, maximum) {calls.push({boundary, fields, maximum}); return Promise.resolve(handle);},
    NativeEnvironment: class {client() {return {async close() {}, async request(options) {
      requests.push(options); return {status: 204, headers: [], protocol: 'http1', close() {}};
    }};}},
    NativeCancellation: class {cancel() {}},
  };
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = {exports: loadFacade(filename, native)};
  return {...loaded.exports, native, handle, calls, requests};
}
const options = {method: 'POST', protocol: 'http1', context: 'raw'};

test('prepared owners expose native metadata and attach the same authentic handle on reuse', async () => {
  const {PreparedBody, Client, calls, requests, handle} = facade();
  const pairs = [['tag', 'first'], ['tag', 'last']];
  pairs[Symbol.iterator] = () => {throw new Error('unused iterator');};
  const body = await PreparedBody.form(pairs, {maximumBytes: 1024n});
  assert.ok(Object.isFrozen(body)); assert.equal(body.contentType, 'native/type'); assert.equal(body.byteLength, 19n);
  assert.deepEqual(calls[0], {fields: [{name: 'tag', value: 'first'}, {name: 'tag', value: 'last'}], maximum: 1024n});
  assert.doesNotMatch(inspect(body, {showHidden: true}), /native\/type|first|last/);
  const client = new Client({profile: 'exact', route: 'direct'});
  for (let index = 0; index < 2; index++) (await client.request('http://example.test/', {...options, body, bodyLength: 19n})).close();
  assert.ok(requests.every((request) => request.preparedBody === handle && request.body === undefined));
  await assert.rejects(client.request('http://example.test/', {...options, body, bodyLength: 18}), {code: 'UploadLength'});
  await assert.rejects(client.request('http://example.test/', {...options, body, file: {path: 'unused', maximumBytes: 1}}), {code: 'InvalidArgument'});
  await assert.rejects(client.request('http://example.test/', {...options, body: Object.create(PreparedBody.prototype)}), {code: 'InvalidArgument'});
  assert.equal(requests.length, 2); await client.close();
});

test('multipart snapshots keep duplicate parts and byte views without host framing', async () => {
  const {PreparedBody, calls} = facade();
  const bytes = Buffer.from([0, 255]);
  await PreparedBody.multipart([{name: 'x', text: 'line\nline'}, {name: 'x', bytes, filename: 'a"b', contentType: 'application/custom'}],
    {boundary: 'caller:boundary', maximumBytes: Number.MAX_SAFE_INTEGER});
  assert.equal(calls[0].boundary, 'caller:boundary'); assert.equal(calls[0].maximum, BigInt(Number.MAX_SAFE_INTEGER));
  assert.equal(calls[0].fields[0].text, 'line\nline'); assert.equal(calls[0].fields[1].bytes, bytes);
  assert.equal(calls[0].fields[1].filename, 'a"b'); assert.equal(calls[0].fields[1].contentType, 'application/custom');
});

test('invalid data, explicit limits and native core errors stay precise and redacted', async () => {
  const {PreparedBody, native, calls} = facade();
  for (const maximumBytes of [undefined, null, true, 'private', -1, 0.5, 18446744073709551616n]) {
    await assert.rejects(PreparedBody.form([], {maximumBytes}), {code: 'InvalidArgument'});
  }
  let read = 0;
  const accessor = []; Object.defineProperty(accessor, '0', {get() {read++; throw new Error('private');}});
  for (const pairs of [new Proxy([], {}), accessor, [['x', 1]], [['x']], Array(1)]) {
    await assert.rejects(PreparedBody.form(pairs, {maximumBytes: 1024}), {code: 'InvalidArgument'});
  }
  for (const parts of [[{name: 'x', text: 'x', bytes: Buffer.alloc(0)}], [{name: 'x'}],
    [{name: 'x', get text() {read++; return 'private';}}], [{name: 'x', bytes: new Uint8Array(new SharedArrayBuffer(1))}]]) {
    await assert.rejects(PreparedBody.multipart(parts, {boundary: 'b', maximumBytes: 1024}), {code: 'InvalidArgument'});
  }
  assert.equal(read, 0); assert.equal(calls.length, 0);
  await assert.rejects(PreparedBody.form([['x', 'value']], {maximumBytes: 1}), {code: 'PreparedBody', kind: 'too_large'});
  await assert.rejects(PreparedBody.multipart(Array(1025).fill({name: '', text: ''}), {boundary: 'b', maximumBytes: 1}), {kind: 'too_many_parts'});
  native.preparedForm = () => {throw new Error('PHANTOM_PREPARED:allocation:request body preparation failed');};
  await assert.rejects(PreparedBody.form([], {maximumBytes: 0}), (error) => error.code === 'PreparedBody'
    && error.kind === 'allocation' && !String(error).includes('private'));
});
