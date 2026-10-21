'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadFacade } = require('./load-facade.cjs');
const {test} = require('node:test');

function facade() {
  const controls = [], requests = [];
  const native = {
    NativeEnvironment: class { client() { return {async close() {}, async request(...args) {
      requests.push(args);
      return {status: 200, protocol: 'http1', url: 'http://example.test/', redirects: 0,
        connectionRetries: 0, decodedContentCodings: [], redirectHistory: null, headers: [], close() {}};
    }}; } },
    NativeCancellation: class { cancel() {} },
    NativeAttemptBudget: class {},
    NativeTransferControl: class {
      constructor(options) { this.options = options; this.snapshots = 0; controls.push(this); }
      snapshot() { this.snapshots++; return {uploadReservedBytes: 0n, uploadBodyBytes: 1n,
        downloadReservedBytes: 2n, downloadEncodedBytes: 3n, downloadDecodedBytes: 4n}; }
    },
  };
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = {exports: loadFacade(filename, native)};
  return {...loaded.exports, controls, requests};
}

test('limits preserve exact u64 values, own data and return one frozen bigint snapshot', () => {
  const {TransferControl, controls} = facade();
  const limits = {uploadBytes: 0, downloadBytes: 18446744073709551615n,
    uploadBytesPerSecond: 1, downloadBytesPerSecond: Number.MAX_SAFE_INTEGER};
  const control = new TransferControl(limits); limits.uploadBytes = 10;
  assert.deepEqual({...controls[0].options}, {uploadBytes: 0n, downloadBytes: 18446744073709551615n,
    uploadBytesPerSecond: 1n, downloadBytesPerSecond: 9007199254740991n});
  assert.ok(Object.isFrozen(control));
  const counts = control.snapshot();
  assert.deepEqual(counts, {uploadReservedBytes: 0n, uploadBodyBytes: 1n,
    downloadReservedBytes: 2n, downloadEncodedBytes: 3n, downloadDecodedBytes: 4n});
  assert.ok(Object.isFrozen(counts)); assert.equal(controls[0].snapshots, 1);
  assert.throws(() => { counts.uploadBodyBytes = 2n; }, TypeError);
  new TransferControl();
  assert.deepEqual({...controls[1].options}, {});
});

test('invalid or executable limits fail redacted without invoking getters or native constructors', () => {
  const {TransferControl, controls} = facade();
  let invoked = 0;
  for (const limits of [null, [], true, {unknown: 1}, new Proxy({}, {}),
    {get uploadBytes() { invoked++; throw new Error('private'); }}]) {
    assert.throws(() => new TransferControl(limits), {code: 'InvalidArgument'});
  }
  for (const field of ['uploadBytes', 'downloadBytes', 'uploadBytesPerSecond', 'downloadBytesPerSecond']) {
    for (const value of [null, true, 'private', -1, -1n, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 18446744073709551616n]) {
      assert.throws(() => new TransferControl({[field]: value}), (error) => error.code === 'InvalidArgument' && error.message.includes(field) && !String(error).includes('private'));
    }
  }
  for (const field of ['uploadBytesPerSecond', 'downloadBytesPerSecond']) {
    for (const value of [0, 0n]) assert.throws(() => new TransferControl({[field]: value}), {code: 'InvalidArgument'});
  }
  assert.equal(invoked, 0); assert.equal(controls.length, 0);
  assert.throws(() => TransferControl.prototype.snapshot.call({}), {code: 'InvalidArgument'});
});

test('requests share only authentic native handles separately from attempt budgets', async () => {
  const {Client, TransferControl, AttemptBudget, controls, requests} = facade();
  const first = new Client({profile: 'exact', route: 'direct'});
  const second = new Client({profile: 'exact', route: 'direct'});
  const transfer = new TransferControl({downloadBytes: 4n}); const budget = new AttemptBudget(2);
  const options = {method: 'GET', protocol: 'http1', context: 'raw', transferControl: transfer, attemptBudget: budget};
  for (const client of [first, second]) (await client.request('http://example.test/', options)).close();
  assert.equal(requests.length, 2);
  assert.equal(requests[0][4], controls[0]); assert.equal(requests[1][4], controls[0]);
  assert.equal(requests[0][2], requests[1][2]); assert.notEqual(requests[0][2], controls[0]);
  assert.equal(requests[0][0].transferControl, undefined);
  for (const forged of [{snapshot() {}}, Object.create(TransferControl.prototype), null, 1]) {
    await assert.rejects(first.request('http://example.test/', {...options, transferControl: forged}), {code: 'InvalidArgument'});
  }
  assert.equal(requests.length, 2);
  await first.close(); await second.close();
});
