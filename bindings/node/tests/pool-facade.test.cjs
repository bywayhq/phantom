'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const {test} = require('node:test');

function facade() {
  const calls = [];
  const native = {NativeEnvironment: class {client(options) {calls.push(options); return {};}}};
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = new Module(filename, module);
  loaded.filename = filename; loaded.paths = module.paths;
  loaded.require = (id) => id === './phantom.node' ? native
    : id === 'node:fs' ? {...fs, existsSync: (file) => file === path.join(path.dirname(filename), 'phantom.node') || fs.existsSync(file)}
    : Module.createRequire(filename)(id);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return {...loaded.exports, calls};
}

test('pool overrides snapshot data and preserve omitted and zero-wait choices', () => {
  const {Client, calls} = facade();
  new Client({profile: 'exact', route: 'direct'});
  assert.equal(calls[0].pool, undefined);
  new Client({profile: 'exact', route: 'direct', pool: {}});
  assert.deepEqual(calls[1].pool, {});
  const pool = {maxConcurrentHttp1RequestsPerOrigin: 2, maxHttp2ConnectionsPerOrigin: 9,
    maxPendingHttp3RequestsPerOrigin: undefined, negotiatedSetupWaitLimitMs: 0};
  new Client({profile: 'exact', route: 'direct', pool});
  pool.maxConcurrentHttp1RequestsPerOrigin = 99;
  assert.deepEqual(calls[2].pool, {maxConcurrentHttp1RequestsPerOrigin: 2,
    maxHttp2ConnectionsPerOrigin: 9, negotiatedSetupWaitLimitMs: 0});
  assert(Object.isFrozen(calls[2].pool));
});

test('pool data rejects malformed numbers and executable fields without invoking them', () => {
  const {Client, calls} = facade(); let invoked = 0;
  const getter = {}; Object.defineProperty(getter, 'maxRetainedHttp1Connections', {get() {invoked++; throw Error('private');}});
  const outer = {profile: 'exact', route: 'direct'};
  Object.defineProperty(outer, 'pool', {enumerable: true, get() {invoked++; throw Error('private');}});
  assert.throws(() => new Client(outer), {code: 'InvalidArgument'});
  for (const pool of [null, [], new Proxy({}, {}), getter, {unknown: 1}, {[Symbol('private')]: 1},
    ...[0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, true, '2', 2n, null]
      .map((maxRetainedHttp1Connections) => ({maxRetainedHttp1Connections})),
    {negotiatedSetupWaitLimitMs: -1}, {negotiatedSetupWaitLimitMs: 0.5}]) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', pool}), (error) => {
      assert.equal(error.code, 'InvalidArgument'); assert(!String(error).includes('private')); return true;
    });
  }
  assert.equal(invoked, 0); assert.equal(calls.length, 0);
});
