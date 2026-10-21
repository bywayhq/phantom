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

test('network settings snapshot ordered duplicates and intentional empty overrides', () => {
  const {Client, calls} = facade();
  const network = {hostOverrides: [{host: 'EXAMPLE.invalid', addresses: []},
    {host: 'example.invalid', addresses: ['::1', '127.0.0.1']}],
  localAddresses: ['127.0.0.1', '::1'], interface: 'lo'};
  new Client({profile: 'exact', route: 'direct', network});
  network.hostOverrides[1].addresses.reverse(); network.hostOverrides.length = 0;
  network.localAddresses[0] = 'changed'; network.interface = 'changed';
  assert.deepEqual(calls[0].network, {hostOverrides: [{host: 'EXAMPLE.invalid', addresses: []},
    {host: 'example.invalid', addresses: ['::1', '127.0.0.1']}],
  localAddresses: ['127.0.0.1', '::1'], interface: 'lo'});
  assert(Object.isFrozen(calls[0].network));
  assert(Object.isFrozen(calls[0].network.hostOverrides[1].addresses));
  new Client({profile: 'exact', route: 'direct'});
  assert.equal(calls[1].network, undefined);
  new Client({profile: 'exact', route: 'direct', network: {}});
  assert.deepEqual(calls[2].network, {hostOverrides: [], localAddresses: [], interface: undefined});
});

test('network data rejects executable or malformed structures before native construction', () => {
  const {Client, calls} = facade(); let getters = 0;
  const accessor = {}; Object.defineProperty(accessor, 'interface', {get() {getters++; throw Error('private input');}});
  const entryAccessor = []; Object.defineProperty(entryAccessor, '0', {get() {getters++; throw Error('private input');}});
  const outer = {profile: 'exact', route: 'direct'};
  Object.defineProperty(outer, 'network', {enumerable: true, get() {getters++; throw Error('private input');}});
  assert.throws(() => new Client(outer), {code: 'InvalidArgument'});
  for (const network of [null, [], new Proxy({}, {}), accessor, {unknown: 1},
    {hostOverrides: null}, {localAddresses: null}, {localAddresses: Array(1)},
    {hostOverrides: entryAccessor}, {hostOverrides: [{host: 'private input'}]},
    {hostOverrides: [{host: 'private input', addresses: [], extra: true}]},
    {interface: {toString() {throw Error('private input');}}}]) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', network}), (error) => {
      assert.equal(error.code, 'InvalidArgument'); assert(!String(error).includes('private input')); return true;
    });
  }
  assert.equal(getters, 0); assert.equal(calls.length, 0);
});

test('network entry and UTF-8 limits apply to aggregate data before native construction', () => {
  const {Client, calls} = facade();
  new Client({profile: 'exact', route: 'direct', network: {hostOverrides: [{host: 'x'.repeat(65536), addresses: []}]}});
  new Client({profile: 'exact', route: 'direct', network: {localAddresses: Array(1024).fill('')}});
  for (const network of [{interface: 'é'.repeat(32769)},
    {hostOverrides: [{host: 'x'.repeat(65536), addresses: ['x']}]},
    {hostOverrides: Array(1024).fill({host: '', addresses: ['']})},
    {hostOverrides: [{host: '', addresses: Array(1024).fill('')}], localAddresses: ['']}]) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', network}));
  }
  assert.equal(calls.length, 2);
});

test('Unix socket paths are copied without expansion and share the network byte budget', () => {
  const {Client, calls} = facade();
  const network = {unixSocket: '~/socket.sock'};
  new Client({profile: 'exact', route: 'direct', network});
  network.unixSocket = 'changed';
  assert.equal(calls[0].network.unixSocket, '~/socket.sock');
  assert(Object.isFrozen(calls[0].network));
  new Client({profile: 'exact', route: 'direct', network: {unixSocket: 'x'.repeat(65536)}});
  for (const unixSocket of ['', null, Buffer.from('/socket'), '\ud800', 'private\0path']) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', network: {unixSocket}}), (error) => {
      assert.equal(error.code, 'InvalidArgument'); assert(!String(error).includes('private')); return true;
    });
  }
  assert.throws(() => new Client({profile: 'exact', route: 'direct', network: {
    unixSocket: 'x'.repeat(65536), interface: 'x',
  }}), {code: 'InputLimit'});
  let getters = 0;
  assert.throws(() => new Client({profile: 'exact', route: 'direct', network: {
    get unixSocket() {getters++; return '/socket';},
  }}), {code: 'InvalidArgument'});
  assert.equal(getters, 0); assert.equal(calls.length, 2);
});
