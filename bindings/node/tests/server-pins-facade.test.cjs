'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadFacade } = require('./load-facade.cjs');
const {test} = require('node:test');

function facade() {
  const clients = [];
  const native = {NativeEnvironment: class {client(options) {clients.push(options); return {};}}};
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = {exports: loadFacade(filename, native)};
  return {...loaded.exports, clients};
}

test('pin lists retain supplied duplicates and separate origin from proxy policy', () => {
  const {Client, clients} = facade();
  const origin = [new Uint8Array(32).fill(1)], proxy = Array(32).fill(Buffer.alloc(32, 2));
  new Client({profile: 'exact', route: 'direct', serverSpkiPins: origin, proxyServerSpkiPins: proxy});
  origin.push(Buffer.alloc(32)); proxy.length = 0;
  assert.equal(clients[0].serverSpkiPins.length, 1);
  assert.equal(clients[0].proxyServerSpkiPins.length, 32);
  assert.deepEqual(clients[0].serverSpkiPins, [Buffer.alloc(32, 1)]);
  assert.deepEqual(clients[0].proxyServerSpkiPins, Array(32).fill(Buffer.alloc(32, 2)));
  new Client({profile: 'exact', route: 'direct'});
  assert.equal(clients[1].serverSpkiPins, undefined);
  assert.equal(clients[1].proxyServerSpkiPins, undefined);
});

test('invalid counts, bytes and shared backing fail before native construction', () => {
  const {Client, clients, PhantomError} = facade();
  const shared = new Uint8Array(new SharedArrayBuffer(32));
  Object.defineProperty(shared, 'buffer', {value: new ArrayBuffer(32)});
  const backing = new ArrayBuffer(32), detached = new Uint8Array(backing);
  structuredClone(backing, {transfer: [backing]});
  for (const field of ['serverSpkiPins', 'proxyServerSpkiPins']) {
    for (const input of [null, 'private-pin', {}, [], Array(33).fill(Buffer.alloc(32)),
      [Buffer.alloc(0)], [Buffer.alloc(31)], [Buffer.alloc(33)], ['private-pin'],
      [Buffer.alloc(64).toString('hex')], [shared], [detached], [new Proxy(Buffer.alloc(32), {})]]) {
      assert.throws(() => new Client({profile: 'exact', route: 'direct', [field]: input}), (error) => {
        assert(error instanceof PhantomError); assert.equal(error.code, 'InvalidArgument');
        assert.ok(error.message.includes(field));
        for (const shown of [String(error), JSON.stringify(error), require('node:util').inspect(error, {showHidden: true})]) {
          assert.ok(!shown.includes('private-pin'));
        }
        return true;
      });
    }
  }
  assert.equal(clients.length, 0);
});

test('executable pin options and arrays are rejected without invoking getters', () => {
  const {Client, clients} = facade();
  let calls = 0;
  const accessor = []; Object.defineProperty(accessor, '0', {get() {calls++; throw new Error('private');}});
  const extra = [Buffer.alloc(32)]; Object.defineProperty(extra, 'extra', {get() {calls++; throw new Error('private');}});
  for (const field of ['serverSpkiPins', 'proxyServerSpkiPins']) {
    const options = {profile: 'exact', route: 'direct'};
    Object.defineProperty(options, field, {enumerable: true, get() {calls++; throw new Error('private');}});
    assert.throws(() => new Client(options), {code: 'InvalidArgument'});
    for (const input of [accessor, extra, Array(1), new Proxy([Buffer.alloc(32)], {})]) {
      assert.throws(() => new Client({profile: 'exact', route: 'direct', [field]: input}), {code: 'InvalidArgument'});
    }
  }
  assert.throws(() => new Client(new Proxy({profile: 'exact', route: 'direct'}, {
    get() {calls++; throw new Error('private');}, getOwnPropertyDescriptor() {calls++; throw new Error('private');},
  })), {code: 'InvalidArgument'});
  assert.equal(calls, 0); assert.equal(clients.length, 0);
});
