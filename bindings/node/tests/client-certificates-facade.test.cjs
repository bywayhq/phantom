'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadFacade } = require('./load-facade.cjs');
const {inspect} = require('node:util');
const {test} = require('node:test');

function facade() {
  const calls = [], clients = [];
  const native = {
    NativeEnvironment: class {client(options) {clients.push(options); return {};}},
    clientCertificatePem(chain, key) {const owner = {chain: Buffer.from(chain), key: Buffer.from(key)}; calls.push(owner); return Promise.resolve(owner);},
    clientCertificateDer(chain, key) {const owner = {chain: chain.map((part) => Buffer.from(part)), key: Buffer.from(key)}; calls.push(owner); return Promise.resolve(owner);},
  };
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = {exports: loadFacade(filename, native)};
  return {...loaded.exports, native, calls, clients};
}

test('certificate factories forward ordinary byte views before await and keep owners opaque', async () => {
  const {ClientCertificate, Client, calls, clients} = facade();
  const chain = Buffer.from('chain'), key = Buffer.from('private supplied key');
  const pending = ClientCertificate.fromPem(chain, key);
  chain.fill(0); key.fill(0);
  const owner = await pending;
  assert.equal(calls[0].chain.toString(), 'chain'); assert.equal(calls[0].key.toString(), 'private supplied key');
  assert(Object.isFrozen(owner)); assert.deepEqual(Object.keys(owner), []);
  for (const shown of [String(owner), JSON.stringify(owner), inspect(owner, {showHidden: true})]) assert(!shown.includes('supplied'));
  assert.throws(() => new ClientCertificate(), {code: 'InvalidArgument'});
  new Client({profile: 'exact', route: 'direct', clientCertificate: owner});
  assert.equal(clients[0].clientCertificate, calls[0]);
  const der = await ClientCertificate.fromDer([new Uint8Array([1]), Buffer.from([2])], Buffer.from([3]));
  assert.deepEqual(calls[1].chain, [Buffer.from([1]), Buffer.from([2])]);
  const mappings = [['https://EXAMPLE.com/', owner], ['https://example.com:443', der]];
  new Client({profile: 'exact', route: 'direct', clientCertificatesFor: mappings});
  mappings.reverse(); mappings[0][0] = 'changed';
  assert.deepEqual(clients[1].clientCertificatesFor, [
    {origin: 'https://EXAMPLE.com/', certificate: calls[0]}, {origin: 'https://example.com:443', certificate: calls[1]},
  ]);
});

test('certificate inputs reject executable shared detached and excessive inputs before native parse', async () => {
  const {ClientCertificate, calls} = facade();
  let getters = 0;
  const accessor = []; Object.defineProperty(accessor, '0', {get() {getters++; throw Error('secret');}});
  const shared = new Uint8Array(new SharedArrayBuffer(4));
  Object.defineProperty(shared, 'buffer', {value: new ArrayBuffer(4)});
  const backing = new ArrayBuffer(4), detached = new Uint8Array(backing);
  structuredClone(backing, {transfer: [backing]});
  for (const input of [[], Array(257).fill(Buffer.alloc(1)), accessor, Array(1), new Proxy([], {})]) {
    await assert.rejects(ClientCertificate.fromDer(input, Buffer.alloc(1)));
  }
  for (const input of ['private supplied', shared, detached, new Proxy(Buffer.alloc(1), {})]) {
    await assert.rejects(ClientCertificate.fromPem(input, Buffer.alloc(1)), {code: 'InvalidArgument'});
    await assert.rejects(ClientCertificate.fromDer([Buffer.alloc(1)], input), {code: 'InvalidArgument'});
  }
  const limit = Buffer.alloc(16 * 1024 * 1024);
  await assert.rejects(ClientCertificate.fromPem(limit, Buffer.alloc(1)), {code: 'ClientCertificate', kind: 'too_large'});
  await assert.rejects(ClientCertificate.fromDer([limit], Buffer.alloc(1)), {code: 'ClientCertificate', kind: 'too_large'});
  assert.equal(getters, 0); assert.equal(calls.length, 0);
});

test('certificate option snapshots reject fake owners accessors proxies and excessive origins', async () => {
  const {ClientCertificate, Client, clients} = facade();
  const owner = await ClientCertificate.fromPem(Buffer.alloc(1), Buffer.alloc(1));
  let getters = 0;
  for (const value of [null, {}, Object.create(ClientCertificate.prototype), new Proxy(owner, {})]) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', clientCertificate: value}), {code: 'InvalidArgument'});
  }
  for (const name of ['clientCertificate', 'clientCertificatesFor']) {
    const options = {profile: 'exact', route: 'direct'};
    Object.defineProperty(options, name, {enumerable: true, get() {getters++; throw Error('private');}});
    assert.throws(() => new Client(options), {code: 'InvalidArgument'});
  }
  for (const input of [null, {}, Array(257).fill(['https://example.com', owner]),
    [['x'.repeat(65537), owner]], [['https://example.com', {}]], [[owner]],
    new Proxy([], {})]) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', clientCertificatesFor: input}));
  }
  assert.equal(getters, 0); assert.equal(clients.length, 0);
  new Client({profile: 'exact', route: 'direct'});
  assert.equal(clients[0].clientCertificate, undefined); assert.equal(clients[0].clientCertificatesFor, undefined);
  new Client({profile: 'exact', route: 'direct', clientCertificatesFor: Array(256).fill(['x'.repeat(65536), owner])});
  assert.equal(clients[1].clientCertificatesFor.length, 256);
});

test('native parser causes stay precise and redacted without exposing foreign errors', async () => {
  const {ClientCertificate, native} = facade();
  for (const kind of ['certificate', 'private_key', 'key_mismatch', 'signature_scheme']) {
    native.clientCertificatePem = () => Promise.reject(Error(`PHANTOM_CERTIFICATE:${kind}:client certificate configuration failed`));
    await assert.rejects(ClientCertificate.fromPem(Buffer.from('private supplied'), Buffer.alloc(1)), (error) => {
      assert.equal(error.code, 'ClientCertificate'); assert.equal(error.kind, kind);
      assert.equal(error.cause, undefined);
      for (const shown of [String(error), JSON.stringify(error), inspect(error, {showHidden: true})]) assert(!shown.includes('supplied'));
      return true;
    });
  }
});
