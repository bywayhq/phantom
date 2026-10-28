'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {loadFacade} = require('./load-facade.cjs');

function facade() {
  const calls = [];
  const native = {NativeEnvironment: class {client(options) {calls.push(options); return {};}}};
  return {...loadFacade(path.resolve(__dirname, '../index.cjs'), native), calls};
}
function https(changes = {}) {
  return {kind: 'https', endpoint: 'https://private.invalid/query', bootstrap: ['127.0.0.1'],
    timeoutMs: 1000, maxConcurrent: 4, ...changes};
}
function tls(changes = {}) {
  return {kind: 'tls', serverName: 'private.invalid', bootstrap: ['127.0.0.1:853'],
    timeoutMs: 1000, maxConcurrent: 4n, ...changes};
}

test('encrypted DNS snapshots ordered data and preserves cache and padding absence states', () => {
  const {Client, calls} = facade();
  const dns = https({wire: 'chromium154', queryId: 27});
  new Client({profile: 'exact', route: 'direct', network: {dns, dnsCache: false}});
  dns.bootstrap[0] = 'changed';
  dns.endpoint = 'changed';
  assert.deepEqual(calls[0].network.dns, {kind: 'https', endpoint: 'https://private.invalid/query',
    bootstrap: ['127.0.0.1'], timeoutMs: 1000, maxConcurrent: 4n, families: 'dual', roots: [],
    paddingBlock: 'inherit', method: 'post', wire: 'chromium154', queryId: 27});
  assert.equal(calls[0].network.dnsCache, false);
  assert(Object.isFrozen(calls[0].network.dns));
  assert(Object.isFrozen(calls[0].network.dns.bootstrap));
  for (const paddingBlock of [undefined, null, 64]) {
    new Client({profile: 'exact', route: 'direct', network: {dns: tls({paddingBlock})}});
    assert.equal(calls.at(-1).network.dns.paddingBlock, paddingBlock === undefined ? 'inherit' : paddingBlock);
    assert.equal(calls.at(-1).network.dnsCache, undefined);
  }
});

test('DNS rejects executable data, transport-mismatched fields and invalid bounds before native calls', () => {
  const {Client, calls} = facade();
  let getters = 0;
  const executable = https();
  Object.defineProperty(executable, 'bootstrap', {get() {getters++; throw Error('private');}});
  const executableArray = [];
  Object.defineProperty(executableArray, '0', {get() {getters++; throw Error('private');}});
  for (const dns of [null, new Proxy(https(), {}), executable, https({bootstrap: executableArray}),
    https({kind: 'private'}), https({serverName: 'private'}), tls({method: 'get'}),
    tls({queryId: 0}), tls({wire: 'standard'}), https({timeoutMs: 0}),
    https({timeoutMs: NaN}), https({timeoutMs: true}), https({maxConcurrent: 0}),
    https({maxConcurrent: 1.5}), https({maxConcurrent: true}), tls({maxConcurrent: 32768}),
    https({families: 'ipv6'}), https({method: 'auto'}), https({wire: 'private'}),
    https({queryId: 65536}), https({queryId: -1}), https({paddingBlock: 0}),
    https({paddingBlock: false}), https({paddingBlock: 'inherit'}), https({bootstrap: []}), https({bootstrap: Array(1)}),
    https({endpoint: 'private\ud800'}), https({roots: [new Uint8Array(new SharedArrayBuffer(1))]})]) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', network: {dns}}), (error) => {
      assert(!String(error).includes('private'));
      return true;
    });
  }
  for (const dnsCache of [true, null, 0]) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', network: {dnsCache}}));
  }
  assert.equal(getters, 0);
  assert.equal(calls.length, 0);
});

test('DNS aggregates UTF-8, DER and entry sizes before construction and rejects detached roots', () => {
  const {Client, calls} = facade();
  const detached = new Uint8Array(8);
  structuredClone(detached.buffer, {transfer: [detached.buffer]});
  for (const dns of [https({endpoint: 'é'.repeat(32769)}),
    https({roots: [Buffer.alloc(65536)]}), https({bootstrap: Array(1025).fill('')}),
    https({bootstrap: Array(1024).fill(''), roots: [Buffer.alloc(0)]}),
    https({roots: [detached]})]) {
    assert.throws(() => new Client({profile: 'exact', route: 'direct', network: {dns}}));
  }
  assert.equal(calls.length, 0);
});
