'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const {test} = require('node:test');

function facade() {
  const requests = [];
  const native = {
    NativeEnvironment: class {client() {return {async close() {}, async request(options) {
      requests.push(options);
      return {status: 204, headers: [], protocol: 'http1', url: 'http://example.test/', redirects: 0,
        connectionRetries: 0, decodedContentCodings: [], redirectHistory: null, close() {}};
    }};}},
    NativeCancellation: class {cancel() {}},
  };
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = new Module(filename, module); loaded.filename = filename; loaded.paths = module.paths;
  loaded.require = (id) => id === './phantom.node' ? native
    : id === 'node:fs' ? {...fs, existsSync: (file) => file === path.join(path.dirname(filename), 'phantom.node') || fs.existsSync(file)}
    : Module.createRequire(filename)(id);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return {...loaded.exports, requests};
}
const options = {method: 'GET', protocol: 'http1', context: 'raw'};

test('request controls preserve exact waits, duplicate order, sensitivity and absence', async () => {
  const {Client, requests} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  const trailers = [{name: 'X-Repeat', value: Buffer.from('first'), sensitive: true},
    {name: 'x-other', value: Buffer.from('middle')}, {name: 'X-Repeat', value: Buffer.from('last')}];
  for (const wait of [0, 0n, Number.MAX_SAFE_INTEGER, 18446744073709551615n]) {
    (await client.request('http://example.test/', {...options, trailers, expectContinueMs: wait})).close();
    assert.equal(requests.at(-1).expectContinueMs, BigInt(wait));
    assert.deepEqual(requests.at(-1).trailers.map((field) => ({...field})), trailers);
    assert.notEqual(requests.at(-1).trailers, trailers); assert.notEqual(requests.at(-1).trailers[0], trailers[0]);
  }
  (await client.request('http://example.test/', options)).close();
  assert.equal(requests.at(-1).trailers, undefined); assert.equal(requests.at(-1).expectContinueMs, undefined);
  let reads = 0;
  (await client.request('http://example.test/', {...options,
    headers: [{name: 'x-existing', get value() {reads++; return Buffer.from('value');}}]})).close();
  assert.ok(reads > 0); assert.equal(requests.at(-1).headers[0].value.toString(), 'value');
  await client.close();
});

test('invalid waits and executable trailer records fail with field-specific redacted errors', async () => {
  const {Client, requests} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  for (const value of [null, true, 'private', -1, -1n, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 18446744073709551616n]) {
    await assert.rejects(client.request('http://example.test/', {...options, expectContinueMs: value}),
      (error) => error.code === 'InvalidArgument' && error.message.includes('expectContinueMs') && !String(error).includes('private'));
  }
  let invoked = 0;
  for (const trailers of [null, {}, new Proxy([], {}), [{name: 'x', get value() {invoked++; throw new Error('private');}}],
    [{name: 'x', value: Buffer.alloc(0), sensitive: 1}], [{name: 1, value: Buffer.alloc(0)}]]) {
    await assert.rejects(client.request('http://example.test/', {...options, trailers}), {code: 'InvalidArgument'});
  }
  assert.equal(invoked, 0); assert.equal(requests.length, 0); await client.close();
});

test('headers and trailers share count and byte caps before native requests', async () => {
  const {Client, requests} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  const field = {name: 'x', value: Buffer.alloc(0)};
  (await client.request('http://example.test/', {...options, headers: Array(255).fill(field), trailers: [field]})).close();
  await assert.rejects(client.request('http://example.test/', {...options, headers: Array(256).fill(field), trailers: [field]}), {code: 'InputLimit'});
  (await client.request('http://example.test/', {...options, headers: [{name: 'x', value: Buffer.alloc(65534)}], trailers: [field]})).close();
  await assert.rejects(client.request('http://example.test/', {...options, headers: [{name: 'x', value: Buffer.alloc(65535)}], trailers: [field]}), {code: 'InputLimit'});
  assert.equal(requests.length, 2); await client.close();
});
