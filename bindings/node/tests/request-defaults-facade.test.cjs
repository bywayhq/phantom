'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const { inspect } = require('node:util');

const { loadFacade } = require('./load-facade.cjs');

function facade() {
  const requests = [];
  const clients = [];
  const owner = () => ({
    async close() {},
    async request(options) {
      requests.push(options);
      return {status: 204, headers: [], protocol: 'http1', url: options.url, redirects: 0,
        connectionRetries: 0, decodedContentCodings: [], redirectHistory: null, close() {}};
    },
  });
  const native = {
    NativeEnvironment: class {
      client(options) { clients.push(options); return owner(); }
      fork() { return owner(); }
      async restoreSession() { return owner(); }
    },
    NativeCancellation: class {cancel() {}},
    profileCatalog(_identifier, context) { return {contexts: context === undefined ? ['raw', 'navigation'] : ['raw', 'profile', 'navigation']}; },
    preparedEncoded(input, contentType) { return {bytes: Buffer.from(input), contentType, byteLength: BigInt(input.length)}; },
  };
  return {...loadFacade(path.resolve(__dirname, '../index.cjs'), native), requests, clients};
}

test('client defaults are immutable, ordered and inherited by fork and restore', async () => {
  const {Client, requests, clients} = facade();
  const first = Buffer.from('one');
  const headers = [{name: 'X-First', value: first}, {name: 'X-Replace', value: Buffer.from('old')},
    {name: 'X-Last', value: Buffer.from('last')}];
  const config = {profile: 'exact', route: 'direct', context: 'raw', protocol: 'http1', headers};
  const client = new Client(config);
  first.fill(0); headers[0].name = 'changed'; headers.push({name: 'late', value: first});
  config.context = 'navigation'; config.protocol = 'http3';
  assert.equal(clients[0].context, undefined);
  assert.equal(clients[0].headers, undefined);
  const fork = client.fork();
  const restored = await client.restoreSession(Buffer.alloc(0), Buffer.alloc(32));
  for (const caller of [client, fork, restored]) {
    (await caller.get('http://example.test/', {headers: [
      {name: 'x-replace', value: Buffer.from('new')}, {name: 'x-replace', value: Buffer.from('again')},
    ]})).close();
    assert.equal(requests.at(-1).method, 'GET');
    assert.equal(requests.at(-1).protocol, 'http1');
    assert.equal(requests.at(-1).context, 'raw');
    assert.deepEqual(requests.at(-1).headers.map(({name, value}) => [name, value.toString()]), [
      ['X-First', 'one'], ['X-Last', 'last'], ['x-replace', 'new'], ['x-replace', 'again'],
    ]);
    await caller.close();
  }
});

test('negotiated protocol and attached templates are defaults without guessing a request context', async () => {
  const {Client, Profile, requests} = facade();
  const client = new Client({profile: Profile.fromCatalog('exact', 'navigation'), route: 'direct'});
  (await client.request('http://example.test/')).close();
  assert.equal(requests[0].protocol, 'negotiated');
  assert.equal(requests[0].context, 'profile');
  (await client.get('http://example.test/', {protocol: 'http2', context: 'raw'})).close();
  assert.equal(requests[1].protocol, 'http2');
  assert.equal(requests[1].context, 'raw');
  const unselected = new Client({profile: 'exact', route: 'direct'});
  await assert.rejects(unselected.get('http://example.test/'), {code: 'InvalidArgument'});
  (await unselected.get('http://example.test/', {context: 'navigation'})).close();
  assert.equal(requests[2].context, 'navigation');
  assert.equal(requests.length, 3);
  await client.close(); await unselected.close();
});

test('method helpers share JSON, UTF-8, form and ordered query preparation', async () => {
  const {Client, requests} = facade();
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  (await client.post('child?raw=%20#part', {json: {word: 'café'}, query: [['tag', 'a b'], ['tag', '+']]})).close();
  assert.equal(requests[0].url, 'child?raw=%20&tag=a+b&tag=%2B#part');
  assert.equal(requests[0].preparedBody.bytes.toString(), '{"word":"café"}');
  assert.equal(requests[0].body, undefined);
  assert.equal(requests[0].preparedBody.contentType, 'application/json');
  assert.equal(requests[0].headers[0].value.toString(), 'application/json');
  (await client.put(new URL('https://example.test/'), {body: 'π'})).close();
  assert.equal(requests[1].url, 'https://example.test/');
  assert.equal(requests[1].preparedBody.bytes.toString('hex'), 'cf80');
  assert.equal(requests[1].headers[0].value.toString(), 'text/plain;charset=UTF-8');
  (await client.patch('/form', {form: new URLSearchParams([['field', 'one'], ['field', 'a b']]),
    headers: [{name: 'content-type', value: Buffer.from('application/x-www-form-urlencoded;charset=UTF-8')}]})).close();
  assert.equal(requests[2].preparedBody.bytes.toString(), 'field=one&field=a+b');
  assert.equal(requests[2].headers.length, 1);
  for (const method of ['get', 'head', 'delete', 'options']) {
    (await client[method]('/')).close();
    assert.equal(requests.at(-1).method, method.toUpperCase());
  }
  (await client.request('/custom', {method: 'PURGE', body: Buffer.from('raw')})).close();
  assert.equal(requests.at(-1).method, 'PURGE');
  assert.equal(requests.at(-1).headers, undefined);
  await client.close();
});

test('invalid convenience input fails before native admission without leaking values', async () => {
  const {Client, requests} = facade();
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  const cycle = {}; cycle.self = cycle;
  for (const options of [{body: '', json: null}, {json: 1, form: []}, {file: {path: 'private', maximumBytes: 1}, json: {}},
    {multipart: {}, form: []}, {json: true, bodyLength: 4}, {form: [['x', 1]]}, {query: 'private'},
    {protocol: null}, {context: null}]) {
    await assert.rejects(client.request('/private', options), (error) =>
      ['InvalidArgument', 'InvalidContext', 'InvalidProtocol'].includes(error.code) && !String(error).includes('private'));
  }
  await assert.rejects(client.post('/', {json: cycle}), {code: 'JsonEncode'});
  await assert.rejects(client.post('/', {json: 1n}), {code: 'JsonEncode'});
  await assert.rejects(client.post('/', {json: () => {}}), {code: 'JsonEncode'});
  await assert.rejects(client.get('/', null), {code: 'InvalidArgument'});
  const cause = new Error('private');
  await assert.rejects(client.post('/', {json: {toJSON() {throw cause;}}}), (error) => {
    assert.equal(error.cause, cause);
    assert.ok(!String(error).includes('private'));
    assert.ok(!inspect(error).includes('private'));
    assert.ok(!JSON.stringify(error).includes('private'));
    return error.code === 'JsonEncode';
  });
  assert.equal(requests.length, 0);
  await client.close();
});

test('default and generated fields retain combined header and body limits', async () => {
  const {Client, requests} = facade();
  const field = {name: 'x', value: Buffer.alloc(0)};
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw', headers: Array(256).fill(field)});
  await assert.rejects(client.post('/', {json: true}), {code: 'InputLimit'});
  await assert.rejects(client.get('/', {trailers: [field]}), {code: 'InputLimit'});
  const bare = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  await assert.rejects(bare.post('/', {body: 'é'.repeat(8 * 1024 * 1024 + 1)}), {code: 'InputLimit'});
  await assert.rejects(bare.get('/', {query: [['x', 'a'.repeat(65536)]]}), {code: 'InputLimit'});
  assert.equal(requests.length, 0);
  await client.close(); await bare.close();
});

test('oversized form and query fields reject before allocating escaped output', async (t) => {
  const {Client, requests} = facade();
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  const encoding = t.mock.method(URLSearchParams.prototype, 'toString', () => {throw new Error('encoder must not run');});
  await assert.rejects(client.get('/', {query: [['name', 'x'.repeat(65536)]]}), {code: 'InputLimit'});
  await assert.rejects(client.post('/', {form: [['name', 'x'.repeat(16 * 1024 * 1024)]]}), {code: 'InputLimit'});
  assert.equal(encoding.mock.calls.length, 0);
  assert.equal(requests.length, 0);
  await client.close();
});
