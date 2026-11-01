'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { loadFacade } = require('./load-facade.cjs');
const {test} = require('node:test');

function facade() {
  const calls = [];
  const restored = {async close() { calls.push(['closed']); }};
  const owner = {async exportSession(key) { calls.push(['export', Buffer.from(key)]); return Buffer.from('ciphertext'); }};
  const native = {NativeEnvironment: class {
    client() { calls.push(['client']); return owner; }
    async restoreSession(source, bytes, key, routes) {
      calls.push(['restore', source, Buffer.from(bytes), Buffer.from(key), routes]);
      return restored;
    }
  }};
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = {exports: loadFacade(filename, native)};
  return {...loaded.exports, calls, owner};
}
const key = Buffer.alloc(32, 0x61);

test('checkpoint facade wraps independent native clients without reparsing configuration', async () => {
  const {Client, calls, owner} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const bytes = await client.exportSession(key);
  const restored = await client.restoreSession(bytes, key, {receivingRoutes: [
    {route: 'direct'}, {route: 'proxy', proxy: 'http://proxy.test', proxyUsername: 'user', proxyPassword: 'password'},
  ]});
  await restored.close();
  assert.deepEqual(calls[1], ['export', key]);
  assert.equal(calls[2][1], owner);
  assert.deepEqual(calls[2][2], Buffer.from('ciphertext'));
  assert.deepEqual(calls[2][3], key);
  assert.deepEqual({...calls[2][4][1]}, {route: 'proxy', proxy: 'http://proxy.test', proxyUsername: 'user', proxyPassword: 'password'});
  assert.equal(calls.filter((call) => call[0] === 'client').length, 1);
  await client.restoreSession(bytes, key);
  assert.deepEqual(calls.at(-1)[4], []);
});

test('checkpoint options reject nondata routes before native submission', async () => {
  const {Client, calls} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  const accessor = {get receivingRoutes() { throw new Error('must not run'); }};
  const entries = []; Object.defineProperty(entries, '0', {get() { throw new Error('must not run'); }});
  const route = {route: 'proxy', get proxy() { throw new Error('must not run'); }};
  for (const options of [null, accessor, {signal: new AbortController().signal}, {receivingRoutes: null},
    {receivingRoutes: entries}, {receivingRoutes: [route]}, {receivingRoutes: [{route: 'direct', proxy: 'private'}]},
    {receivingRoutes: [{route: 'proxy', proxy: 'private', proxyUsername: 'private'}]}, {receivingRoutes: new Array(1)},
    {receivingRoutes: new Proxy([], {})}, {receivingRoutes: [{route: 'unknown'}]}]) {
    await assert.rejects(client.restoreSession(Buffer.alloc(0), key, options), (error) => error.code === 'InvalidArgument' && !String(error).includes('private'));
  }
  await assert.rejects(client.restoreSession(Buffer.alloc(0), key, {receivingRoutes: Array(257).fill({route: 'direct'})}), (error) => error.code === 'SessionSnapshot' && error.kind === 'too_large');
  assert.equal(calls.length, 1);
});

test('checkpoint native categories are redacted and remain distinguishable', async () => {
  const {Client, owner, PhantomError} = facade(); const client = new Client({profile: 'exact', route: 'direct'});
  owner.exportSession = async () => { throw new Error('PHANTOM_SNAPSHOT:unsupported:session checkpoint failed'); };
  await assert.rejects(client.exportSession(key), (error) => error instanceof PhantomError
    && error.code === 'SessionSnapshot' && error.kind === 'unsupported' && error.protocol === undefined);
  for (const length of [0, 31, 33]) {
    await assert.rejects(client.exportSession(Buffer.alloc(length)), (error) => error.code === 'SessionSnapshot' && error.kind === 'invalid_key_length');
  }
});


const cookieEntry = (overrides = {}) => ({sourceScheme: 'https', name: 'state', value: 'private',
  domain: 'example.test', path: '/', hostOnly: true, secure: true, httpOnly: true,
  sameSite: 'lax', partitionKey: null, expiresAtNanoseconds: null, ...overrides});
const alternative = (overrides = {}) => ({origin: 'https://example.test', alternativeHost: 'alt.example.test',
  alternativePort: 443, expiresAtNanoseconds: 2000000000123456789n, ...overrides});

test('typed standalone state preserves order, exact expiry and disabled versus empty', () => {
  const {Client, owner} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  owner.exportCookies = () => undefined; owner.exportAltSvc = () => undefined;
  assert.equal(client.exportCookies(), null); assert.equal(client.exportAltSvc(), null);
  owner.exportCookies = () => []; owner.exportAltSvc = () => [];
  assert.deepEqual(client.exportCookies(), []); assert.deepEqual(client.exportAltSvc(), []);
  const cookies = [cookieEntry(), cookieEntry({name: 'second', expiresAtNanoseconds: -123456789n})];
  owner.importCookies = (entries) => {
    assert.deepEqual(entries, cookies); assert.notEqual(entries, cookies);
    assert(Object.isFrozen(entries[0]));
  };
  client.importCookies(cookies);
  owner.exportCookies = () => cookies;
  const exported = client.exportCookies();
  assert(Object.isFrozen(exported)); assert(Object.isFrozen(exported[0]));
  assert.deepEqual(exported, cookies);
  owner.importAltSvc = (entries) => assert.deepEqual(entries, [alternative()]);
  client.importAltSvc([alternative()]);
});

test('typed imports reject malformed and executable data before native mutation', () => {
  const {Client, owner} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  let calls = 0, getters = 0;
  owner.importCookies = owner.importAltSvc = () => calls++;
  const bad = cookieEntry(); Object.defineProperty(bad, 'value', {get() { getters++; return 'secret'; }});
  for (const entries of [[bad], [cookieEntry({secure: 1})], [cookieEntry({sameSite: 'invented'})],
    [cookieEntry({partitionKey: undefined})], [cookieEntry({value: '\ud800'})], Array(1)]) {
    assert.throws(() => client.importCookies(entries));
  }
  for (const expiry of [0, 1.5, NaN, Infinity, undefined, 1n << 128n, -(1n << 128n)]) {
    assert.throws(() => client.importCookies([cookieEntry({expiresAtNanoseconds: expiry})]));
    assert.throws(() => client.importAltSvc([alternative({expiresAtNanoseconds: expiry})]));
  }
  for (const port of [0, -1, 65536, 1.5, 4294967297]) {
    assert.throws(() => client.importAltSvc([alternative({alternativePort: port})]));
  }
  assert.equal(getters, 0); assert.equal(calls, 0);
});

test('standalone admission supports default jar capacity and bounds aggregate UTF-8', () => {
  const {Client, owner} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  let calls = 0;
  owner.importCookies = (entries) => { calls++; assert.equal(entries.length, 3300); };
  client.importCookies(Array.from({length: 3300}, (_, index) => cookieEntry({name: `c${index}`, value: 'x'.repeat(4000)})));
  assert.equal(calls, 1);
  assert.throws(() => client.importCookies(Array(16385).fill(cookieEntry())), (error) => error.kind === 'too_large');
  assert.throws(() => client.importAltSvc(Array(32769).fill(alternative())), (error) => error.kind === 'too_large');
  assert.throws(() => client.importCookies([cookieEntry({value: '\u00e9'.repeat(16 * 1024 * 1024)})]), (error) => error.kind === 'too_large');
  assert.equal(calls, 1);
});

test('core import failure categories and zero-based index survive without values', async () => {
  const {Client, owner, PhantomError} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  owner.importCookies = () => { throw new Error('PHANTOM_STATE:CookieSnapshot:invalid_prefix:0:state transfer failed'); };
  assert.throws(() => client.importCookies([cookieEntry()]), (error) => error instanceof PhantomError
    && error.code === 'CookieSnapshot' && error.kind === 'invalid_prefix' && error.entryIndex === 0
    && !String(error).includes('private'));
  owner.importAltSvc = () => { throw new Error('PHANTOM_STATE:AltSvcSnapshot:noncanonical_origin:1:state transfer failed'); };
  assert.throws(() => client.importAltSvc([alternative()]), (error) => error.code === 'AltSvcSnapshot' && error.entryIndex === 1);
  owner.importSessionTickets = async () => { throw new Error('PHANTOM_STATE:SessionTickets:authentication::state transfer failed'); };
  await assert.rejects(client.importSessionTickets(Buffer.from('ciphertext'), key), (error) => error.code === 'SessionTickets'
    && error.kind === 'authentication' && error.entryIndex === undefined);
});

test('ticket-only facade uses installed owner and exact receiving routes with bounded bytes', async () => {
  const {Client, owner} = facade(), client = new Client({profile: 'exact', route: 'direct'});
  const ciphertext = Buffer.from('sealed-ticket-state'); let calls = 0;
  owner.exportSessionTickets = async (actualKey) => { calls++; assert.deepEqual(actualKey, key); return ciphertext; };
  owner.importSessionTickets = async (bytes, actualKey, routes) => {
    calls++; assert.deepEqual(bytes, ciphertext); assert.deepEqual(actualKey, key); assert.deepEqual(routes.map((route) => ({...route})), [{route: 'direct'}]);
  };
  assert.equal(await client.exportSessionTickets(key), ciphertext);
  await client.importSessionTickets(ciphertext, key, {receivingRoutes: [{route: 'direct'}]});
  for (const length of [0, 31, 33]) await assert.rejects(client.exportSessionTickets(Buffer.alloc(length)),
    (error) => error.code === 'SessionTickets' && error.kind === 'invalid_key_length');
  await assert.rejects(client.importSessionTickets(Buffer.alloc(16 * 1024 * 1024 + 1), key),
    (error) => error.code === 'SessionTickets' && error.kind === 'too_large');
  await assert.rejects(client.importSessionTickets(ciphertext, key, {receivingRoutes: Array(257).fill({route: 'direct'})}),
    (error) => error.code === 'SessionTickets' && error.kind === 'too_large');
  await assert.rejects(client.importSessionTickets(ciphertext, key, {receivingRoutes: [{route: 'direct', proxy: 'http://private'}]}));
  assert.equal(calls, 2);
});
