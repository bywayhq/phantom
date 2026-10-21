'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
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
  const loaded = new Module(filename, module);
  loaded.filename = filename; loaded.paths = module.paths;
  loaded.require = (id) => id === './phantom.node' ? native
    : id === 'node:fs' ? {...fs, existsSync: (file) => file === path.join(path.dirname(filename), 'phantom.node') || fs.existsSync(file)}
    : Module.createRequire(filename)(id);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
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
