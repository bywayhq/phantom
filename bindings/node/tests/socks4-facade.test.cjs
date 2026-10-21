'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const {test} = require('node:test');

function facade() {
  const calls = [];
  const owner = {};
  const native = {NativeEnvironment: class {
    client(options) {calls.push(options); return owner;}
    async restoreSession(...args) {calls.push(args); return owner;}
  }};
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = new Module(filename, module);
  loaded.filename = filename; loaded.paths = module.paths;
  loaded.require = (id) => id === './phantom.node' ? native
    : id === 'node:fs' ? {...fs, existsSync: (file) => file === path.join(path.dirname(filename), 'phantom.node') || fs.existsSync(file)}
    : Module.createRequire(filename)(id);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return {...loaded.exports, calls};
}

test('SOCKS4 user IDs retain exact empty and UTF-8 boundary values', async () => {
  const {Client, calls} = facade();
  const maximum = 'é'.repeat(127) + 'a';
  for (const proxyUserId of [undefined, '', maximum]) {
    new Client({profile: 'exact', route: 'proxy', proxy: 'socks4a://127.0.0.1:1080', proxyUserId});
    assert.equal(calls.at(-1).proxyUserId, proxyUserId);
  }
  const client = new Client({profile: 'exact', route: 'direct'});
  const route = {route: 'proxy', proxy: 'socks4a://127.0.0.1:1080', proxyUserId: maximum};
  await client.restoreSession(Buffer.alloc(0), Buffer.alloc(32), {receivingRoutes: [route]});
  assert.deepEqual({...calls.at(-1)[3][0]}, route);
});

test('SOCKS4 user ID validation does not coerce or expose caller input', async () => {
  const {Client, calls} = facade();
  for (const proxyUserId of [null, false, 1, {}, 'private\0input', 'é'.repeat(128), '\ud800']) {
    assert.throws(() => new Client({profile: 'exact', route: 'proxy', proxy: 'socks4://127.0.0.1:1080', proxyUserId}),
      (error) => error.code === 'InvalidProxy' && !String(error).includes('private'));
  }
  const options = {profile: 'exact', route: 'direct'};
  Object.defineProperty(options, 'proxyUserId', {enumerable: true, get() {throw Error('private getter');}});
  assert.throws(() => new Client(options), {code: 'InvalidArgument'});
  assert.equal(calls.length, 0);
  const client = new Client({profile: 'exact', route: 'direct'});
  for (const route of [{route: 'direct', proxyUserId: ''}, {route: 'proxy', proxy: 'socks4://127.0.0.1', proxyUserId: 'private\0input'}]) {
    await assert.rejects(client.restoreSession(Buffer.alloc(0), Buffer.alloc(32), {receivingRoutes: [route]}));
  }
  assert.equal(calls.length, 1);
});
