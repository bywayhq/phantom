'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {loadFacade} = require('./load-facade.cjs');
const {performance} = require('node:perf_hooks');

const key = Buffer.alloc(32, 0x61);
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}
function facade({encode, restore} = {}) {
  const calls = [];
  const child = {destroy() { calls.push('destroy'); }, async close() { calls.push('close'); }};
  const owner = {async exportSession(secret) {
    calls.push(['export', Buffer.from(secret)]);
    return encode ? await encode() : Buffer.from('encrypted');
  }};
  const {Client} = loadFacade(path.resolve(__dirname, '../index.cjs'), {NativeEnvironment: class {
    client() { return owner; }
    async restoreSession(source, bytes, secret, routes) {
      calls.push(['restore', source, Buffer.from(bytes), Buffer.from(secret), routes]);
      if (restore) await restore();
      return child;
    }
  }});
  return {client: new Client({profile: 'exact', route: 'direct'}), owner, calls};
}
function memory() {
  const values = new Map();
  return {values, async save(name, bytes, {signal}) {signal.throwIfAborted(); values.set(name, bytes);},
    async load(name, {signal}) { signal.throwIfAborted(); return values.get(name) ?? null; }};
}

test('store gets only name, encrypted bytes and cancellation; restore keeps source and routes', async () => {
  const {client, owner, calls} = facade(), store = memory();
  await client.saveSession(store, 'é'.repeat(128), key, {timeoutMs: 5000});
  assert.deepEqual(store.values.get('é'.repeat(128)), Buffer.from('encrypted'));
  assert.equal(await client.loadSession(store, 'absent', key, {timeoutMs: 5000}), null);
  const child = await client.loadSession(store, 'é'.repeat(128), key, {timeoutMs: 5000, receivingRoutes: [{route: 'direct'}]});
  assert.notEqual(child, client);
  assert.equal(calls[1][1], owner);
  assert.deepEqual(calls[1][4].map((route) => ({...route})), [{route: 'direct'}]);
  assert.deepEqual(calls[0][1], key);
  assert.deepEqual(calls[1][3], key);
  assert(!calls.includes('destroy'));
});

test('invalid names, backend errors and oversize reads are distinct from absence', async () => {
  const {client, calls} = facade(), store = memory();
  for (const name of ['', 'é'.repeat(129), 'a\0', 'a\u0085', '\ud800']) {
    await assert.rejects(client.saveSession(store, name, key, {timeoutMs: 5000}), {code: 'SessionStorage', kind: 'invalid_name'});
  }
  assert.equal(calls.length, 0);
  const original = new Error('private backend detail');
  store.load = async () => { throw original; };
  await assert.rejects(client.loadSession(store, 'session', key, {timeoutMs: 5000}), (error) => {
    assert.equal(error.kind, 'backend'); assert.equal(error.cause, original);
    assert(!String(error).includes('private')); return true;
  });
  store.load = async () => Buffer.alloc(32 * 1024 * 1024 + 1);
  await assert.rejects(client.loadSession(store, 'session', key, {timeoutMs: 5000}), {code: 'SessionSnapshot', kind: 'too_large'});
  assert.equal(calls.length, 0);
});

test('abort promptly rejects a pending backend and observes its late rejection', async () => {
  const {client, calls} = facade(), pending = deferred(), started = deferred();
  const abort = new AbortController(), reason = new Error('cancelled');
  const store = memory();
  store.load = async (name, {signal}) => { started.resolve(signal); return await pending.promise; };
  const result = client.loadSession(store, 'session', key, {timeoutMs: 5000, signal: abort.signal});
  const signal = await started.promise;
  abort.abort(reason);
  await assert.rejects(result, (error) => error === reason);
  assert(signal.aborted);
  pending.reject(new Error('late backend failure'));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls.length, 0);
});

test('timeout interrupts a pending backend and accepted external writes are not undone', async () => {
  const {client} = facade(), store = memory(), started = deferred(), pending = deferred();
  store.save = async (name, snapshot, {signal}) => {
    store.values.set(name, snapshot); started.resolve(signal); return await pending.promise;
  };
  const result = client.saveSession(store, 'session', key, {timeoutMs: 100});
  const signal = await started.promise;
  await assert.rejects(result, {code: 'SessionStorage', kind: 'deadline'});
  assert(signal.aborted);
  assert(store.values.has('session'));
  pending.resolve();
});

test('cancelled CPU phases settle; encoding skips backend and late restores are destroyed', async () => {
  const abort = new AbortController(), reason = new Error('cancelled during CPU');
  const store = memory(); let saves = 0;
  store.save = async () => { saves++; };
  const first = facade({encode: async () => { abort.abort(reason); return Buffer.from('encrypted'); }});
  await assert.rejects(first.client.saveSession(store, 'session', key, {timeoutMs: 5000, signal: abort.signal}), (error) => error === reason);
  assert.equal(saves, 0);
  const later = new AbortController(); store.values.set('session', Buffer.from('encrypted'));
  const second = facade({restore: async () => later.abort(reason)});
  await assert.rejects(second.client.loadSession(store, 'session', key, {timeoutMs: 5000, signal: later.signal}), (error) => error === reason);
  assert.deepEqual(second.calls.slice(-2), ['destroy', 'close']);
  assert.equal(second.calls.filter((call) => Array.isArray(call) && call[0] === 'restore').length, 1);
});

test('CPU failures check cancellation after settling and otherwise retain the original cause', async (t) => {
  for (const phase of ['encode', 'restore']) {
    for (const interruption of ['abort', 'deadline', 'none']) {
      await t.test(`${phase}: ${interruption}`, async (caseTest) => {
        let clock = 0;
        caseTest.mock.method(performance, 'now', () => clock);
        const pending = deferred(), started = deferred(), abort = new AbortController();
        const original = new Error('native CPU failure'), reason = new Error('caller cancellation');
        const work = async () => { started.resolve(); return await pending.promise; };
        const {client, calls} = facade({[phase]: work});
        const store = memory();
        store.values.set('session', Buffer.from('encrypted'));
        let settled = false;
        const result = phase === 'encode'
          ? client.saveSession(store, 'session', key, {timeoutMs: 5000, signal: abort.signal})
          : client.loadSession(store, 'session', key, {timeoutMs: 5000, signal: abort.signal});
        result.then(() => { settled = true; }, () => { settled = true; });
        await started.promise;
        if (interruption === 'abort') abort.abort(reason);
        if (interruption === 'deadline') clock = 5001;
        await new Promise((resolve) => setImmediate(resolve));
        assert.equal(settled, false, 'CPU work remains owned until it settles');
        const rejected = assert.rejects(result, (error) => interruption === 'abort'
          ? error === reason
          : interruption === 'deadline' ? error.kind === 'deadline' : error.cause === original);
        pending.reject(original);
        await rejected;
        assert(!calls.includes('destroy'));
      });
    }
  }
});

test('one deadline spans encoding and backend and cooperative cancellation releases backend work', async (t) => {
  let clock = 0;
  t.mock.method(performance, 'now', () => clock);
  const store = memory();
  const {client, calls} = facade({encode: async () => { clock = 4; return Buffer.from('encrypted'); }});
  store.save = async () => { clock = 6; };
  await assert.rejects(client.saveSession(store, 'session', key, {timeoutMs: 5}), {kind: 'deadline'});
  assert.equal(calls.length, 1);
  t.mock.restoreAll();
  const abort = new AbortController(), started = deferred();
  let released = false;
  store.load = async (name, {signal}) => {
    started.resolve();
    try {
      await new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), {once: true}));
      return null;
    } finally { released = true; }
  };
  const pending = client.loadSession(store, 'session', key, {timeoutMs: 5000, signal: abort.signal});
  await started.promise; abort.abort();
  await assert.rejects(pending, {name: 'AbortError'});
  await new Promise((resolve) => setImmediate(resolve));
  assert(released);
});
