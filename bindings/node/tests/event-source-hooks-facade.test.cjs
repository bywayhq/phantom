'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {loadFacade} = require('./load-facade.cjs');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}
const field = (name, value) => ({name, value: Buffer.from(value)});

function facade() {
  const sources = [], mailboxes = [];
  class Hooks {
    constructor(count, source) {
      assert.equal(source, true);
      this.count = count; this.serial = 0n; this.cancelled = 0n;
      this.queue = []; this.changed = deferred(); this.closedSignal = deferred();
      this.exited = deferred(); mailboxes.push(this);
    }
    invoke(index = 0, headers = []) {
      assert.equal(this.active, undefined);
      const serial = ++this.serial;
      const reply = deferred();
      this.active = {serial, reply};
      this.queue.push({serial, index, method: 'GET', uri: 'https://local/events', headers});
      this.changed.resolve();
      return reply.promise;
    }
    async next() {
      while (!this.ended) {
        if (this.queue.length) return this.queue.shift();
        this.changed = deferred();
        await this.changed.promise;
      }
      return null;
    }
    async nextCancelled(after) {
      while (!this.ended && this.cancelled <= after) {
        this.cancelChanged = deferred();
        await this.cancelChanged.promise;
      }
      return this.ended ? null : this.cancelled;
    }
    isActive(serial) { return !this.ended && this.active?.serial === serial; }
    complete(index, edits, serial) {
      assert(this.isActive(serial));
      const {reply} = this.active; this.active = undefined;
      reply.resolve(edits);
    }
    fail(index, serial) {
      assert(this.isActive(serial));
      const {reply} = this.active; this.active = undefined;
      reply.reject(new Error('PHANTOM_EVENT_SOURCE:Request:source request failed\nPHANTOM_REQUEST:HeaderHook:http2::callback failed'));
    }
    cancelGet() {
      if (!this.active) return;
      this.cancelled = this.active.serial;
      this.active.reply.reject(new Error('PHANTOM:Timeout:GET timed out'));
      this.active = undefined;
      this.cancelChanged?.resolve();
    }
    stop() {
      this.ended = true;
      this.active?.reply.reject(new Error('PHANTOM:Cancelled:source closed'));
      this.active = undefined;
      this.changed.resolve(); this.cancelChanged?.resolve(); this.closedSignal.resolve();
    }
    closed() { return this.closedSignal.promise; }
    settled() { this.exited.resolve(); }
  }
  class Source {
    closed = false; lastEventId = ''; retryMs = 0n; reconnects = 0;
    constructor() { sources.push(this); }
    async read(cancellation) {
      const pending = this.pending ??= this.nextEvent();
      return cancellation ? Promise.race([pending, cancellation.cancelled.promise]) : pending;
    }
    close() { this.closed = true; this.hooks?.stop(); }
    async waitClosed(timeoutMs) {
      if (!this.hooks) return;
      let timer;
      try {
        await Promise.race([this.hooks.exited.promise, new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('PHANTOM:Timeout:cleanup timed out')), timeoutMs);
        })]);
      } finally { clearTimeout(timer); }
    }
  }
  const owner = () => ({
    async close() {},
    async eventSource(options, source, hooks) {
      source.hooks = hooks;
      for (let i = 0; i < (hooks?.count ?? 0); i++) await hooks.invoke(i);
      return {status: 200, protocol: 'http2', url: options.url, headers: []};
    },
  });
  const native = {
    NativeHeaderHooks: Hooks, NativeEventSource: Source,
    NativeCancellation: class {
      cancelled = deferred();
      cancel() { this.cancelled.reject(new Error('PHANTOM:Cancelled:read cancelled')); }
    },
    NativeEnvironment: class { client() { return owner(); } fork() { return owner(); } async restoreSession() { return owner(); } },
  };
  return {...loadFacade(path.resolve(__dirname, '../index.cjs'), native), sources, mailboxes};
}

test('EventSource snapshots client-first callbacks and skips inheritance per opening', async () => {
  const {Client, sources, mailboxes} = facade();
  const calls = [];
  const inherited = [context => { calls.push('client'); context.append(field('x-client', 'first')); }];
  const client = new Client({profile: 'exact', headerHooks: inherited});
  inherited.push(() => { throw new Error('not snapshotted'); });
  for (const owner of [client, client.fork(), await client.restoreSession(Buffer.from('checkpoint'), Buffer.alloc(32))]) {
    const source = await owner.eventSource('https://local/events', {protocol: 'http2', headerHooks: [() => calls.push('source')]});
    const mailbox = sources.at(-1).hooks;
    for (let i = 0; i < mailbox.count; i++) await mailbox.invoke(i);
    await source.closeAsync();
    await owner.close();
  }
  assert.deepEqual(calls, Array(6).fill(['client', 'source']).flat());
  const fresh = new Client({profile: 'exact', headerHooks: [() => { throw new Error('skipped'); }]});
  const selected = await fresh.eventSource('https://local/events', {protocol: 'http2', skipClientHeaderHooks: true, headerHooks: [() => {}]});
  await selected.closeAsync();
  const plain = new Client({profile: 'exact'});
  const before = mailboxes.length;
  const noHooks = await plain.eventSource('https://local/events', {protocol: 'http2'});
  assert.equal(mailboxes.length, before);
  await noHooks.closeAsync();
});

test('a timed-out GET aborts its context and waits for real cleanup before the next callback', async () => {
  const {Client, sources} = facade();
  const entered = deferred(), cleaning = deferred(), release = deferred();
  const late = new Error('late cleanup');
  let calls = 0, retained;
  const client = new Client({profile: 'exact'});
  const source = await client.eventSource('https://local/events', {protocol: 'http2', headerHooks: [async context => {
    if (++calls === 2) {
      retained = context; entered.resolve();
      try { await new Promise((_, reject) => context.signal.addEventListener('abort', () => reject(context.signal.reason), {once: true})); }
      finally { cleaning.resolve(); await release.promise; throw late; }
    }
  }]});
  const mailbox = sources[0].hooks;
  const first = mailbox.invoke();
  await entered.promise;
  mailbox.cancelGet();
  await assert.rejects(first, /GET timed out/);
  await cleaning.promise;
  assert.throws(() => retained.append(field('late', 'no')), {code: 'InvalidOperation'});
  const second = mailbox.invoke();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls, 2);
  release.resolve();
  await second;
  assert.equal(calls, 3);
  await assert.rejects(source.closeAsync(), error => error.code === 'HeaderHookCleanup' && error.cause === late);
  await source.closeAsync();
  await client.close();
});

test('per-read cancellation preserves the same pending GET and callback pump', async () => {
  const {Client, sources} = facade();
  const entered = deferred(), release = deferred();
  let calls = 0;
  const client = new Client({profile: 'exact'});
  const source = await client.eventSource('https://local/events', {protocol: 'http2', headerHooks: [async () => {
    if (++calls === 2) { entered.resolve(); await release.promise; }
  }]});
  sources[0].nextEvent = async () => { await sources[0].hooks.invoke(); return {data: 'next', event: 'message', id: ''}; };
  const controller = new AbortController();
  const reading = source.read({signal: controller.signal});
  await entered.promise;
  controller.abort();
  await assert.rejects(reading, {code: 'Cancelled'});
  assert.equal(source.closed, false);
  release.resolve();
  assert.equal((await source.read()).data, 'next');
  assert.equal(calls, 2);
  await source.closeAsync();
});

test('source close waits for actual callback exit and does not abort its finalizer twice', async () => {
  const {Client, sources} = facade();
  const entered = deferred(), cleaning = deferred(), release = deferred();
  let calls = 0, exited = false, aborts = 0;
  const client = new Client({profile: 'exact'});
  const source = await client.eventSource('https://local/events', {protocol: 'http2', headerHooks: [async context => {
    if (++calls === 2) {
      context.signal.addEventListener('abort', () => { aborts++; }); entered.resolve();
      try { await new Promise((_, reject) => context.signal.addEventListener('abort', () => reject(context.signal.reason), {once: true})); }
      finally { cleaning.resolve(); await release.promise; exited = true; }
    }
  }]});
  const pending = sources[0].hooks.invoke();
  const observed = assert.rejects(pending, /source closed/);
  await entered.promise;
  const closing = source.closeAsync({timeoutMs: 10});
  await cleaning.promise;
  await assert.rejects(closing, {code: 'Timeout'});
  await assert.rejects(client.close({timeoutMs: 0}), {code: 'Timeout'});
  assert.equal(exited, false); assert.equal(aborts, 1);
  source.close(); release.resolve();
  await source.closeAsync(); await observed;
  assert.equal(exited, true); assert.equal(aborts, 1);
});

test('source callback thrown values including undefined retain identity under typed SSE errors', async () => {
  for (const original of [new Error('private callback'), undefined, null, 42]) {
    const {Client} = facade();
    const client = new Client({profile: 'exact'});
    await assert.rejects(client.eventSource('https://local/events', {protocol: 'http2', headerHooks: [() => { throw original; }]}), error => {
      assert.equal(error.code, 'Sse'); assert.equal(error.cause.code, 'HeaderHook');
      assert(Object.hasOwn(error.cause, 'cause')); assert.equal(error.cause.cause, original);
      return true;
    });
    await client.close();
  }
});

test('late thrown undefined is observed once by closeAsync', async () => {
  const {Client, sources} = facade();
  const entered = deferred(); let calls = 0;
  const client = new Client({profile: 'exact'});
  const source = await client.eventSource('https://local/events', {protocol: 'http2', headerHooks: [async context => {
    if (++calls === 2) {
      entered.resolve();
      await new Promise(resolve => context.signal.addEventListener('abort', resolve, {once: true}));
      throw undefined;
    }
  }]});
  const pending = sources[0].hooks.invoke();
  const observed = assert.rejects(pending);
  await entered.promise;
  await assert.rejects(source.closeAsync(), error => error.code === 'HeaderHookCleanup' && Object.hasOwn(error, 'cause') && error.cause === undefined);
  await source.closeAsync(); await observed; await client.close();
});

test('a source callback cannot wait for its own cleanup or client shutdown', async () => {
  const {Client, sources} = facade();
  let calls = 0, source;
  const client = new Client({profile: 'exact'});
  source = await client.eventSource('https://local/events', {protocol: 'http2', headerHooks: [async () => {
    if (++calls === 2) {
      await assert.rejects(source.closeAsync(), {code: 'InvalidOperation'});
      await assert.rejects(client.close(), {code: 'InvalidOperation'});
    }
  }]});
  await sources[0].hooks.invoke();
  assert.equal(source.closed, false);
  await source[Symbol.asyncDispose]();
  await client.close();
});

test('invalid source callbacks and read/close options fail before native work', async () => {
  const {Client, sources, mailboxes} = facade();
  const client = new Client({profile: 'exact'});
  for (const options of [{headerHooks: [42]}, {headerHooks: Array(257).fill(() => {})}, {skipClientHeaderHooks: 'yes'}]) {
    await assert.rejects(client.eventSource('https://local/events', {protocol: 'http2', ...options}));
  }
  assert.equal(sources.length, 0); assert.equal(mailboxes.length, 0);
  const source = await client.eventSource('https://local/events', {protocol: 'http2'});
  await assert.rejects(source.read({signal: 42}), {code: 'InvalidArgument'});
  await assert.rejects(source.closeAsync({timeoutMs: -1}), {code: 'InvalidArgument'});
  assert.equal(source.closed, false);
  await source.closeAsync();
});

test('a deadline racing a successful completion does not invent a host cleanup failure', async () => {
  const {Client, sources} = facade();
  const client = new Client({profile: 'exact'});
  const source = await client.eventSource('https://local/events', {protocol: 'http2', headerHooks: [() => {}]});
  const mailbox = sources[0].hooks;
  const complete = mailbox.complete.bind(mailbox);
  mailbox.complete = () => {
    mailbox.cancelGet();
    throw new Error('PHANTOM:InvalidOperation:header hook invocation is no longer active');
  };
  await assert.rejects(mailbox.invoke(), /GET timed out/);
  mailbox.complete = complete;
  await mailbox.invoke();
  await source.closeAsync();
  await client.close();
});

test('a discarded GET error is not attached to a later native header validation failure', async () => {
  const {Client, sources} = facade();
  const original = new Error('earlier callback raced a deadline');
  let calls = 0;
  const client = new Client({profile: 'exact'});
  const source = await client.eventSource('https://local/events', {protocol: 'http2', headerHooks: [() => {
    if (++calls === 2) throw original;
  }]});
  const mailbox = sources[0].hooks;
  // The core can select a deadline after delivery and reconnect instead of exposing this error.
  await assert.rejects(mailbox.invoke());
  await mailbox.invoke();
  sources[0].nextEvent = async () => { throw new Error('PHANTOM_EVENT_SOURCE:Request:protected field\nPHANTOM_REQUEST:HeaderHook:http2::invalid managed header edit'); };
  await assert.rejects(source.read(), error => {
    assert.equal(error.cause.code, 'HeaderHook'); assert.equal(Object.hasOwn(error.cause, 'cause'), false);
    return true;
  });
  await assert.rejects(source.closeAsync(), error => error.code === 'HeaderHookCleanup' && error.cause === original);
  await client.close();
});
