'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {inspect} = require('node:util');
const {loadFacade} = require('./load-facade.cjs');

const field = (name, value) => ({name, value: Buffer.from(value)});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

function facade({nativeHooks = true} = {}) {
  const owners = [], requests = [], clients = [];
  class Hooks {
    constructor(count) {
      this.count = count; this.index = 0; this.stopped = deferred();
      this.edits = []; this.replies = []; owners.push(this);
    }
    async next() {
      if (this.ended) return null;
      if (this.index === this.count) {
        if (this.options.redirectPolicy?.mode === 'custom' && !this.redirectIssued) {
          this.redirectIssued = true;
          return {index: 0, method: '', uri: '', headers: [], redirect: {
            fromUrl: this.options.url, toUrl: 'http://destination.test/final?private',
            status: 302, method: 'POST', nextMethod: 'GET', hop: 1n,
          }};
        }
        this.response.resolve(this.head);
        await this.stopped.promise;
        return null;
      }
      const index = this.index++;
      return {index, method: 'POST', uri: this.options.url,
        headers: [field('Content-Type', 'text/plain'), ...this.edits]};
    }
    complete(index, edits) {
      assert.equal(index, this.index - 1);
      this.replies.push(edits);
      for (const edit of edits) {
        if (edit.action === 'append') this.edits.push({...edit});
      }
    }
    fail() { this.response.reject(new Error('PHANTOM_REQUEST:HeaderHook:::header hook failed')); }
    completeRedirect(hop, decision) {
      assert.equal(hop, 1n);
      this.decision = decision;
      if (decision === 'reject') this.response.reject(new Error('PHANTOM_REQUEST:Redirect:::redirect rejected'));
    }
    failRedirect(hop) {
      assert.equal(hop, 1n);
      this.response.reject(new Error('PHANTOM_REQUEST:Redirect:::redirect callback failed'));
    }
    closed() { return this.stopped.promise; }
    stop() { this.ended = true; this.stopped.resolve(); }
    settled() { this.acknowledged = true; }
    interrupt(code) {
      this.stop();
      this.response.reject(new Error(`PHANTOM_REQUEST:${code}:::request interrupted`));
    }
  }
  const owner = () => ({
    async close() {},
    async request(options, cancellation, _budget, _upload, _transfer, _diagnostics, hooks) {
      requests.push(options);
      const head = {status: 204, headers: [], protocol: 'http1', url: options.url, redirects: 0,
        connectionRetries: 0, decodedContentCodings: [], redirectHistory: null, close() {}};
      if (!hooks) return head;
      hooks.options = options; hooks.head = head; hooks.response = deferred();
      cancellation.owner = hooks;
      return await hooks.response.promise;
    },
  });
  const native = {
    NativeEnvironment: class {
      client(config) { clients.push(config); return owner(); }
      fork() { return owner(); }
      async restoreSession() { return owner(); }
    },
    NativeCancellation: class {cancel() {this.owner?.interrupt('Cancelled');}},
    ...(nativeHooks ? {NativeHeaderHooks: Hooks} : {}),
  };
  return {...loadFacade(path.resolve(__dirname, '../index.cjs'), native), owners, requests, clients};
}

test('hooks see prepared fields, run client first and retain ordered native edits', async () => {
  const {Client, HeaderHookContext, owners, clients} = facade();
  const calls = [];
  let retained;
  const hooks = [(context) => {
    assert(context instanceof HeaderHookContext);
    assert.equal(context.method, 'POST');
    assert.equal(context.url, 'http://example.test/private');
    assert.equal(context.headers[0].value.toString(), 'text/plain');
    const headers = context.headers;
    headers[0].value.fill(0);
    assert.equal(context.headers[0].value.toString(), 'text/plain');
    assert(Object.isFrozen(headers));
    assert(!inspect(context).includes('private'));
    calls.push('client');
    context.append(field('X-Client', 'one'));
    retained = context;
  }];
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw', headerHooks: hooks});
  hooks.push(() => { throw new Error('late mutation'); });
  const response = await client.post('http://example.test/private', {headerHooks: [async (context) => {
    calls.push('request');
    assert.equal(context.headers[1].name, 'X-Client');
    context.append(field('X-Dupe', 'a'));
    context.append(field('x-dupe', 'b'));
    context.set(field('X-Dupe', 'c'));
    assert.deepEqual(context.headers.map((header) => header.name), ['Content-Type', 'X-Client', 'X-Dupe']);
    context.remove('content-type');
  }]});
  response.close();
  assert.deepEqual(calls, ['client', 'request']);
  assert.equal(clients[0].headerHooks, undefined);
  assert.deepEqual(owners[0].replies[1].map((edit) => edit.action), ['append', 'append', 'set', 'remove']);
  assert.throws(() => retained.append(field('late', 'no')), {code: 'InvalidOperation'});
  assert.throws(() => new HeaderHookContext(), {code: 'InvalidOperation'});
  await client.close();
});

test('hook errors preserve thrown identity, including primitives', async () => {
  for (const error of [new Error('private host cause'), undefined, 'original']) {
    const {Client} = facade();
    const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
    let caught = false;
    try { await client.get('http://example.test/', {headerHooks: [() => {throw error;}]}); }
    catch (observed) {caught = true; assert.equal(observed, error);}
    assert(caught);
    await client.close();
  }
});

test('cancellation settles the send but shutdown waits for the actual callback', async () => {
  const {Client, owners} = facade();
  const entered = deferred(), release = deferred();
  const abort = new AbortController();
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  const send = client.get('http://example.test/', {signal: abort.signal, headerHooks: [async (context) => {
    entered.resolve(context.signal);
    await release.promise;
  }]});
  const signal = await entered.promise;
  abort.abort();
  await assert.rejects(send, {code: 'Cancelled'});
  assert(signal.aborted);
  assert.equal(owners[0].acknowledged, undefined);
  const close = client.close();
  let closed = false;
  close.then(() => {closed = true;});
  await Promise.resolve();
  assert.equal(closed, false);
  release.resolve();
  await close;
  assert.equal(owners[0].acknowledged, true);
});

test('hook self-shutdown fails promptly instead of waiting for itself', async () => {
  const {Client} = facade();
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  (await client.get('http://example.test/', {headerHooks: [async () => {
    await assert.rejects(client.close(), {code: 'InvalidOperation'});
  }]})).close();
  await client.close();
});

test('a host failure after cancellation remains observable during shutdown', async (t) => {
  for (const original of [new Error('late callback failure'), undefined]) await t.test(String(original), async () => {
  const {Client} = facade();
  const entered = deferred(), release = deferred();
  const controller = new AbortController();
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  const send = client.get('http://example.test/', {signal: controller.signal, headerHooks: [async () => {
    entered.resolve(); await release.promise; throw original;
  }]});
  await entered.promise;
  controller.abort();
  await assert.rejects(send, {code: 'Cancelled'});
  release.resolve();
  await assert.rejects(client.close(), (error) => Object.hasOwn(error, 'cause') && error.cause === original);
  });
});

test('forks and restored clients inherit hooks and requests can skip them', async () => {
  const {Client} = facade();
  let calls = 0;
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw', headerHooks: [() => {calls++;}]});
  const fork = client.fork();
  const restored = await client.restoreSession(Buffer.alloc(0), Buffer.alloc(32));
  for (const owner of [client, fork, restored]) {
    (await owner.get('http://example.test/')).close();
    (await owner.get('http://example.test/', {skipClientHeaderHooks: true})).close();
    await owner.close();
  }
  assert.equal(calls, 3);
});

test('disabled hooks need no new payload capability; invalid hooks fail before native send', async () => {
  const {Client, requests} = facade({nativeHooks: false});
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  (await client.get('http://example.test/')).close();
  await assert.rejects(client.get('http://example.test/', {headerHooks: [() => {}]}), {code: 'NativeHeaderHooksUnavailable'});
  for (const input of [null, [1], Array(257).fill(() => {})]) {
    await assert.rejects(client.get('http://example.test/', {headerHooks: input}));
  }
  await assert.rejects(client.get('http://example.test/', {skipClientHeaderHooks: 'yes'}), {code: 'InvalidArgument'});
  assert.equal(requests.length, 1);
  await client.close();
});

test('redirect callbacks share the ordered pump and receive immutable redacted metadata', async () => {
  const {Client, RedirectDecision, owners, clients, requests} = facade();
  const calls = [];
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw', headerHooks: [() => calls.push('headers')],
    redirectPolicy: {mode: 'custom', maximumHops: 3, credentialHeaders: ['x-secret'], callback: async (attempt) => {
      calls.push('redirect');
      assert(Object.isFrozen(attempt));
      assert.equal(attempt.fromUrl, 'http://example.test/private');
      assert.equal(attempt.toUrl, 'http://destination.test/final?private');
      assert.equal(attempt.status, 302); assert.equal(attempt.hop, 1n);
      assert.equal(attempt.method, 'POST'); assert.equal(attempt.nextMethod, 'GET');
      assert(attempt.signal instanceof AbortSignal); assert.equal(attempt.signal.aborted, false);
      assert(!inspect(attempt).includes('private'));
      assert.throws(() => {attempt.toUrl = 'http://changed.test';}, TypeError);
      await assert.rejects(client.close(), {code: 'InvalidOperation'});
      await Promise.resolve();
      return RedirectDecision.Follow;
    }}});
  (await client.post('http://example.test/private')).close();
  assert.deepEqual(calls, ['headers', 'redirect']);
  assert.equal(owners.length, 1); assert.equal(owners[0].decision, 'follow');
  for (const policy of [clients[0].redirectPolicy, requests[0].redirectPolicy]) {
    assert.deepEqual(policy, {mode: 'custom', maximumHops: 3n, credentialHeaders: ['x-secret']});
    assert.equal(policy.callback, undefined);
  }
  assert(Object.isFrozen(RedirectDecision));
  await client.close();
});

test('redirect defaults snapshot through fork and restore, with per-request replacement and no-owner opt-out', async () => {
  const {Client, RedirectDecision, owners, requests} = facade();
  let calls = 0;
  const policy = {mode: 'custom', maximumHops: 2, callback: () => {calls++; return RedirectDecision.Stop;}};
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw', redirectPolicy: policy});
  policy.callback = () => {throw new Error('mutated default');}; policy.maximumHops = 0;
  const fork = client.fork(), restored = await client.restoreSession(Buffer.alloc(0), Buffer.alloc(32));
  for (const owner of [client, fork, restored]) {
    (await owner.get('http://example.test/')).close();
    (await owner.get('http://example.test/', {redirectPolicy: {mode: 'none'}})).close();
    await assert.rejects(owner.eventSource('http://example.test/'), {code: 'InvalidArgument'});
    await owner.close();
  }
  assert.equal(calls, 3); assert.equal(owners.length, 3);
  assert.deepEqual(owners.map((owner) => [owner.count, owner.decision]), Array(3).fill([0, 'stop']));
  assert.deepEqual(requests.map((request) => request.redirectPolicy.mode), ['custom', 'none', 'custom', 'none', 'custom', 'none']);
});

test('redirect callback failures retain every thrown value and invalid decisions fail closed', async () => {
  for (const original of [new Error('private cause'), undefined, 'host cause']) {
    const {Client} = facade();
    const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
    let caught = false;
    try { await client.get('http://example.test/', {redirectPolicy: {mode: 'custom', maximumHops: 1, callback: async () => {throw original;}}}); }
    catch (error) {caught = true; assert.equal(error, original);}
    assert(caught); await client.close();
  }
  const {Client, owners, requests} = facade();
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  await assert.rejects(client.get('http://example.test/', {redirectPolicy: {mode: 'custom', maximumHops: 1, callback: () => undefined}}), {code: 'InvalidArgument'});
  await assert.rejects(client.get('http://example.test/', {redirectPolicy: {mode: 'custom', maximumHops: 1, callback: () => 'reject'}}), {code: 'Redirect'});
  let reads = 0;
  for (const redirectPolicy of [{mode: 'custom', maximumHops: 1}, {mode: 'custom', maximumHops: 0, callback() {}},
    {mode: 'limited', maximumHops: 1, callback() {}}, {mode: 'custom', maximumHops: 1, get callback() {reads++; return () => 'follow';}}]) {
    await assert.rejects(client.get('http://example.test/', {redirectPolicy}), {code: 'InvalidArgument'});
  }
  assert.equal(reads, 0); assert.equal(requests.length, 2); assert.equal(owners.length, 2);
  await client.close();
});

test('redirect cancellation retains host custody and late failures without replacing the request outcome', async () => {
  for (const reason of ['Cancelled', 'Timeout']) {
    const {Client, owners} = facade();
    const entered = deferred(), release = deferred();
    const controller = new AbortController();
    const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
    const pending = client.get('http://example.test/', {signal: controller.signal, redirectPolicy: {mode: 'custom', maximumHops: 1,
      callback: async (attempt) => {entered.resolve(attempt.signal); await release.promise; throw undefined;}}});
    const signal = await entered.promise;
    if (reason === 'Cancelled') controller.abort(); else owners[0].interrupt('Timeout');
    await assert.rejects(pending, {code: reason});
    assert(signal.aborted); assert.equal(owners[0].acknowledged, undefined);
    const closed = client.close();
    let finished = false; closed.then(() => {finished = true;}, () => {finished = true;});
    await Promise.resolve(); assert.equal(finished, false);
    release.resolve();
    await assert.rejects(closed, (error) => Object.hasOwn(error, 'cause') && error.cause === undefined);
    assert.equal(owners[0].acknowledged, true);
  }
});

test('ordinary inherited policies keep the no-callback request path', async () => {
  const {Client, requests} = facade({nativeHooks: false});
  for (const redirectPolicy of [undefined, {mode: 'none'}, {mode: 'limited', maximumHops: 2}]) {
    const owner = new Client({profile: 'exact', route: 'direct', context: 'raw', redirectPolicy});
    (await owner.get('http://example.test/')).close();
    await owner.close();
  }
  assert.equal(requests.length, 3);
  assert(requests.every((request) => request.redirectPolicy === undefined));
});
