'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {inspect} = require('node:util');
const {loadFacade} = require('./load-facade.cjs');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {resolve = yes; reject = no;});
  return {promise, resolve, reject};
}
const initial = {method: 'POST', url: 'https://local/private?secret', headers: [], decodedContentCodings: []};
const logicalError = (primary, secondary = 0n, base = 'PHANTOM_REQUEST:RequestHook:http2::callback failed', hook = '', origin = 'https:443:local') =>
  new Error(`PHANTOM_LOGICAL:${primary}:${secondary}:${hook}\n${origin}\n${base}`);

function facade(program = async () => {}) {
  const mailboxes = [], requests = [], configs = [], sources = [];
  class Hooks {
    constructor(count, source, mask = 0) {
      this.count = count; this.source = source; this.mask = mask;
      this.serial = 0n; this.cancelled = 0n; this.queue = [];
      this.changed = deferred(); this.cancelChanged = deferred(); this.finished = deferred();
      this.exited = deferred(); mailboxes.push(this);
    }
    invoke(phase, fields = {}) {
      assert.equal(this.active, undefined);
      const serial = ++this.serial, reply = deferred();
      this.active = {serial, reply};
      this.queue.push({serial, index: 0, method: '', uri: '', headers: [], logical: {...initial, phase, ...fields}});
      this.changed.resolve();
      return reply.promise.then(failed => ({failed, serial}));
    }
    header(method = 'POST') {
      const serial = ++this.serial, reply = deferred();
      this.active = {serial, reply};
      this.queue.push({serial, index: 0, method, uri: initial.url, headers: []});
      this.changed.resolve();
      return reply.promise;
    }
    async next() {
      while (!this.ended) {
        if (this.queue.length) return this.queue.shift();
        this.changed = deferred(); await this.changed.promise;
      }
      return null;
    }
    async nextCancelled(after) {
      while (!this.ended && this.cancelled <= after) {
        this.cancelChanged = deferred(); await this.cancelChanged.promise;
      }
      return this.ended ? null : this.cancelled;
    }
    isActive(serial) { return !this.ended && this.active?.serial === serial; }
    completeLogical(serial, failed) {
      assert(this.isActive(serial));
      const {reply} = this.active; this.active = undefined; reply.resolve(failed);
    }
    complete(_index, _edits, serial) { this.completeLogical(serial, false); }
    fail(_index, serial) { this.completeLogical(serial, true); }
    expire() {
      if (this.active) {
        this.cancelled = this.active.serial;
        this.active.reply.reject(new Error('PHANTOM_REQUEST:Timeout::total:deadline expired'));
        this.active = undefined; this.cancelChanged.resolve();
      }
    }
    stop() {
      this.ended = true;
      this.active?.reply.reject(new Error('PHANTOM:Cancelled:request cancelled'));
      this.active = undefined; this.changed.resolve(); this.cancelChanged.resolve(); this.finished.resolve();
    }
    closed() { return this.finished.promise; }
    settled() { this.exited.resolve(); }
  }
  const head = url => ({status: 204, protocol: 'http2', url, headers: [], redirects: 0, close() {}});
  const owner = () => ({
    async close() {}, destroy() {},
    async request(options, cancellation, _budget, _upload, _transfer, _diagnostics, hooks) {
      requests.push(options); cancellation.hooks = hooks;
      await program(hooks, options);
      return head(options.url);
    },
    async eventSource(options, source, hooks) {
      source.hooks = hooks; await program(hooks, options);
      return head(options.url);
    },
  });
  class Source {
    closed = false; lastEventId = ''; retryMs = 0n; reconnects = 0;
    constructor() {sources.push(this);}
    close() {this.closed = true; this.hooks?.stop();}
    async waitClosed() {await this.hooks?.exited.promise;}
    async read(cancellation) {
      const pending = this.pending ??= this.nextEvent ? this.nextEvent() : Promise.resolve(null);
      return cancellation ? Promise.race([pending, cancellation.cancelled.promise]) : pending;
    }
  }
  const native = {
    NativeHeaderHooks: Hooks, NativeEventSource: Source,
    NativeCancellation: class {
      constructor() {this.cancelled = deferred(); this.cancelled.promise.catch(() => {});}
      cancel() {if (this.hooks) this.hooks.stop(); else this.cancelled.reject(new Error('PHANTOM:Cancelled:read cancelled'));}
    },
    NativeEnvironment: class {
      client(config) {configs.push(config); return owner();}
      fork() {return owner();} async restoreSession() {return owner();}
    },
  };
  return {...loadFacade(path.resolve(__dirname, '../index.cjs'), native), mailboxes, requests, configs, sources};
}

test('empty bundles allocate no bridge and invalid callback properties fail before admission', async () => {
  const {Client, mailboxes, requests, configs} = facade();
  const client = new Client({profile: 'exact', context: 'raw', requestHooks: {onRequest: undefined}});
  (await client.get(initial.url, {requestHooks: {}})).close();
  assert.equal(mailboxes.length, 0);
  assert(!Object.hasOwn(configs[0], 'requestHooks'));
  for (const bundle of [{onRequest: 1}, {unknown: () => {}}, Object.defineProperty({}, 'onError', {get() {throw new Error('accessor ran');}}), new Proxy({}, {})]) {
    await assert.rejects(client.get(initial.url, {requestHooks: bundle}), {code: 'InvalidArgument'});
  }
  assert.equal(requests.length, 1);
});

test('bundle snapshots inherit through fork/restore and immutable heads are client-first', async () => {
  const calls = [];
  const {Client, mailboxes} = facade(async hooks => {
    assert.equal(hooks.mask, 3);
    assert.equal((await hooks.invoke(0)).failed, false);
    assert.equal((await hooks.invoke(1, {status: 207, protocol: 'http2', effectiveUrl: 'https://local/final', redirects: 1, retries: 2,
      headers: [{name: 'x-private', value: Buffer.from('first'), sensitive: true}, {name: 'x-private', value: Buffer.from('second')}], decodedContentCodings: ['gzip']})).failed, false);
  });
  const bundle = {onRequest: async context => {calls.push('client request'); assert(Object.isFrozen(context)); assert(!inspect(context).includes('secret'));},
    onResponse: context => {calls.push('client response'); context.headers[0].value.fill(0); assert.equal(context.headers[0].value.toString(), 'first');}};
  const client = new Client({profile: 'exact', context: 'raw', requestHooks: bundle});
  bundle.onRequest = () => {throw new Error('changed after construction');};
  for (const selected of [client, client.fork(), await client.restoreSession(Buffer.from('checkpoint'), Buffer.alloc(32))]) {
    const response = await selected.get(initial.url, {requestHooks: {
      onRequest: context => {calls.push('request request'); assert.equal(context.method, 'POST');},
      onResponse: context => {
        calls.push('request response'); assert.equal(context.status, 207); assert.equal(context.url, 'https://local/final');
        assert.equal(context.redirects, 1); assert.equal(context.connectionRetries, 2); assert.deepEqual(context.decodedContentCodings, ['gzip']);
        assert.equal(context.headers[0].value.toString(), 'first'); assert.equal(context.headers.length, 2); assert(!('body' in context));
        assert(Object.isFrozen(context.headers)); assert(Object.isFrozen(context.request));
      },
    }});
    response.close(); await selected.close();
  }
  assert.deepEqual(calls, Array(3).fill(['client request', 'request request', 'client response', 'request response']).flat());
  assert.equal(mailboxes.length, 3);
});

test('only configured phases cross the native mailbox', async () => {
  const {Client} = facade(async hooks => {
    assert.equal(hooks.mask, 2);
    await hooks.invoke(1, {status: 204});
  });
  const client = new Client({profile: 'exact', context: 'raw', requestHooks: {onResponse() {}}});
  (await client.get(initial.url)).close(); await client.close();
});

test('request and error failures preserve two thrown undefined values and native metadata', async () => {
  let phases = [];
  const {Client} = facade(async hooks => {
    const primary = await hooks.invoke(0); assert(primary.failed);
    const native = logicalError(primary.serial);
    const secondary = await hooks.invoke(2, {error: native.message, originScheme: 'https', originHost: 'local', originPort: 443}); assert(secondary.failed);
    throw logicalError(primary.serial, secondary.serial, undefined, 'PHANTOM_REQUEST:RequestHook:http2::error callback failed');
  });
  const client = new Client({profile: 'exact', context: 'raw', requestHooks: {
    onRequest() {phases.push('request'); throw undefined;},
    onError(context) {
      phases.push('error'); assert.equal(context.error.code, 'RequestHook'); assert(Object.hasOwn(context.error, 'cause'));
      assert.equal(context.error.cause, undefined); assert.deepEqual(context.error.origin, {scheme: 'https', host: 'local', port: 443}); throw undefined;
    },
  }});
  await assert.rejects(client.get(initial.url), error => {
    assert.equal(error.code, 'RequestHook'); assert(Object.hasOwn(error, 'cause')); assert.equal(error.cause, undefined);
    assert.equal(error.hookError.code, 'RequestHook'); assert(Object.hasOwn(error.hookError, 'cause')); assert.equal(error.hookError.cause, undefined);
    return true;
  });
  assert.deepEqual(phases, ['request', 'error']); await client.close();
});

test('network failure stays primary when an error observer throws', async () => {
  const original = {private: 'host cause'};
  const {Client} = facade(async hooks => {
    const failure = await hooks.invoke(2, {error: 'PHANTOM_REQUEST:Connect:http1:connect:connection failed', originScheme: 'http', originHost: 'local', originPort: 80});
    assert(failure.failed);
    throw logicalError(0n, failure.serial, 'PHANTOM_REQUEST:Connect:http1:connect:connection failed', 'PHANTOM_REQUEST:RequestHook:http1::error callback failed', 'http:80:local');
  });
  const client = new Client({profile: 'exact', context: 'raw'});
  await assert.rejects(client.get(initial.url, {requestHooks: {onError(context) {assert.equal(context.error.code, 'Connect'); throw original;}}}), error =>
    error.code === 'Connect' && error.protocol === 'http1' && error.timeoutPhase === 'connect' && error.hookError.cause === original
      && error.origin.scheme === 'http' && error.origin.host === 'local' && error.origin.port === 80);
  await client.close();
});

test('ordinary and logical native errors preserve canonical IPv6 origin metadata', async () => {
  const base = 'PHANTOM_REQUEST:Connect:http2:connect:connection failed';
  for (const frame of [`PHANTOM_ORIGIN:https:443:::1\n${base}`, logicalError(0n, 0n, base, '', 'https:443:::1').message]) {
    const {Client} = facade(async () => {throw new Error(frame);});
    const client = new Client({profile: 'exact', context: 'raw'});
    await assert.rejects(client.get(initial.url), error => {
      assert.equal(error.code, 'Connect'); assert.equal(error.protocol, 'http2'); assert.equal(error.timeoutPhase, 'connect');
      assert.deepEqual(error.origin, {scheme: 'https', port: 443, host: '::1'}); assert(Object.isFrozen(error.origin)); return true;
    });
    await client.close();
  }
});

test('a negative header reply leaves the logical error phase alive', async () => {
  const original = new Error('header cause'); let errors = 0;
  const {Client} = facade(async hooks => {
    assert.equal(await hooks.header(), true);
    await hooks.invoke(2, {error: 'PHANTOM_REQUEST:HeaderHook:http2::header callback failed'});
    throw new Error('PHANTOM_REQUEST:HeaderHook:http2::header callback failed');
  });
  const client = new Client({profile: 'exact', context: 'raw', headerHooks: [() => {throw original;}],
    requestHooks: {onError(context) {errors++; assert.equal(context.error.cause, original);}}});
  await assert.rejects(client.get(initial.url), error => error.code === 'HeaderHook' && error.cause === original);
  assert.equal(errors, 1); await client.close();
});

test('logical tags do not collide with valid lowercase custom header methods', async () => {
  const methods = [];
  const {Client} = facade(async (hooks, options) => {await hooks.header(options.method); await hooks.invoke(1, {status: 204});});
  const client = new Client({profile: 'exact', context: 'raw'});
  for (const method of ['request', 'response', 'error']) {
    (await client.request(initial.url, {method, headerHooks: [context => methods.push(context.method)], requestHooks: {onResponse() {}}})).close();
  }
  assert.deepEqual(methods, ['request', 'response', 'error']); await client.close();
});

test('cancelling a logical callback retains actual host cleanup and observes late rejection', async () => {
  const entered = deferred(), release = deferred(); const late = new Error('late host failure');
  const {Client, mailboxes} = facade(async hooks => {await hooks.invoke(0);});
  const client = new Client({profile: 'exact', context: 'raw'}); const controller = new AbortController();
  let signal;
  const send = client.get(initial.url, {signal: controller.signal, requestHooks: {async onRequest(context) {
    signal = context.signal; entered.resolve(); await release.promise; throw late;
  }}});
  await entered.promise; controller.abort(); await assert.rejects(send, {code: 'Cancelled'});
  assert(signal.aborted); assert.equal(mailboxes[0].exited.promise instanceof Promise, true);
  await assert.rejects(client.close({timeoutMs: 1}), {code: 'Timeout'});
  release.resolve(); await mailboxes[0].exited.promise;
  await assert.rejects(client.close(), error => error.cause === late);
  await client.close();
});

test('cancelled error observers retain both the earlier request cause and their late failure', async () => {
  const first = new Error('request failure'), second = new Error('late error observer'); const entered = deferred(), release = deferred();
  const {Client, mailboxes} = facade(async hooks => {
    const result = await hooks.invoke(0);
    await hooks.invoke(2, {error: logicalError(result.serial).message});
  });
  const client = new Client({profile: 'exact', context: 'raw'}), controller = new AbortController();
  const pending = client.get(initial.url, {signal: controller.signal, requestHooks: {
    onRequest() {throw first;},
    async onError(context) {assert.equal(context.error.cause, first); entered.resolve(); await release.promise; throw second;},
  }});
  await entered.promise; controller.abort(); await assert.rejects(pending, {code: 'Cancelled'});
  release.resolve(); await mailboxes[0].exited.promise;
  await assert.rejects(client.close(), error => error.cause === first && error.hookError?.cause === second);
  await client.close();
});

test('EventSource reuses one source owner for fresh logical GET phases', async () => {
  const calls = [];
  const {Client, sources, mailboxes} = facade(async hooks => {await hooks.invoke(0); await hooks.invoke(1, {status: 200});});
  const client = new Client({profile: 'exact', requestHooks: {onRequest() {calls.push('client');}}});
  const source = await client.eventSource(initial.url, {protocol: 'http2', requestHooks: {onRequest() {calls.push('source');}, onResponse() {calls.push('head');}}});
  const hooks = sources[0].hooks;
  await hooks.invoke(0); await hooks.invoke(1, {status: 204});
  assert.equal(mailboxes.length, 1); assert.equal(hooks.source, true); assert.equal(hooks.mask, 3);
  assert.deepEqual(calls, ['client', 'source', 'head', 'client', 'source', 'head']);
  await source.closeAsync(); await client.close();
});

test('cancelled EventSource reads retain their pending logical callback and GET', async () => {
  const entered = deferred(), release = deferred(); let calls = 0, signal;
  const {Client, sources} = facade(async hooks => {await hooks.invoke(0);});
  const client = new Client({profile: 'exact'});
  const source = await client.eventSource(initial.url, {protocol: 'http2', requestHooks: {async onRequest(context) {
    if (++calls === 2) {signal = context.signal; entered.resolve(); await release.promise;}
  }}});
  const hooks = sources[0].hooks;
  sources[0].nextEvent = async () => {await hooks.invoke(0); return {data: 'same GET', event: '', id: ''};};
  const controller = new AbortController(); const pending = source.read({signal: controller.signal});
  await entered.promise; controller.abort(); await assert.rejects(pending, {code: 'Cancelled'});
  assert.equal(signal.aborted, false); assert.equal(hooks.ended, undefined);
  release.resolve(); assert.equal((await source.read()).data, 'same GET'); assert.equal(calls, 2);
  await source.closeAsync(); await client.close();
});

test('expired source callbacks finish before the next GET and never explain a later native failure', async () => {
  const entered = deferred(), cleaning = deferred(), release = deferred(); const late = new Error('old GET finalizer'); let calls = 0;
  const {Client, sources} = facade(async hooks => {await hooks.invoke(0);});
  const client = new Client({profile: 'exact'});
  const source = await client.eventSource(initial.url, {protocol: 'http2', requestHooks: {async onRequest(context) {
    if (++calls === 2) {
      entered.resolve(); await new Promise(resolve => context.signal.addEventListener('abort', resolve, {once: true}));
      cleaning.resolve(); await release.promise; throw late;
    }
  }}});
  const hooks = sources[0].hooks;
  const old = hooks.invoke(0); await entered.promise; hooks.expire(); await assert.rejects(old, /deadline expired/); await cleaning.promise;
  const fresh = hooks.invoke(0); assert.equal(calls, 2);
  release.resolve(); assert.equal((await fresh).failed, false); assert.equal(calls, 3);
  sources[0].nextEvent = async () => {throw new Error('PHANTOM_EVENT_SOURCE:Request:source request failed\nPHANTOM_REQUEST:RequestHook:http2::metadata rejected');};
  await assert.rejects(source.read(), error => error.code === 'Sse' && error.cause.code === 'RequestHook' && !Object.hasOwn(error.cause, 'cause'));
  await assert.rejects(source.closeAsync(), error => error.code === 'RequestHookCleanup' && error.cause === late);
  await source.closeAsync(); await client.close();
});
