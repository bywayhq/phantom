// @ts-check
'use strict';

const { addAbortListener } = require('node:events');

const { PhantomError, translated, caused } = require('./errors.cjs');
const { headerHooks, isHeaderHookContext, pumpHeaderHooks } = require('./header-hooks.cjs');
const { requestHookBundles, logicalMask, requestFailure, consumeCallbackFailure } = require('./request-hooks.cjs');
const { eventLimits } = require('./events.cjs');
const native = require('./native.cjs');
const { mergeHeaders, requestUrl } = require('./request-preparation.cjs');
const { phaseTimeouts, requestFields } = require('./request-options.cjs');
const { receivingRoutes } = require('./session.cjs');
const { integer, orderedDataArray, policyFields } = require('./validation.cjs');

/** @typedef {import('../index.js').Header} Header */
/** @typedef {import('../index.js').EventSourceEvent} EventSourceEvent */
/** @typedef {import('../index.js').EventSourceOptions} EventSourceOptions */
/** @typedef {import('../index.js').EventSourceHeader} EventSourceHeader */
/** @typedef {import('../index.js').ResponseHeader} ResponseHeader */
/** @typedef {{status: number, protocol: string, url: string, headers: ResponseHeader[]}} NativeHead */
/** @typedef {{read(cancellation?: import('./client-native.cjs').NativeCancellation): Promise<EventSourceEvent | null>, close(): void, waitClosed(timeoutMs: number): Promise<void>, readonly lastEventId: string,
 * readonly retryMs: bigint, readonly reconnects: number, readonly closed: boolean}} NativeSource */
/** @typedef {{kind: 'field' | 'lastEventId', name: string, value: Uint8Array, sensitive?: boolean}} PreparedHeader */

/** @typedef {{native: import('./client-native.cjs').NativeHeaderHooks, pumping: Promise<void>, outcome: import('./header-hooks.cjs').HookOutcome}} SourceHooks */
/** @typedef {{_trackHeaderPump(pumping: Promise<void>, outcome: import('./header-hooks.cjs').HookOutcome): void}} CallbackClient */

/** @param {unknown} error @param {SourceHooks | undefined} hooks */
function sourceFailure(error, hooks) {
  const failure = translated(error);
  const request = failure.cause;
  if (hooks?.outcome.logical && request instanceof PhantomError) {
    caused(failure, requestFailure(request, hooks.outcome));
  }
  if (hooks?.outcome.failed && request instanceof PhantomError && request.code === 'HeaderHook') {
    caused(request, hooks.outcome.error);
    const retained = hooks.outcome.bridgeFailure;
    if (retained && retained.serial === hooks.outcome.failureSerial) retained.observed = true;
  }
  return failure;
}

/** @param {SourceHooks | undefined} hooks */
function observeCleanup(hooks) {
  if (hooks?.outcome.logical) {
    const failure = consumeCallbackFailure(hooks.outcome);
    if (failure) throw failure.error;
    return;
  }
  const failure = hooks?.outcome.bridgeFailure;
  if (failure && !failure.observed) {
    failure.observed = true;
    throw caused(new PhantomError('HeaderHookCleanup', 'event source callback cleanup failed'), failure.error);
  }
}

const token = {};
/** @type {FinalizationRegistry<() => void>} */
const abandoned = new FinalizationRegistry((cleanup) => cleanup());

class EventSource {
  #native;
  #cleanup;
  /** @type {CallbackClient | undefined} */
  #owner;
  #signal;
  #reading = false;
  #hooks;
  #ended = false;

  /** @param {NativeSource} source @param {NativeHead} head @param {() => void} cleanup
   * @param {CallbackClient} owner @param {AbortSignal | undefined} signal @param {object} internal @param {SourceHooks | undefined} hooks */
  constructor(source, head, cleanup, owner, signal, internal, hooks) {
    if (internal !== token) throw new PhantomError('InvalidOperation', 'use client.eventSource to open an event source');

    this.#native = source;
    this.#cleanup = cleanup;
    this.#owner = owner;
    this.#signal = signal;
    this.#hooks = hooks;
    Object.defineProperties(this, {
      status: {value: head.status, enumerable: true},
      protocol: {value: head.protocol, enumerable: true},
      url: {value: head.url, enumerable: true},
      headers: {value: Object.freeze(head.headers.map((field) => Object.freeze({...field}))), enumerable: true},
    });
    abandoned.register(this, cleanup, this);
    if (source.closed) this.#finish();
  }

  get lastEventId() { return this.#native.lastEventId; }
  get retryMs() { return this.#native.retryMs; }
  get reconnects() { return this.#native.reconnects; }
  get closed() { return this.#ended || this.#native.closed; }

  #finish() {
    if (this.#ended) return;

    this.#ended = true;
    abandoned.unregister(this);
    this.#cleanup();
    if (!this.#hooks) this.#owner = undefined;
  }

  /** @param {{signal?: AbortSignal}} [options] @returns {Promise<EventSourceEvent | null>} */
  async read(options) {
    if (this.#ended) return null;
    if (this.#reading) throw new PhantomError('ConcurrentRead', 'only one event read may be pending');

    const fields = policyFields(options ?? {}, ['signal']);
    const signal = fields.signal;
    if (signal !== undefined && !(signal instanceof AbortSignal)) throw new PhantomError('InvalidArgument', 'signal must be an AbortSignal');
    if (signal?.aborted) throw new PhantomError('Cancelled', 'event read was cancelled');
    const cancellation = signal ? new native.NativeCancellation() : undefined;
    const listener = signal && cancellation ? addAbortListener(signal, () => cancellation.cancel()) : undefined;
    this.#reading = true;

    try {
      if (this.#signal?.aborted) throw new PhantomError('Cancelled', 'event source was aborted');
      const value = cancellation ? await this.#native.read(cancellation) : await this.#native.read();
      if (value === null) {
        this.#finish();
        if (this.#hooks) await this.closeAsync();
        return null;
      }
      return Object.freeze({data: value.data, event: value.event, id: value.id});
    } catch (error) {
      const failure = sourceFailure(error, this.#hooks);
      if (signal?.aborted && !this.#native.closed && failure.code === 'Cancelled') throw failure;
      this.#finish();
      throw failure;
    } finally {
      listener?.[Symbol.dispose]();
      this.#reading = false;
    }
  }

  close() { this.#finish(); }

  /** @param {{timeoutMs?: number}} [options] */
  async closeAsync(options = {}) {
    const fields = policyFields(options, ['timeoutMs']);
    const timeoutMs = integer(fields.timeoutMs === undefined ? 5000 : fields.timeoutMs, 'timeoutMs');
    if (this.#owner && isHeaderHookContext(this.#owner, this.#hooks?.native)) throw new PhantomError('InvalidOperation', 'a source callback cannot await its own cleanup');
    const started = performance.now();
    this.close();
    try {
      await this.#native.waitClosed(timeoutMs);
      if (this.#hooks) {
        let timer;
        try {
          await Promise.race([this.#hooks.pumping, new Promise((_, reject) => {
            timer = setTimeout(() => reject(new PhantomError('Timeout', 'event source callback cleanup deadline expired')), Math.max(0, timeoutMs - (performance.now() - started)));
          })]);
        } finally { clearTimeout(timer); }
      }
    } catch (error) { throw translated(error); }
    this.#owner = undefined;
    observeCleanup(this.#hooks);
  }

  /** @returns {Promise<IteratorResult<EventSourceEvent>>} */
  async next() {
    const value = await this.read();
    return value === null ? {done: true, value: undefined} : {done: false, value};
  }

  /** @returns {Promise<IteratorResult<EventSourceEvent>>} */
  async return() {
    await this.closeAsync();
    return {done: true, value: undefined};
  }

  /** @param {unknown} error */
  async throw(error) {
    try { await this.closeAsync(); } catch (cleanup) {
      const failure = caused(new PhantomError('EventSourceCleanup', 'event source consumer failed during cleanup'), error);
      Object.defineProperty(failure, 'cleanupError', {value: cleanup});
      throw failure;
    }
    throw error;
  }

  [Symbol.asyncIterator]() { return this; }
  [Symbol.dispose]() { this.close(); }
  async [Symbol.asyncDispose]() { await this.closeAsync(); }
}

/** @param {number} value @param {string} name */
function delay(value, name) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new PhantomError('InvalidArgument', `${name} must be finite nonnegative milliseconds`);
  }
  return value;
}

/** @param {readonly EventSourceHeader[] | undefined} input @param {readonly Header[]} defaults
 * @param {'http1' | 'http2' | 'http3'} protocol */
function sourceHeaders(input, defaults, protocol) {
  /** @type {PreparedHeader[]} */
  const fields = input === undefined ? [] : orderedDataArray(input, 256, 'event source headers').map((entry) => {
    const slot = policyFields(entry, ['lastEventId', 'name', 'value', 'sensitive']);
    if (Object.hasOwn(slot, 'lastEventId')) {
      if (Object.keys(slot).length !== 1) throw new PhantomError('InvalidArgument', 'a managed Last-Event-ID slot cannot include literal fields');
      if (typeof slot.lastEventId !== 'string') throw new PhantomError('InvalidArgument', 'lastEventId must be a header name');
      return {kind: 'lastEventId', name: slot.lastEventId, value: Buffer.alloc(0)};
    }
    const parsed = requestFields([slot], undefined).headers;
    if (parsed === undefined || parsed.length !== 1) throw new PhantomError('NativeFailure', 'event source header preparation failed');
    const [header] = parsed;
    return {kind: 'field', ...header};
  });
  /** @type {Header[]} */
  const implicit = input === undefined ? [
    {name: protocol === 'http1' ? 'Accept' : 'accept', value: Buffer.from('text/event-stream')},
    {name: protocol === 'http1' ? 'Cache-Control' : 'cache-control', value: Buffer.from('no-cache')},
  ] : [];
  const inherited = mergeHeaders(implicit, [...defaults]) ?? [];
  const merged = mergeHeaders(inherited, fields) ?? [];
  // The existing header boundary checks the combined count, names and bytes.
  requestFields(merged, undefined);
  return merged.map((field) => 'kind' in field && field.kind === 'lastEventId'
    ? {kind: 'lastEventId', name: field.name}
    : {kind: 'field', name: field.name, value: field.value, sensitive: field.sensitive});
}

/** @param {{eventSource(settings: object, source: NativeSource, hooks?: import('./client-native.cjs').NativeHeaderHooks): Promise<NativeHead>}} client
 * @param {CallbackClient} owner @param {string | URL} input @param {EventSourceOptions} options
 * @param {readonly Header[]} defaults @param {readonly import('../index.js').HeaderHook[]} inherited
 * @param {Readonly<import('../index.js').RequestHooks>} [inheritedLogical] */
async function openEventSource(client, owner, input, options, defaults, inherited, inheritedLogical) {
  const fields = /** @type {EventSourceOptions} */ (policyFields(options, [
    'protocol', 'headers', 'limits', 'idleTimeoutMs', 'initialRetryMs', 'minimumRetryMs',
    'maximumReconnects', 'timeouts', 'route', 'signal', 'headerHooks', 'skipClientHeaderHooks', 'requestHooks',
  ]));
  if (fields.skipClientHeaderHooks !== undefined && typeof fields.skipClientHeaderHooks !== 'boolean') throw new PhantomError('InvalidArgument', 'skipClientHeaderHooks must be boolean');
  const callbacks = [...(fields.skipClientHeaderHooks ? [] : inherited), ...headerHooks(fields.headerHooks)];
  const logicalBundles = requestHookBundles(inheritedLogical, fields.requestHooks);
  const phases = logicalMask(logicalBundles);
  if (callbacks.length > 256) throw new PhantomError('InputLimit', 'headerHooks exceed 256 callbacks');
  const protocol = fields.protocol;
  if (!['http1', 'http2', 'http3'].includes(protocol)) throw new PhantomError('InvalidProtocol', 'event source requires http1, http2 or http3');
  const url = requestUrl(input, undefined);
  if (fields.signal !== undefined && !(fields.signal instanceof AbortSignal)) throw new PhantomError('InvalidArgument', 'signal must be an AbortSignal');
  const [maximumLineBytes, maximumEventBytes] = eventLimits(fields.limits);
  const headers = sourceHeaders(fields.headers, defaults, protocol);
  const timeoutFields = fields.timeouts === undefined ? undefined : policyFields(fields.timeouts,
    ['poolAdmissionMs', 'connectMs', 'responseHeadMs', 'totalMs', 'readIdleMs']);
  if (timeoutFields !== undefined && Object.hasOwn(timeoutFields, 'readIdleMs')) {
    throw new PhantomError('InvalidTimeout', 'use idleTimeoutMs for event source body inactivity');
  }
  const settings = {
    url, protocol, headers, maximumLineBytes, maximumEventBytes,
    idleTimeoutMs: fields.idleTimeoutMs === undefined ? undefined : delay(fields.idleTimeoutMs, 'idleTimeoutMs'),
    initialRetryMs: delay(fields.initialRetryMs === undefined ? 3000 : fields.initialRetryMs, 'initialRetryMs'),
    minimumRetryMs: fields.minimumRetryMs === undefined ? undefined : delay(fields.minimumRetryMs, 'minimumRetryMs'),
    maximumReconnects: integer(fields.maximumReconnects === undefined ? 3 : fields.maximumReconnects, 'maximumReconnects'),
    timeouts: phaseTimeouts(timeoutFields),
    route: fields.route === undefined ? undefined : receivingRoutes({receivingRoutes: [fields.route]}, 'InputLimit')[0],
  };
  /** @type {NativeSource} */
  const source = new native.NativeEventSource();
  /** @type {Disposable | undefined} */
  let listener;
  /** @type {SourceHooks | undefined} */
  let hooks;
  /** @type {import('./client-native.cjs').NativeHeaderHooks | undefined} */
  let mailbox;
  const cleanup = () => {
    source.close();
    hooks?.native.stop();
    listener?.[Symbol.dispose]();
    listener = undefined;
  };

  try {
    if (fields.signal) listener = addAbortListener(fields.signal, () => source.close());
    if (fields.signal?.aborted) throw new PhantomError('Cancelled', 'event source was aborted');
    let pending;
    if (callbacks.length || phases) {
      if (typeof native.NativeHeaderHooks !== 'function') throw new PhantomError('NativeHeaderHooksUnavailable', 'install the matching native payload for header hooks');
      const created = /** @type {import('./client-native.cjs').NativeHeaderHooks} */ (phases ? new native.NativeHeaderHooks(callbacks.length, true, phases) : new native.NativeHeaderHooks(callbacks.length, true));
      mailbox = created;
      if (typeof created.nextCancelled !== 'function' || typeof created.isActive !== 'function' || typeof source.waitClosed !== 'function') throw new PhantomError('NativeHeaderHooksUnavailable', 'install the matching native payload for EventSource hooks');
      if (phases && typeof created.completeLogical !== 'function') throw new PhantomError('NativeHeaderHooksUnavailable', 'install the matching native payload for logical hooks');
      /** @type {import('./header-hooks.cjs').HookOutcome} */
      const outcome = phases ? {failed: false, logical: {}} : {failed: false};
      pending = client.eventSource(settings, source, created);
      const pumping = pumpHeaderHooks(owner, created, callbacks, outcome, undefined, true, logicalBundles);
      hooks = {native: created, pumping, outcome};
      owner._trackHeaderPump(pumping, outcome);
    } else pending = client.eventSource(settings, source);
    const head = await pending;
    if (fields.signal?.aborted) throw new PhantomError('Cancelled', 'event source was aborted');
    const result = new EventSource(source, head, cleanup, owner, fields.signal, token, hooks);
    if (source.closed && hooks) await result.closeAsync();
    return result;
  } catch (error) {
    cleanup();
    if (!hooks) { mailbox?.stop(); mailbox?.settled(); }
    throw sourceFailure(error, hooks);
  }
}

module.exports = {EventSource, openEventSource};
