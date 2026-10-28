// @ts-check
'use strict';

const { addAbortListener } = require('node:events');

const { PhantomError, translated } = require('./errors.cjs');
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
/** @typedef {{read(): Promise<EventSourceEvent | null>, close(): void, readonly lastEventId: string,
 * readonly retryMs: bigint, readonly reconnects: number, readonly closed: boolean}} NativeSource */
/** @typedef {{kind: 'field' | 'lastEventId', name: string, value: Uint8Array, sensitive?: boolean}} PreparedHeader */

const token = {};
/** @type {FinalizationRegistry<() => void>} */
const abandoned = new FinalizationRegistry((cleanup) => cleanup());

class EventSource {
  #native;
  #cleanup;
  #owner;
  #signal;
  #reading = false;
  #ended = false;

  /** @param {NativeSource} source @param {NativeHead} head @param {() => void} cleanup
   * @param {unknown} owner @param {AbortSignal | undefined} signal @param {object} internal */
  constructor(source, head, cleanup, owner, signal, internal) {
    if (internal !== token) throw new PhantomError('InvalidOperation', 'use client.eventSource to open an event source');

    this.#native = source;
    this.#cleanup = cleanup;
    this.#owner = owner;
    this.#signal = signal;
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
    this.#owner = undefined;
  }

  /** @returns {Promise<EventSourceEvent | null>} */
  async read() {
    if (this.#ended) return null;
    if (this.#reading) throw new PhantomError('ConcurrentRead', 'only one event read may be pending');

    this.#reading = true;

    try {
      if (this.#signal?.aborted) throw new PhantomError('Cancelled', 'event source was aborted');
      const value = await this.#native.read();
      if (value === null) {
        this.#finish();
        return null;
      }
      return Object.freeze({data: value.data, event: value.event, id: value.id});
    } catch (error) {
      this.#finish();
      throw translated(error);
    } finally {
      this.#reading = false;
    }
  }

  close() { this.#finish(); }

  /** @returns {Promise<IteratorResult<EventSourceEvent>>} */
  async next() {
    const value = await this.read();
    return value === null ? {done: true, value: undefined} : {done: false, value};
  }

  /** @returns {Promise<IteratorResult<EventSourceEvent>>} */
  async return() {
    this.close();
    return {done: true, value: undefined};
  }

  /** @param {unknown} error */
  async throw(error) {
    this.close();
    throw error;
  }

  [Symbol.asyncIterator]() { return this; }
  [Symbol.dispose]() { this.close(); }
  async [Symbol.asyncDispose]() { this.close(); }
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

/** @param {{eventSource(settings: object, source: NativeSource): Promise<NativeHead>}} client
 * @param {unknown} owner @param {string | URL} input @param {EventSourceOptions} options
 * @param {readonly Header[]} defaults */
async function openEventSource(client, owner, input, options, defaults) {
  const fields = /** @type {EventSourceOptions} */ (policyFields(options, [
    'protocol', 'headers', 'limits', 'idleTimeoutMs', 'initialRetryMs', 'minimumRetryMs',
    'maximumReconnects', 'timeouts', 'route', 'signal',
  ]));
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
    route: fields.route === undefined ? undefined : receivingRoutes({receivingRoutes: [fields.route]})[0],
  };
  /** @type {NativeSource} */
  const source = new native.NativeEventSource();
  /** @type {Disposable | undefined} */
  let listener;
  const cleanup = () => {
    source.close();
    listener?.[Symbol.dispose]();
    listener = undefined;
  };

  try {
    if (fields.signal) listener = addAbortListener(fields.signal, () => source.close());
    if (fields.signal?.aborted) throw new PhantomError('Cancelled', 'event source was aborted');
    const head = await client.eventSource(settings, source);
    if (fields.signal?.aborted) throw new PhantomError('Cancelled', 'event source was aborted');
    return new EventSource(source, head, cleanup, owner, fields.signal, token);
  } catch (error) {
    cleanup();
    throw translated(error);
  }
}

module.exports = {EventSource, openEventSource};
