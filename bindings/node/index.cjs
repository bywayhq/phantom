'use strict';

const native = require('./phantom.node');
const { types, TextDecoder } = require('node:util');
const { addAbortListener } = require('node:events');
const apply = Reflect.apply;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const backingOf = Object.getOwnPropertyDescriptor(typedArray, 'buffer').get;
const offsetOf = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset').get;
const lengthOf = Object.getOwnPropertyDescriptor(typedArray, 'byteLength').get;
const environment = new native.NativeEnvironment();
const budgetHandles = new WeakMap();
const abandonedResponses = new FinalizationRegistry((cleanup) => cleanup());

class PhantomError extends Error {
  constructor(code, message, protocol, timeoutPhase) {
    super(message);
    this.name = 'PhantomError';
    this.code = code;
    this.protocol = protocol;
    this.timeoutPhase = timeoutPhase;
  }
}

function translated(error) {
  if (error instanceof PhantomError) return error;
  const request = /^PHANTOM_REQUEST:([A-Za-z0-9_]+):([A-Za-z0-9_]*):([A-Za-z0-9_]*):([\s\S]*)$/.exec(error?.message ?? '');
  if (request) return new PhantomError(request[1], request[4], request[2] || undefined, request[3] || undefined);
  const match = /^PHANTOM:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  return match
    ? new PhantomError(match[1], match[2])
    : new PhantomError('InvalidArgument', 'native argument conversion failed');
}

function integer(value, name, minimum = 0, maximum = 0xffffffff) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new PhantomError('InvalidArgument', `${name} is outside its supported integer range`);
  }
  return value;
}

function bytes(value) {
  if (!types.isUint8Array(value)) {
    throw new PhantomError('InvalidArgument', 'bytes must be a non-shared Uint8Array or Buffer');
  }
  const backing = apply(backingOf, value, []);
  if (types.isSharedArrayBuffer(backing)) throw new PhantomError('InvalidArgument', 'shared byte buffers are unsupported');
  return Buffer.isBuffer(value) ? value : Buffer.from(backing, apply(offsetOf, value, []), apply(lengthOf, value, []));
}

function phaseTimeouts(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new PhantomError('InvalidArgument', 'timeouts must be an object');
  }
  const names = {
    poolAdmissionMs: 'poolAdmission', connectMs: 'connect',
    responseHeadMs: 'responseHead', readIdleMs: 'readIdle', totalMs: 'total',
  };
  const result = {};
  for (const name of Object.keys(value)) {
    if (!Object.hasOwn(names, name)) throw new PhantomError('InvalidArgument', 'unknown timeout phase');
    const milliseconds = value[name];
    if (milliseconds !== undefined) {
      result[names[name]] = milliseconds === null
        ? {disabled: true, milliseconds: 0}
        : {disabled: false, milliseconds: integer(milliseconds, name)};
    }
  }
  return result;
}

class AttemptBudget {
  constructor(maximum) {
    budgetHandles.set(this, new native.NativeAttemptBudget(integer(maximum, 'maximum')));
  }
  get remaining() { return budgetHandles.get(this).remaining; }
}

class Response {
  #native;
  #cleanup;
  #owner;
  #reading = false;
  constructor(response, cleanup, owner) {
    this.#native = response;
    this.#cleanup = cleanup;
    this.#owner = owner;
    abandonedResponses.register(this, cleanup, this);
    this.status = response.status;
    this.protocol = response.protocol;
    this.url = response.url;
    this.redirects = response.redirects;
    this.connectionRetries = response.connectionRetries;
    this.headers = response.headers.map(({ name, value }) => ({ name, value }));
  }
  #finished() {
    this.#cleanup?.();
    this.#cleanup = undefined;
    this.#owner = undefined;
    abandonedResponses.unregister(this);
  }
  async read(maximumBytes = 65536) {
    integer(maximumBytes, 'maximumBytes', 1, 65536);
    if (this.#reading) throw new PhantomError('ConcurrentRead', 'only one body read may be pending');
    this.#reading = true;
    try {
      const part = await this.#native.read(maximumBytes);
      if (part === null) this.#finished();
      return part;
    } catch (error) {
      this.close();
      throw translated(error);
    } finally { this.#reading = false; }
  }
  async bytes(maximumBytes) {
    integer(maximumBytes, 'maximumBytes');
    if (this.#reading) {
      this.close();
      throw new PhantomError('ConcurrentRead', 'only one body read may be pending');
    }
    this.#reading = true;
    try {
      const body = await this.#native.collect(maximumBytes);
      this.#finished();
      return body;
    } catch (error) { this.close(); throw translated(error); }
    finally { this.#reading = false; }
  }
  async text(maximumBytes) {
    const body = await this.bytes(maximumBytes);
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(body);
    } catch {
      throw new PhantomError('TextDecode', 'response UTF-8 decoding failed');
    } finally { this.close(); }
  }
  async json(maximumBytes) {
    const text = await this.text(maximumBytes);
    try {
      return JSON.parse(text);
    } catch {
      throw new PhantomError('JsonDecode', 'response JSON parsing failed');
    }
  }
  close() { this.#native.close(); this.#finished(); }
  [Symbol.asyncIterator]() {
    const response = this;
    return {
      async next() {
        const value = await response.read();
        return value === null ? { done: true, value: undefined } : { done: false, value };
      },
      async return() { response.close(); return { done: true, value: undefined }; },
      async throw(error) { response.close(); throw error; },
      [Symbol.asyncIterator]() { return this; },
    };
  }
  async [Symbol.asyncDispose]() { this.close(); }
}

class Client {
  #native;
  constructor(options) {
    try {
      if (options.maximumActiveRequests !== undefined) integer(options.maximumActiveRequests, 'maximumActiveRequests', 1, 1024);
      this.#native = environment.client({
        ...options, additionalRoots: options.additionalRoots?.map(bytes),
        additionalProxyRoots: options.additionalProxyRoots?.map(bytes),
        timeouts: phaseTimeouts(options.timeouts),
      });
    } catch (error) { throw translated(error); }
  }
  async request(url, options) {
    const cancellation = new native.NativeCancellation();
    let signal;
    let abortListener;
    const abort = () => cancellation.cancel();
    const cleanup = () => { abortListener?.[Symbol.dispose](); abortListener = undefined; };
    try {
      if (options === null || typeof options !== 'object') throw new PhantomError('InvalidArgument', 'request options are required');
      if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new PhantomError('InvalidArgument', 'signal must be an AbortSignal');
      signal = options.signal;
      if (options.timeoutMs !== undefined) integer(options.timeoutMs, 'timeoutMs');
      if (options.file) integer(options.file.maximumBytes, 'maximumBytes');
      if (signal) abortListener = addAbortListener(signal, abort);
      if (signal?.aborted) abort();
      const budget = options.attemptBudget === undefined ? undefined : budgetHandles.get(options.attemptBudget);
      if (options.attemptBudget !== undefined && budget === undefined) throw new PhantomError('InvalidArgument', 'attemptBudget must be an AttemptBudget');
      const response = await this.#native.request({
        url, method: options.method, protocol: options.protocol, context: options.context,
        headers: options.headers?.map((header) => ({ ...header, value: bytes(header.value) })),
        body: options.body === undefined ? undefined : bytes(options.body),
        file: options.file, timeoutMs: options.timeoutMs, timeouts: phaseTimeouts(options.timeouts),
      }, cancellation, budget);
      if (signal?.aborted) { response.close(); throw new PhantomError('Cancelled', 'request was cancelled'); }
      return new Response(response, cleanup, this);
    } catch (error) { cancellation.cancel(); cleanup(); throw translated(error); }
  }
  setCookie(url, cookie) {
    try { this.#native.setCookie(url, cookie); } catch (error) { throw translated(error); }
  }
  cookieValue(url) {
    try { return this.#native.cookieValue(url); } catch (error) { throw translated(error); }
  }
  clearCookies() {
    try { this.#native.clearCookies(); } catch (error) { throw translated(error); }
  }
  clearDnsCache() {
    try { this.#native.clearDnsCache(); } catch (error) { throw translated(error); }
  }
  clearAltSvc() {
    try { this.#native.clearAltSvc(); } catch (error) { throw translated(error); }
  }
  clearClientHints() {
    try { this.#native.clearClientHints(); } catch (error) { throw translated(error); }
  }
  clearSessionTickets() {
    try { return this.#native.clearSessionTickets(); } catch (error) { throw translated(error); }
  }
  async closeIdleConnections() {
    try { await this.#native.closeIdleConnections(); } catch (error) { throw translated(error); }
  }
  async refreshConnections() {
    try { await this.#native.refreshConnections(); } catch (error) { throw translated(error); }
  }
  async close({ timeoutMs = 5000 } = {}) {
    integer(timeoutMs, 'timeoutMs');
    try { await this.#native.close(timeoutMs); } catch (error) { throw translated(error); }
  }
  async [Symbol.asyncDispose]() { await this.close(); }
}

module.exports = { AttemptBudget, Client, PhantomError, Response, profiles: () => native.profileIds() };
