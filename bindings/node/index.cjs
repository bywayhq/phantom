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
  constructor(code, message) {
    super(message);
    this.name = 'PhantomError';
    this.code = code;
  }
}

function translated(error) {
  if (error instanceof PhantomError) return error;
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
    const chunks = [];
    let length = 0;
    try {
      for (;;) {
        const chunk = await this.read(Math.min(65536, Math.max(1, maximumBytes - length + 1)));
        if (chunk === null) return Buffer.concat(chunks, length);
        length += chunk.length;
        if (length > maximumBytes) throw new PhantomError('ResponseBodyLimit', 'response exceeds maximumBytes');
        chunks.push(chunk);
      }
    } catch (error) { this.close(); throw error; }
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
      this.#native = environment.client({ ...options, additionalRoots: options.additionalRoots?.map(bytes) });
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
        file: options.file, timeoutMs: options.timeoutMs,
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
  async close({ timeoutMs = 5000 } = {}) {
    integer(timeoutMs, 'timeoutMs');
    try { await this.#native.close(timeoutMs); } catch (error) { throw translated(error); }
  }
  async [Symbol.asyncDispose]() { await this.close(); }
}

module.exports = { AttemptBudget, Client, PhantomError, Response, profiles: () => native.profileIds() };
