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
const profileHandles = new WeakMap();
const profileToken = {};
const clientToken = {};
const abandonedResponses = new FinalizationRegistry((cleanup) => cleanup());

class PhantomError extends Error {
  constructor(code, message, protocol, timeoutPhase, kind, field) {
    super(message);
    this.name = 'PhantomError';
    this.code = code;
    this.protocol = protocol;
    this.timeoutPhase = timeoutPhase;
    this.kind = kind;
    this.field = field;
  }
}

function translated(error) {
  if (error instanceof PhantomError) return error;
  const profile = /^PHANTOM_PROFILE:(ProfileImport|ProfileExport):([A-Za-z0-9_]+):([^:]*):([\s\S]*)$/.exec(error?.message ?? '');
  if (profile) return new PhantomError(profile[1], profile[4], undefined, undefined, profile[2], profile[3]);
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

function sessionSharing(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new PhantomError('InvalidArgument', 'sharing must be a plain object');
  }
  const result = {cookies: false, dns: false, clientHints: false, discovery: false, tickets: false};
  for (const name of Reflect.ownKeys(value)) {
    const field = Object.getOwnPropertyDescriptor(value, name);
    if (!Object.hasOwn(result, name) || !Object.hasOwn(field, 'value') || typeof field.value !== 'boolean') {
      throw new PhantomError('InvalidArgument', 'sharing selectors must be known boolean fields');
    }
    result[name] = field.value;
  }
  return result;
}

function policyFields(value, names) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new PhantomError('InvalidArgument', 'policy must be a plain data object');
  }
  const result = Object.create(null);
  for (const name of Reflect.ownKeys(value)) {
    const field = Object.getOwnPropertyDescriptor(value, name);
    if (!names.includes(name) || !Object.hasOwn(field, 'value')) {
      throw new PhantomError('InvalidArgument', 'policy contains an unknown or non-data field');
    }
    result[name] = field.value;
  }
  return result;
}

function contentDecoding(value) {
  if (value === undefined) return undefined;
  const copy = policyFields(value, ['mode', 'maximumDecodedBytes']);
  if (copy.mode === 'none' && !Object.hasOwn(copy, 'maximumDecodedBytes')) return {mode: 'none'};
  if (copy.mode === 'advertised') {
    const maximum = copy.maximumDecodedBytes;
    if ((typeof maximum === 'bigint' && maximum >= 0n && maximum <= 18446744073709551615n)
      || (typeof maximum === 'number' && Number.isSafeInteger(maximum) && maximum >= 0)) {
      return {mode: 'advertised', maximumDecodedBytes: BigInt(maximum)};
    }
  }
  throw new PhantomError('InvalidArgument', 'choose none or advertised with an exact unsigned u64 byte cap');
}

class AttemptBudget {
  constructor(maximum) {
    if (typeof maximum === 'number' && Number.isSafeInteger(maximum) && maximum >= 0) maximum = BigInt(maximum);
    if (typeof maximum !== 'bigint' || maximum < 0n) {
      throw new PhantomError('InvalidArgument', 'maximum must be a nonnegative safe integer or bigint');
    }
    try { budgetHandles.set(this, new native.NativeAttemptBudget(maximum)); }
    catch (error) { throw translated(error); }
  }
  get remaining() { return budgetHandles.get(this).remaining; }
  tryAdmit() {
    try { budgetHandles.get(this).tryAdmit(); }
    catch (error) { throw translated(error); }
  }
}

function profileHandle(value) {
  const handle = profileHandles.get(value);
  if (handle === undefined) throw new PhantomError('InvalidProfile', 'profile must be an exact identifier or a Profile');
  return handle;
}

function descriptionError(kind = 'InvalidValue') {
  return new PhantomError('ProfileImport', 'profile description rejected', undefined, undefined, kind, 'document');
}

function encodeDescription(document) {
  let remaining = 16 * 1024 * 1024;
  let nodes = 0;
  const active = new WeakSet();
  const charge = (length) => {
    remaining -= length;
    if (remaining < 0) throw descriptionError('TooLarge');
  };
  const string = (value) => {
    if (value.length > 65536 || Buffer.byteLength(value) > 65536) throw descriptionError('TooLarge');
    charge(Buffer.byteLength(JSON.stringify(value)));
  };
  // Snapshot data descriptors before stringify: getters/toJSON cannot change
  // validated values or expand them after the resource checks.
  const snapshot = (value, depth) => {
    if (depth > 16 || ++nodes > 1048576) throw descriptionError('TooLarge');
    if (typeof value === 'string') { string(value); return value; }
    if (typeof value === 'bigint') {
      if (value < 0n || value > 18446744073709551615n) throw descriptionError();
      charge(value.toString().length);
      return value;
    }
    if (value === null || typeof value === 'boolean') { charge(value === null ? 4 : value ? 4 : 5); return value; }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) throw descriptionError();
      charge(JSON.stringify(value).length);
      return value;
    }
    if (typeof value !== 'object' || types.isProxy(value) || active.has(value)) throw descriptionError();
    const array = Array.isArray(value);
    if (!array && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw descriptionError();
    if (Object.getOwnPropertySymbols(value).length !== 0) throw descriptionError();
    if (array && value.length > 65535) throw descriptionError('TooLarge');
    const result = array ? [] : Object.create(null);
    active.add(value);
    charge(2);
    let count = 0;
    for (const name in value) {
      if (!Object.hasOwn(value, name)) continue;
      if (++count > (array ? 65535 : 64)) throw descriptionError('TooLarge');
      if (array && name !== String(count - 1)) throw descriptionError();
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!Object.hasOwn(descriptor, 'value')) throw descriptionError();
      if (count > 1) charge(1);
      if (!array) { string(name); charge(1); }
      Object.defineProperty(result, name, {value: snapshot(descriptor.value, depth + 1), enumerable: true});
    }
    if (array && count !== value.length) throw descriptionError();
    active.delete(value);
    return result;
  };
  if (document === null || typeof document !== 'object' || types.isProxy(document) || Array.isArray(document)) throw descriptionError();
  const copy = snapshot(document, 0);
  return Buffer.from(JSON.stringify(copy, (_name, value) => typeof value === 'bigint' ? JSON.rawJSON(value.toString()) : value));
}

class Profile {
  constructor(token, handle) {
    if (token !== profileToken) throw new PhantomError('InvalidProfile', 'use Profile.fromCatalog or Profile.importJson');
    profileHandles.set(this, handle);
    Object.freeze(this);
  }
  static fromCatalog(identifier, context) {
    if (typeof identifier !== 'string' || (context !== undefined && typeof context !== 'string')) {
      throw new PhantomError('InvalidArgument', 'catalog identifier and optional context must be strings');
    }
    try { return new Profile(profileToken, native.profileCatalog(identifier, context)); }
    catch (error) { throw translated(error); }
  }
  static importJson(input) {
    try { return new Profile(profileToken, native.profileImportJson(bytes(input))); }
    catch (error) { throw translated(error); }
  }
  static fromDescription(document) { return Profile.importJson(encodeDescription(document)); }
  get catalogId() { return profileHandle(this).catalogId; }
  get contexts() { return Object.freeze(profileHandle(this).contexts); }
  exportJson() {
    try { return profileHandle(this).exportJson(); }
    catch (error) { throw translated(error); }
  }
  describe() {
    return JSON.parse(this.exportJson().toString('utf8'), (_name, value, context) =>
      typeof value === 'number' && !Number.isSafeInteger(value) ? BigInt(context.source) : value);
  }
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
    Object.defineProperty(this, 'decodedContentCodings', {
      value: Object.freeze(response.decodedContentCodings), enumerable: true,
    });
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
  constructor(options, token) {
    if (token === clientToken) { this.#native = options; return; }
    try {
      if (options.maximumActiveRequests !== undefined) integer(options.maximumActiveRequests, 'maximumActiveRequests', 1, 1024);
      this.#native = environment.client({
        ...options, profile: typeof options.profile === 'string' ? options.profile : undefined,
        additionalRoots: options.additionalRoots?.map(bytes),
        additionalProxyRoots: options.additionalProxyRoots?.map(bytes),
        timeouts: phaseTimeouts(options.timeouts),
      }, typeof options.profile === 'string' ? undefined : profileHandle(options.profile));
    } catch (error) { throw translated(error); }
  }
  fork(sharing = {}) {
    try { return new Client(environment.fork(this.#native, sessionSharing(sharing)), clientToken); }
    catch (error) { throw translated(error); }
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
        contentDecoding: contentDecoding(options.contentDecoding),
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
  clearAltSvcRacingHistory() {
    try { this.#native.clearAltSvcRacingHistory(); } catch (error) { throw translated(error); }
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

module.exports = { AttemptBudget, Client, PhantomError, Profile, Response, profiles: () => native.profileIds() };
