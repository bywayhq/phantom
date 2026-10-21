'use strict';

const { types, TextDecoder, inspect } = require('node:util');
const { addAbortListener } = require('node:events');
const { AsyncLocalStorage } = require('node:async_hooks');
const { Readable } = require('node:stream');
const { finished } = require('node:stream/promises');
const multipartClaims = new WeakSet();
const apply = Reflect.apply;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const backingOf = Object.getOwnPropertyDescriptor(typedArray, 'buffer').get;
const offsetOf = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset').get;
const lengthOf = Object.getOwnPropertyDescriptor(typedArray, 'byteLength').get;
const budgetHandles = new WeakMap();
const transferHandles = new WeakMap();
const diagnosticsHandles = new WeakMap();
const profileHandles = new WeakMap();
const preparedHandles = new WeakMap();
const certificateHandles = new WeakMap();
const certificateToken = {};
const preparedToken = {};
const profileToken = {};
const clientToken = {};
const abandonedResponses = new FinalizationRegistry((cleanup) => cleanup());
const uploadContext = new AsyncLocalStorage();

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

function loadNative() {
  const failure = (code, message, cause) => {
    const error = new PhantomError(code, message);
    if (cause !== undefined) Object.defineProperty(error, 'cause', {value: cause});
    return error;
  };
  const load = (name) => {
    try { return require(name); }
    catch (cause) { throw failure('NativeLoad', 'Phantom native library could not be loaded', cause); }
  };
  if (require('node:fs').existsSync(require('node:path').join(__dirname, 'phantom.node'))) {
    return load('./phantom.node');
  }
  let packageName;
  if (process.platform === 'win32' && process.arch === 'x64') packageName = '@byway/phantom-win32-x64-msvc';
  else if (process.platform === 'darwin' && process.arch === 'arm64') packageName = '@byway/phantom-darwin-arm64';
  else if (process.platform === 'linux' && process.arch === 'x64') {
    let glibc;
    try { glibc = process.report.getReport().header.glibcVersionRuntime; }
    catch (cause) { throw failure('NativePlatformUnsupported', 'Phantom requires a supported native host', cause); }
    if (typeof glibc === 'string' && glibc.length > 0) packageName = '@byway/phantom-linux-x64-gnu';
  }
  if (packageName === undefined) {
    throw failure('NativePlatformUnsupported', 'Phantom has no native package for this host');
  }
  let metadataPath;
  try { metadataPath = require.resolve(`${packageName}/package.json`); }
  catch (cause) {
    throw failure(cause?.code === 'MODULE_NOT_FOUND' ? 'NativePackageMissing' : 'NativeLoad',
      'Phantom requires its matching optional native package; install with optional dependencies enabled', cause);
  }
  const metadata = load(metadataPath);
  if (metadata.name !== packageName || metadata.version !== require('./package.json').version) {
    throw failure('NativePackageVersion', 'Phantom facade and native package versions must match exactly');
  }
  return load(packageName);
}

const native = loadNative();
const environment = new native.NativeEnvironment();

function translated(error) {
  if (error instanceof PhantomError) return error;
  const certificate = /^PHANTOM_CERTIFICATE:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  if (certificate) return new PhantomError('ClientCertificate', certificate[2], undefined, undefined, certificate[1]);
  const prepared = /^PHANTOM_PREPARED:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  if (prepared) return new PhantomError('PreparedBody', prepared[2], undefined, undefined, prepared[1]);
  const snapshot = /^PHANTOM_SNAPSHOT:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  if (snapshot) return new PhantomError('SessionSnapshot', snapshot[2], undefined, undefined, snapshot[1]);
  const profile = /^PHANTOM_PROFILE:(ProfileImport|ProfileExport):([A-Za-z0-9_]+):([^:]*):([\s\S]*)$/.exec(error?.message ?? '');
  if (profile) return new PhantomError(profile[1], profile[4], undefined, undefined, profile[2], profile[3]);
  const request = /^PHANTOM_REQUEST:([A-Za-z0-9_]+):([A-Za-z0-9_]*):([A-Za-z0-9_]*):([\s\S]*)$/.exec(error?.message ?? '');
  if (request) return new PhantomError(request[1], request[4], request[2] || undefined, request[3] || undefined);
  const match = /^PHANTOM:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  return match
    ? new PhantomError(match[1], match[2])
    : new PhantomError('InvalidArgument', 'native argument conversion failed');
}

function uploadError(error, outcome, preferSource = false) {
  const nativeError = translated(error);
  if (!outcome) return nativeError;
  const result = (preferSource || nativeError.code === 'RequestBody')
    && outcome.error && outcome.error !== outcome.cleanupError
    && !['Cancelled', 'Timeout'].includes(nativeError.code)
    ? outcome.error : nativeError;
  if (result !== nativeError) {
    for (const field of ['protocol', 'timeoutPhase', 'kind', 'field']) {
      if (result[field] === undefined) result[field] = nativeError[field];
    }
  }
  if (!Object.hasOwn(result, 'cleanupError')) {
    Object.defineProperties(result, {
      cause: {get: () => outcome.originalPresent ? outcome.original : outcome.cleanupOriginal},
      cleanupError: {get: () => outcome.cleanupOriginal},
      [inspect.custom]: {value: () => `PhantomError { code: ${inspect(result.code)}, protocol: ${inspect(result.protocol)}, timeoutPhase: ${inspect(result.timeoutPhase)}, upload details redacted }`},
    });
  }
  return result;
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

function clientPins(options, name) {
  if (options === null || typeof options !== 'object' || types.isProxy(options)) {
    throw new PhantomError('InvalidArgument', 'client options must be a data object');
  }
  const field = Object.getOwnPropertyDescriptor(options, name);
  if (field === undefined) return undefined;
  if (!Object.hasOwn(field, 'value')) throw new PhantomError('InvalidArgument', `${name} must be a data field`);
  const input = field.value;
  if (input === undefined) return undefined;
  if (!Array.isArray(input) || types.isProxy(input) || input.length < 1 || input.length > 32) {
    throw new PhantomError('InvalidArgument', `${name} requires one to 32 supplied digests`);
  }
  if (Reflect.ownKeys(input).length !== input.length + 1) throw new PhantomError('InvalidArgument', `${name} must contain only digest entries`);
  const copy = [];
  for (let index = 0; index < input.length; index++) {
    const entry = Object.getOwnPropertyDescriptor(input, String(index));
    if (!entry || !Object.hasOwn(entry, 'value')) throw new PhantomError('InvalidArgument', `${name} entries must be data fields`);
    let pin;
    try { pin = bytes(entry.value); }
    catch { throw new PhantomError('InvalidArgument', `${name} entries must be non-shared Uint8Array values`); }
    if (apply(lengthOf, pin, []) !== 32) throw new PhantomError('InvalidArgument', `${name} entries must contain exactly 32 bytes`);
    copy.push(pin);
  }
  return copy;
}

function certificateFailure(kind) {
  return new PhantomError('ClientCertificate', 'client certificate configuration failed', undefined, undefined, kind);
}

function certificateArray(input, maximum, name) {
  if (!Array.isArray(input) || types.isProxy(input) || input.length > maximum
    || Reflect.ownKeys(input).length !== input.length + 1) {
    throw new PhantomError('InvalidArgument', `${name} must be a bounded ordered data array`);
  }
  const result = [];
  for (let index = 0; index < input.length; index++) {
    const field = Object.getOwnPropertyDescriptor(input, String(index));
    if (!field || !Object.hasOwn(field, 'value')) throw new PhantomError('InvalidArgument', `${name} entries must be data fields`);
    result.push(field.value);
  }
  return result;
}

function certificateHandle(value) {
  const owner = certificateHandles.get(value);
  if (!owner) throw new PhantomError('InvalidArgument', 'client certificate must be an authentic ClientCertificate');
  return owner;
}

class ClientCertificate {
  constructor(owner, token) {
    if (token !== certificateToken) throw new PhantomError('InvalidArgument', 'use ClientCertificate.fromPem or fromDer');
    certificateHandles.set(this, owner);
    Object.defineProperty(this, inspect.custom, {value: () => 'ClientCertificate {}'});
    Object.freeze(this);
  }
  static async fromPem(certificateChain, privateKey) {
    try {
      const chain = bytes(certificateChain), key = bytes(privateKey);
      if (apply(lengthOf, chain, []) + apply(lengthOf, key, []) > 16 * 1024 * 1024) throw certificateFailure('too_large');
      return new ClientCertificate(await native.clientCertificatePem(chain, key), certificateToken);
    } catch (error) { throw translated(error); }
  }
  static async fromDer(certificateChain, privateKey) {
    try {
      if (Array.isArray(certificateChain) && !types.isProxy(certificateChain)
        && (certificateChain.length === 0 || certificateChain.length > 256)) throw certificateFailure('invalid_chain_count');
      const chain = certificateArray(certificateChain, 256, 'certificateChain');
      const key = bytes(privateKey), inputs = chain.map(bytes);
      let total = apply(lengthOf, key, []);
      for (const input of inputs) total += apply(lengthOf, input, []);
      if (total > 16 * 1024 * 1024) throw certificateFailure('too_large');
      return new ClientCertificate(await native.clientCertificateDer(inputs, key), certificateToken);
    } catch (error) { throw translated(error); }
  }
}

function clientCertificates(options) {
  const field = (name) => {
    const descriptor = Object.getOwnPropertyDescriptor(options, name);
    if (descriptor === undefined) return undefined;
    if (!Object.hasOwn(descriptor, 'value')) throw new PhantomError('InvalidArgument', `${name} must be a data field`);
    return descriptor.value;
  };
  const defaultOwner = field('clientCertificate'), origins = field('clientCertificatesFor');
  const result = {clientCertificate: defaultOwner === undefined ? undefined : certificateHandle(defaultOwner)};
  if (origins === undefined) return result;
  const input = certificateArray(origins, 256, 'clientCertificatesFor');
  let total = 0;
  const pairs = [];
  for (const value of input) {
    const pair = certificateArray(value, 2, 'clientCertificatesFor pair');
    if (pair.length !== 2 || typeof pair[0] !== 'string') throw new PhantomError('InvalidArgument', 'clientCertificatesFor requires origin and certificate pairs');
    const count = Buffer.byteLength(pair[0]);
    total += count;
    if (count > 65536 || total > 16 * 1024 * 1024) throw new PhantomError('InputLimit', 'clientCertificatesFor exceeds its byte limit');
    pairs.push({origin: pair[0], certificate: certificateHandle(pair[1])});
  }
  result.clientCertificatesFor = pairs;
  return result;
}

function requestFields(headers, trailers) {
  for (const [name, fields] of [['headers', headers], ['trailers', trailers]]) {
    if (fields !== undefined && (!Array.isArray(fields) || types.isProxy(fields))) {
      throw new PhantomError('InvalidArgument', `${name} must be an ordered array`);
    }
  }
  if ((headers?.length ?? 0) + (trailers?.length ?? 0) > 256) {
    throw new PhantomError('InputLimit', 'headers and trailers exceed 256 fields');
  }
  let remaining = 65536;
  const copy = (fields, name) => fields?.map((header) => {
    const field = name === 'headers' ? {...header, value: bytes(header.value)}
      : policyFields(header, ['name', 'value', 'sensitive']);
    if (typeof field.name !== 'string' || (field.sensitive !== undefined && typeof field.sensitive !== 'boolean')) {
      throw new PhantomError('InvalidArgument', `${name} entries require a string name and optional boolean sensitive`);
    }
    field.value = bytes(field.value);
    remaining -= Buffer.byteLength(field.name, 'utf8') + apply(lengthOf, field.value, []);
    if (remaining < 0) throw new PhantomError('InputLimit', 'headers and trailers exceed 65536 bytes');
    return field;
  });
  return {headers: copy(headers, 'headers'), trailers: copy(trailers, 'trailers')};
}

function expectContinue(value) {
  if (value === undefined) return undefined;
  if ((typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
    || (typeof value === 'bigint' && value >= 0n && value <= 0xffffffffffffffffn)) return BigInt(value);
  throw new PhantomError('InvalidArgument', 'expectContinueMs must be an exact nonnegative u64 integer');
}

function preparedFailure(kind) {
  return new PhantomError('PreparedBody', 'request body preparation failed', undefined, undefined, kind);
}

function preparedOptions(options, multipart) {
  const fields = policyFields(options, multipart ? ['boundary', 'maximumBytes'] : ['maximumBytes']);
  const value = fields.maximumBytes;
  if (!((typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
    || (typeof value === 'bigint' && value >= 0n && value <= 0xffffffffffffffffn))) {
    throw new PhantomError('InvalidArgument', 'maximumBytes must be an exact nonnegative u64 integer');
  }
  if (multipart && typeof fields.boundary !== 'string') throw new PhantomError('InvalidArgument', 'boundary must be a string');
  return {...fields, maximumBytes: BigInt(value)};
}

function preparedArray(value) {
  if (!Array.isArray(value) || types.isProxy(value)) throw new PhantomError('InvalidArgument', 'body fields must be an ordered array');
  // Reject accessors before reading entries; sparse arrays are not field lists.
  for (let index = 0; index < value.length; index++) {
    if (!Object.hasOwn(Object.getOwnPropertyDescriptor(value, String(index)) ?? {}, 'value')) {
      throw new PhantomError('InvalidArgument', 'body fields must contain data entries');
    }
  }
}

class PreparedBody {
  constructor(handle, token) {
    if (token !== preparedToken) throw new PhantomError('InvalidArgument', 'use a PreparedBody factory');
    preparedHandles.set(this, handle);
    Object.defineProperties(this, {
      contentType: {value: handle.contentType, enumerable: true},
      byteLength: {value: handle.byteLength, enumerable: true},
      [inspect.custom]: {value: () => `PreparedBody { byteLength: ${handle.byteLength}n }`},
    });
    Object.freeze(this);
  }
  static async form(pairs, options) {
    try {
      const {maximumBytes} = preparedOptions(options, false);
      if (!Array.isArray(pairs) || types.isProxy(pairs)) throw new PhantomError('InvalidArgument', 'form pairs must be an ordered array');
      if (BigInt(pairs.length) > maximumBytes) throw preparedFailure('too_large');
      preparedArray(pairs);
      let remaining = maximumBytes;
      const fields = [];
      for (let index = 0; index < pairs.length; index++) {
        const pair = pairs[index];
        if (!Array.isArray(pair) || types.isProxy(pair) || pair.length !== 2) throw new PhantomError('InvalidArgument', 'form pairs require two strings');
        preparedArray(pair);
        const name = pair[0], value = pair[1];
        if (typeof name !== 'string' || typeof value !== 'string') throw new PhantomError('InvalidArgument', 'form pairs require two strings');
        remaining -= BigInt(Buffer.byteLength(name) + Buffer.byteLength(value) + 1);
        if (remaining < 0n) throw preparedFailure('too_large');
        fields.push({name, value});
      }
      return new PreparedBody(await native.preparedForm(fields, maximumBytes), preparedToken);
    } catch (error) { throw translated(error); }
  }
  static async multipart(parts, options) {
    try {
      const {boundary, maximumBytes} = preparedOptions(options, true);
      if (!Array.isArray(parts) || types.isProxy(parts)) throw new PhantomError('InvalidArgument', 'multipart parts must be an ordered array');
      if (parts.length > 1024) throw preparedFailure('too_many_parts');
      preparedArray(parts);
      let remaining = maximumBytes - BigInt(Buffer.byteLength(boundary));
      const fields = [];
      for (let index = 0; index < parts.length; index++) {
        const part = policyFields(parts[index], ['name', 'text', 'bytes', 'filename', 'contentType']);
        if (typeof part.name !== 'string' || (part.text === undefined) === (part.bytes === undefined)
          || (part.text !== undefined && typeof part.text !== 'string')) {
          throw new PhantomError('InvalidArgument', 'multipart part requires a string name and exactly one text or bytes field');
        }
        for (const field of ['name', 'filename', 'contentType']) {
          if (part[field] === undefined && field !== 'name') continue;
          if (typeof part[field] !== 'string') throw new PhantomError('InvalidArgument', `multipart ${field} must be a string`);
          const count = Buffer.byteLength(part[field]);
          if (count > 4096) throw preparedFailure('too_large');
          remaining -= BigInt(count);
        }
        if (part.bytes !== undefined) part.bytes = bytes(part.bytes);
        remaining -= BigInt(part.text === undefined ? apply(lengthOf, part.bytes, []) : Buffer.byteLength(part.text));
        if (remaining < 0n) throw preparedFailure('too_large');
        fields.push(part);
      }
      return new PreparedBody(await native.preparedMultipart(boundary, fields, maximumBytes), preparedToken);
    } catch (error) { throw translated(error); }
  }
}

function multipartOptions(value) {
  if (value === undefined) return undefined;
  const options = policyFields(value, ['boundary', 'maximumBytes', 'parts']);
  const {boundary, maximumBytes} = preparedOptions({boundary: options.boundary, maximumBytes: options.maximumBytes}, true);
  const parts = options.parts;
  if (!Array.isArray(parts) || types.isProxy(parts)) throw new PhantomError('InvalidArgument', 'multipart parts must be an ordered array');
  if (parts.length > 1024) throw preparedFailure('too_many_parts');
  preparedArray(parts);
  let metadata = 65536, remaining = maximumBytes;
  const fields = [], sources = [], identities = new Set();
  for (const input of parts) {
    const part = policyFields(input, ['name', 'text', 'bytes', 'stream', 'file', 'filename', 'contentType']);
    if (['text', 'bytes', 'stream', 'file'].filter((key) => part[key] !== undefined).length !== 1) throw new PhantomError('InvalidArgument', 'multipart part requires one payload');
    for (const key of ['name', 'filename', 'contentType']) {
      if (part[key] === undefined && key !== 'name') continue;
      if (typeof part[key] !== 'string') throw new PhantomError('InvalidArgument', `multipart ${key} must be a string`);
      const count = Buffer.byteLength(part[key]);
      metadata -= count;
      if (count > 4096 || metadata < 0) throw new PhantomError('InputLimit', 'multipart metadata exceeds its limit');
    }
    const field = {...part};
    let source;
    if (part.text !== undefined) {
      if (typeof part.text !== 'string') throw new PhantomError('InvalidArgument', 'multipart text must be a string');
      remaining -= BigInt(Buffer.byteLength(part.text));
    } else if (part.bytes !== undefined) {
      field.bytes = bytes(part.bytes); remaining -= BigInt(apply(lengthOf, field.bytes, []));
    } else if (part.file !== undefined) {
      const file = policyFields(part.file, ['path', 'maximumBytes']);
      if (typeof file.path !== 'string' || !file.path.length || Buffer.byteLength(file.path) > 4096) throw new PhantomError('InvalidArgument', 'multipart file requires a bounded path');
      integer(file.maximumBytes, 'multipart file maximumBytes');
      metadata -= Buffer.byteLength(file.path);
      if (metadata < 0) throw new PhantomError('InputLimit', 'multipart metadata exceeds its limit');
      field.file = file;
    } else {
      source = part.stream;
      if (source === null || typeof source !== 'object' || types.isProxy(source)
        || (!(source instanceof Readable) && (typeof source.next !== 'function' || typeof source.return !== 'function' || typeof source[Symbol.asyncIterator] !== 'function'))) {
        throw new PhantomError('InvalidArgument', 'multipart stream must be a Readable or closeable async iterator');
      }
      if (identities.has(source)) throw new PhantomError('InvalidArgument', 'multipart sources must be distinct');
      identities.add(source); field.stream = true;
    }
    if (remaining < 0n) throw preparedFailure('too_large');
    fields.push(field); sources.push(source);
  }
  if (multipartClaims.has(value)) throw new PhantomError('InvalidOperation', 'multipart belongs to one request');
  return {descriptor: value, boundary, maximumBytes, fields, sources};
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

function checkpointKey(value) {
  const key = bytes(value);
  if (apply(lengthOf, key, []) !== 32) throw new PhantomError('SessionSnapshot', 'session checkpoint failed', undefined, undefined, 'invalid_key_length');
  return key;
}

function receivingRoutes(options) {
  const fields = policyFields(options, ['receivingRoutes']);
  const routes = fields.receivingRoutes === undefined ? [] : fields.receivingRoutes;
  if (!Array.isArray(routes) || types.isProxy(routes)) throw new PhantomError('InvalidArgument', 'receivingRoutes must be a data array');
  if (routes.length > 256) throw new PhantomError('SessionSnapshot', 'session checkpoint failed', undefined, undefined, 'too_large');
  if (Reflect.ownKeys(routes).length !== routes.length + 1) throw new PhantomError('InvalidArgument', 'receivingRoutes must contain only route entries');
  const result = [];
  for (let index = 0; index < routes.length; index++) {
    const field = Object.getOwnPropertyDescriptor(routes, String(index));
    if (!field || !Object.hasOwn(field, 'value')) throw new PhantomError('InvalidArgument', 'receivingRoutes must contain data entries');
    const route = policyFields(field.value, ['route', 'proxy', 'proxyUsername', 'proxyPassword']);
    if (route.route === 'direct') {
      if (route.proxy !== undefined || route.proxyUsername !== undefined || route.proxyPassword !== undefined) throw new PhantomError('InvalidArgument', 'a direct receiving route cannot include a proxy');
    } else if (route.route !== 'proxy' || typeof route.proxy !== 'string'
      || (route.proxyUsername !== undefined && typeof route.proxyUsername !== 'string')
      || (route.proxyPassword !== undefined && typeof route.proxyPassword !== 'string')
      || (route.proxyUsername === undefined) !== (route.proxyPassword === undefined)) {
      throw new PhantomError('InvalidArgument', 'receiving proxy routes require a URI and paired string credentials');
    }
    result.push(route);
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

function redirectPolicy(value) {
  if (value === undefined) return undefined;
  const copy = policyFields(value, ['mode', 'maximumHops']);
  if (copy.mode === 'none' && !Object.hasOwn(copy, 'maximumHops')) return {mode: 'none'};
  if (copy.mode === 'limited') return {
    mode: 'limited', maximumHops: positiveCount(copy.maximumHops),
  };
  throw new PhantomError('InvalidArgument', 'choose none or limited with a positive hop count');
}

function positiveCount(value) {
  if ((typeof value === 'bigint' && value > 0n && value <= 18446744073709551615n)
    || (typeof value === 'number' && Number.isSafeInteger(value) && value > 0)) {
    return BigInt(value);
  }
  throw new PhantomError('InvalidArgument', 'count must be a positive exact integer fitting the native pointer size');
}

function retryDelay(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new PhantomError('InvalidArgument', 'retry delays must be finite nonnegative milliseconds');
  }
  return value;
}

function retryBoolean(value) {
  if (typeof value !== 'boolean') throw new PhantomError('InvalidArgument', 'retry selections must be boolean');
  return value;
}

function retryStatuses(value) {
  if (!Array.isArray(value) || types.isProxy(value)
    || Reflect.ownKeys(value).length !== value.length + 1) {
    throw new PhantomError('InvalidArgument', 'retry statuses must be a data-only array');
  }
  const unique = new Set();
  for (let index = 0; index < value.length; index++) {
    const field = Object.getOwnPropertyDescriptor(value, String(index));
    if (field === undefined || !Object.hasOwn(field, 'value')) {
      throw new PhantomError('InvalidArgument', 'retry statuses must be a data-only array');
    }
    unique.add(integer(field.value, 'retry status', 100, 999));
  }
  return [...unique];
}

function retrySchedule(value, status) {
  const copy = policyFields(value, status
    ? ['statuses', 'maximum', 'delayMs', 'maximumDelayMs', 'fullJitter', 'retryAfterLimitMs']
    : ['maximum', 'delayMs', 'maximumDelayMs', 'fullJitter']);
  const result = {maximum: positiveCount(copy.maximum), delayMs: retryDelay(copy.delayMs)};
  if (copy.maximumDelayMs !== undefined) result.maximumDelayMs = retryDelay(copy.maximumDelayMs);
  if (copy.fullJitter !== undefined) result.fullJitter = retryBoolean(copy.fullJitter);
  if (status) {
    result.statuses = retryStatuses(copy.statuses);
    if (copy.retryAfterLimitMs !== undefined) result.retryAfterLimitMs = retryDelay(copy.retryAfterLimitMs);
  }
  return result;
}

function retryPolicy(value) {
  if (value === undefined) return undefined;
  const copy = policyFields(value, ['connectionFailures', 'reusedConnectionReplay', 'unprocessedReplays',
    'statusRetry', 'maximumRetries', 'http2Fallback']);
  const result = {};
  if (copy.connectionFailures !== undefined) result.connectionFailures = retrySchedule(copy.connectionFailures, false);
  if (copy.statusRetry !== undefined) result.statusRetry = retrySchedule(copy.statusRetry, true);
  if (copy.unprocessedReplays !== undefined) result.unprocessedReplays = positiveCount(copy.unprocessedReplays);
  if (copy.maximumRetries !== undefined) result.maximumRetries = copy.maximumRetries === 0 || copy.maximumRetries === 0n
    ? 0n : positiveCount(copy.maximumRetries);
  if (copy.reusedConnectionReplay !== undefined) result.reusedConnectionReplay = retryBoolean(copy.reusedConnectionReplay);
  if (copy.http2Fallback !== undefined) result.http2Fallback = retryBoolean(copy.http2Fallback);
  return result;
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

function diagnosticRecord(value, label) {
  return Object.freeze(Object.defineProperty(value, inspect.custom, {
    value: () => `${label} { details omitted }`,
  }));
}

function diagnosticTls(value) {
  const info = value.info;
  return diagnosticRecord({state: value.state, info: info == null ? null : diagnosticRecord({
    ...info, versionId: info.versionId ?? null, cipherSuiteId: info.cipherSuiteId ?? null,
    alpn: info.alpn ?? null,
    peerCertificatesDer: info.peerCertificatesDer == null ? null : Object.freeze(info.peerCertificatesDer),
  }, 'TLSConnectionInfo')}, 'TLSConnectionState');
}

class RequestDiagnostics {
  constructor(options = {}) {
    const copy = policyFields(options, ['maximumEvents']);
    const maximum = copy.maximumEvents === undefined ? 128n : positiveCount(copy.maximumEvents);
    try { diagnosticsHandles.set(this, new native.NativeRequestDiagnostics(maximum)); }
    catch (error) { throw translated(error); }
    Object.freeze(this);
  }
  snapshot() {
    const handle = diagnosticsHandles.get(this);
    if (handle === undefined) throw new PhantomError('InvalidArgument', 'receiver must be RequestDiagnostics');
    let snapshot;
    try { snapshot = handle.snapshot(); } catch (error) { throw translated(error); }
    if (snapshot == null) return null;
    return diagnosticRecord({...snapshot, sendElapsedNs: snapshot.sendElapsedNs ?? null,
      events: Object.freeze(snapshot.events.map((event) => diagnosticRecord({...event,
        admission: event.admission ?? null, protocol: event.protocol ?? null,
        finishedNs: event.finishedNs ?? null,
        connection: event.connection == null ? null : diagnosticRecord({...event.connection,
          localAddress: event.connection.localAddress ?? null, peerAddress: event.connection.peerAddress ?? null,
          originTls: diagnosticTls(event.connection.originTls), proxyTls: diagnosticTls(event.connection.proxyTls),
        }, 'RequestConnection'),
      }, 'RequestTiming'))),
    }, 'RequestTimeline');
  }
}

class TransferControl {
  constructor(limits = {}) {
    const copy = policyFields(limits, ['uploadBytes', 'downloadBytes', 'uploadBytesPerSecond', 'downloadBytesPerSecond']);
    const options = {};
    for (const [name, value] of Object.entries(copy)) {
      if (value === undefined) continue;
      const minimum = name.endsWith('PerSecond') ? 1n : 0n;
      const exact = typeof value === 'number' && Number.isSafeInteger(value) ? BigInt(value) : value;
      if (typeof exact !== 'bigint' || exact < minimum || exact > 0xffffffffffffffffn) {
        throw new PhantomError('InvalidArgument', `${name} must be an exact u64 ${minimum === 1n ? 'positive rate' : 'byte cap'}`);
      }
      options[name] = exact;
    }
    try { transferHandles.set(this, new native.NativeTransferControl(options)); }
    catch (error) { throw translated(error); }
    Object.freeze(this);
  }
  snapshot() {
    const handle = transferHandles.get(this);
    if (handle === undefined) throw new PhantomError('InvalidArgument', 'receiver must be a TransferControl');
    try { return Object.freeze(handle.snapshot()); }
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
  static #import(input, options, method, binary = false) {
    if (options === null || typeof options !== 'object' || types.isProxy(options) || Array.isArray(options)) {
      throw new PhantomError('InvalidArgument', 'imports require an explicit base Profile');
    }
    const properties = Object.getOwnPropertyDescriptors(options);
    if (Object.keys(properties).some((name) => !['base', ...(method === 'importJa4' ? ['format'] : [])].includes(name))
      || Object.values(properties).some((property) => !Object.hasOwn(property, 'value'))) {
      throw new PhantomError('InvalidArgument', 'import options must contain only base and the required JA4 format');
    }
    const handle = profileHandle(properties.base?.value);
    const format = properties.format?.value;
    if (method === 'importJa4' && format !== 'sorted' && format !== 'original') {
      throw new PhantomError('ProfileImport', 'profile description rejected', undefined, undefined, 'InvalidValue', 'ja4.format');
    }
    if (!binary && typeof input !== 'string') throw new PhantomError('InvalidArgument', 'fingerprint description must be a string');
    try {
      const imported = method === 'importJa4' ? handle[method](input, format) : handle[method](binary ? bytes(input) : input);
      return Object.freeze({
        profile: new Profile(profileToken, imported.profile),
        observedFields: Object.freeze([...imported.observedFields]),
        supplementedFields: Object.freeze([...imported.supplementedFields]),
      });
    } catch (error) { throw translated(error); }
  }
  static importJa3(description, options) { return Profile.#import(description, options, 'importJa3'); }
  static importClientHello(handshake, options) { return Profile.#import(handshake, options, 'importClientHello', true); }
  static importAkamai(description, options) { return Profile.#import(description, options, 'importAkamai'); }
  static importJa4(description, options) { return Profile.#import(description, options, 'importJa4'); }
  static importQuicTransport(parameters, options) { return Profile.#import(parameters, options, 'importQuicTransport', true); }
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
  #upload;
  #reading = false;
  constructor(response, cleanup, owner, upload) {
    this.#native = response;
    this.#cleanup = cleanup;
    this.#owner = owner;
    this.#upload = upload;
    abandonedResponses.register(this, cleanup, this);
    this.status = response.status;
    this.protocol = response.protocol;
    this.url = response.url;
    this.redirects = response.redirects;
    this.connectionRetries = response.connectionRetries;
    Object.defineProperty(this, 'decodedContentCodings', {
      value: Object.freeze(response.decodedContentCodings), enumerable: true,
    });
    const history = response.redirectHistory;
    Object.defineProperty(this, 'redirectHistory', {
      value: history == null ? null : Object.freeze(Object.defineProperty({
        entries: Object.freeze(history.entries.map((hop) => Object.freeze(Object.defineProperty(
          {...hop}, inspect.custom, {value: () => 'RedirectHop { URLs redacted }'},
        )))),
        omittedHops: history.omittedHops,
      }, inspect.custom, {value: () => 'RedirectHistory { URLs redacted }'})), enumerable: true,
    });
    this.headers = Object.freeze(response.headers.map(({name, value, sensitive}) =>
      Object.freeze({name, value, sensitive})));
  }
  get trailers() {
    try {
      const snapshot = this.#native.trailers;
      switch (snapshot.state) {
        case 'pending': case 'unavailable':
          return Object.freeze({state: snapshot.state, headers: null});
        case 'complete':
          return Object.freeze({state: 'complete', headers: Object.freeze(snapshot.headers.map(
            ({name, value, sensitive}) => Object.freeze({name, value, sensitive}),
          ))});
        default: throw new PhantomError('UnsupportedResponseTrailers', 'unsupported response trailer state');
      }
    } catch (error) { throw translated(error); }
  }
  #finished() {
    this.#cleanup?.();
    this.#cleanup = undefined;
    this.#owner = undefined;
    abandonedResponses.unregister(this);
  }
  #checkMultipartWait() {
    if (this.#upload?.multipart && this.#upload.context !== undefined && uploadContext.getStore() === this.#upload.context) throw new PhantomError('InvalidOperation', 'an upload producer cannot await its own response');
  }
  async #settleMultipart() {
    if (!this.#upload?.multipart) return;
    await this.#upload.finished;
    if (this.#upload.error) throw uploadError(this.#upload.error, this.#upload, true);
  }
  async read(maximumBytes = 65536) {
    this.#checkMultipartWait();
    integer(maximumBytes, 'maximumBytes', 1, 65536);
    if (this.#reading) throw new PhantomError('ConcurrentRead', 'only one body read may be pending');
    this.#reading = true;
    try {
      const part = await this.#native.read(maximumBytes);
      if (part === null) { this.#finished(); await this.#settleMultipart(); }
      return part;
    } catch (error) {
      this.close();
      throw uploadError(error, this.#upload);
    } finally { this.#reading = false; }
  }
  async bytes(maximumBytes) {
    this.#checkMultipartWait();
    integer(maximumBytes, 'maximumBytes');
    if (this.#reading) {
      this.close();
      throw new PhantomError('ConcurrentRead', 'only one body read may be pending');
    }
    this.#reading = true;
    try {
      const body = await this.#native.collect(maximumBytes);
      this.#finished();
      await this.#settleMultipart();
      return body;
    } catch (error) { this.close(); throw uploadError(error, this.#upload); }
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
  async [Symbol.asyncDispose]() { this.#checkMultipartWait(); this.close(); await this.#settleMultipart(); }
}

class Client {
  #native;
  #uploads = new Set();
  #uploadCleanupError;
  #trackUpload(iterator, upload, outcome) {
    outcome.context = this;
    const pumping = uploadContext.run(this, () => outcome.multipart ? pumpMultipart(iterator, upload, outcome) : pumpUpload(iterator, upload, outcome));
    outcome.finished = pumping;
    this.#uploads.add(pumping);
    const settled = () => {
      this.#uploads.delete(pumping);
      outcome.context = undefined;
      this.#uploadCleanupError ??= outcome.cleanupError;
    };
    pumping.then(settled, settled);
  }
  constructor(options, token) {
    if (token === clientToken) { this.#native = options; return; }
    try {
      const serverSpkiPins = clientPins(options, 'serverSpkiPins');
      const proxyServerSpkiPins = clientPins(options, 'proxyServerSpkiPins');
      const certificates = clientCertificates(options);
      if (options.maximumActiveRequests !== undefined) integer(options.maximumActiveRequests, 'maximumActiveRequests', 1, 1024);
      this.#native = environment.client({
        ...options, profile: typeof options.profile === 'string' ? options.profile : undefined,
        additionalRoots: options.additionalRoots?.map(bytes),
        additionalProxyRoots: options.additionalProxyRoots?.map(bytes),
        serverSpkiPins, proxyServerSpkiPins, ...certificates,
        timeouts: phaseTimeouts(options.timeouts),
        redirectPolicy: redirectPolicy(options.redirectPolicy),
        retryPolicy: retryPolicy(options.retryPolicy),
      }, typeof options.profile === 'string' ? undefined : profileHandle(options.profile));
    } catch (error) { throw translated(error); }
  }
  fork(sharing = {}) {
    try { return new Client(environment.fork(this.#native, sessionSharing(sharing)), clientToken); }
    catch (error) { throw translated(error); }
  }
  async exportSession(key) {
    try { return await this.#native.exportSession(checkpointKey(key)); }
    catch (error) { throw translated(error); }
  }
  async restoreSession(snapshot, key, options = {}) {
    try {
      const input = bytes(snapshot);
      if (apply(lengthOf, input, []) > 32 * 1024 * 1024) throw new PhantomError('SessionSnapshot', 'session checkpoint failed', undefined, undefined, 'too_large');
      const restored = await environment.restoreSession(this.#native, input, checkpointKey(key), receivingRoutes(options));
      return new Client(restored, clientToken);
    } catch (error) { throw translated(error); }
  }
  async request(url, options) {
    const cancellation = new native.NativeCancellation();
    let signal;
    let abortListener;
    let upload;
    let producer;
    let iterator;
    let multipartUpload = false;
    const abort = () => cancellation.cancel();
    const cleanup = () => { upload?.stop(); abortListener?.[Symbol.dispose](); abortListener = undefined; };
    try {
      if (options === null || typeof options !== 'object') throw new PhantomError('InvalidArgument', 'request options are required');
      if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new PhantomError('InvalidArgument', 'signal must be an AbortSignal');
      signal = options.signal;
      if (options.timeoutMs !== undefined) integer(options.timeoutMs, 'timeoutMs');
      if (options.file) integer(options.file.maximumBytes, 'maximumBytes');
      const fields = requestFields(options.headers, options.trailers);
      const continueWait = expectContinue(options.expectContinueMs);
      if (options.multipart !== undefined && (options.body !== undefined || options.file !== undefined || options.bodyLength !== undefined)) throw new PhantomError('InvalidArgument', 'multipart cannot be combined with body, file or bodyLength');
      const multipart = multipartOptions(options.multipart);
      const prepared = options.body === undefined ? undefined : preparedHandles.get(options.body);
      const streaming = options.body !== undefined && prepared === undefined && !types.isUint8Array(options.body);
      if (options.file !== undefined && options.body !== undefined) throw new PhantomError('InvalidArgument', 'choose body or file');
      if (options.bodyLength !== undefined && (options.body === undefined || options.file !== undefined)) {
        throw new PhantomError('InvalidArgument', 'bodyLength requires a body');
      }
      const length = options.bodyLength === undefined ? undefined : uploadLength(options.bodyLength);
      if (prepared !== undefined && length !== undefined && prepared.byteLength !== length) {
        throw new PhantomError('UploadLength', 'body does not match bodyLength');
      }
      const byteBody = options.body === undefined || streaming || prepared !== undefined ? undefined : bytes(options.body);
      if (byteBody !== undefined && length !== undefined && BigInt(apply(lengthOf, byteBody, [])) !== length) {
        throw new PhantomError('UploadLength', 'body does not match bodyLength');
      }
      if (streaming) {
        if (typeof options.body?.[Symbol.asyncIterator] !== 'function') throw new PhantomError('InvalidArgument', 'body must be bytes or an AsyncIterable of bytes');
        iterator = options.body[Symbol.asyncIterator]();
        if (iterator === null || typeof iterator?.next !== 'function') throw new PhantomError('InvalidArgument', 'body must provide an async iterator');
        upload = new native.NativeUpload(length);
      }
      if (signal) abortListener = addAbortListener(signal, abort);
      if (signal?.aborted) abort();
      const budget = options.attemptBudget === undefined ? undefined : budgetHandles.get(options.attemptBudget);
      if (options.attemptBudget !== undefined && budget === undefined) throw new PhantomError('InvalidArgument', 'attemptBudget must be an AttemptBudget');
      const transfer = options.transferControl === undefined ? undefined : transferHandles.get(options.transferControl);
      if (options.transferControl !== undefined && transfer === undefined) throw new PhantomError('InvalidArgument', 'transferControl must be a TransferControl');
      const diagnostics = options.diagnostics === undefined ? undefined : diagnosticsHandles.get(options.diagnostics);
      if (options.diagnostics !== undefined && diagnostics === undefined) throw new PhantomError('InvalidArgument', 'diagnostics must be RequestDiagnostics');
      const policies = {
        timeouts: phaseTimeouts(options.timeouts), contentDecoding: contentDecoding(options.contentDecoding),
        redirectPolicy: redirectPolicy(options.redirectPolicy), retryPolicy: retryPolicy(options.retryPolicy),
        redirectHistoryLimit: options.redirectHistoryLimit === undefined ? undefined : positiveCount(options.redirectHistoryLimit),
      };
      if (multipart) {
        const candidate = new native.NativeUpload();
        candidate.configureMultipart(multipart.boundary, multipart.fields, multipart.maximumBytes);
        multipartClaims.add(multipart.descriptor);
        upload = candidate; iterator = multipart.sources; multipartUpload = true;
      }
      const extra = diagnostics === undefined ? [] : [diagnostics];
      const pending = this.#native.request({
        url, method: options.method, protocol: options.protocol, context: options.context,
        ...fields, expectContinueMs: continueWait,
        body: byteBody,
        preparedBody: prepared,
        file: options.file, timeoutMs: options.timeoutMs, ...policies,
      }, cancellation, budget, upload, transfer, ...extra);
      if (upload) {
        producer = {error: undefined, multipart: multipartUpload};
        this.#trackUpload(iterator, upload, producer);
      }
      const response = await pending;
      if (signal?.aborted) { response.close(); throw new PhantomError('Cancelled', 'request was cancelled'); }
      return new Response(response, cleanup, this, producer);
    } catch (error) {
      cancellation.cancel(); cleanup();
      if (upload && !producer) {
        producer = {error: undefined, multipart: multipartUpload};
        this.#trackUpload(iterator, upload, producer);
      }
      throw uploadError(error, producer, true);
    }
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
    if (uploadContext.getStore() === this) throw new PhantomError('InvalidOperation', 'an upload producer cannot await its own client shutdown');
    const started = performance.now();
    try {
      await this.#native.close(timeoutMs);
      if (this.#uploads.size) {
        let timer;
        try {
          await Promise.race([Promise.all([...this.#uploads]), new Promise((_, reject) => {
            timer = setTimeout(() => reject(new PhantomError('Timeout', 'upload cleanup deadline expired')), Math.max(0, timeoutMs - (performance.now() - started)));
          })]);
        } finally { clearTimeout(timer); }
      }
      if (this.#uploadCleanupError) throw this.#uploadCleanupError;
    } catch (error) { throw translated(error); }
  }
  async [Symbol.asyncDispose]() { await this.close(); }
}

function uploadLength(value) {
  if ((typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
    || (typeof value === 'bigint' && value >= 0n && value <= 0xffffffffffffffffn)) return BigInt(value);
  throw new PhantomError('InvalidArgument', 'bodyLength must be an exact unsigned 64-bit integer');
}

async function pumpUpload(iterator, upload, outcome) {
  let ended = false;
  let terminated = false;
  const stopped = upload.stopped().then(() => { terminated = true; return {stopped: true}; });
  try {
    let credit = false;
    let emptyChunks = 0;
    while (true) {
      if (!credit) {
        const ready = await Promise.race([upload.ready().then((ready) => ({ready})), stopped]);
        if (!ready.ready) return;
      }
      if (terminated) return;
      const next = await Promise.race([Promise.resolve().then(async () => {
        try {
          if (terminated) return {stopped: true};
          const result = await iterator.next();
          if (result === null || typeof result !== 'object') throw new Error();
          return {done: Boolean(result.done), value: result.value};
        } catch (error) {
          outcome.original = error;
          outcome.originalPresent = true;
          throw new PhantomError('UploadSource', 'upload source failed');
        }
      }), stopped]);
      if (next.stopped) return;
      if (next === null || typeof next !== 'object') throw new PhantomError('UploadSource', 'upload iterator returned an invalid result');
      if (next.done) {
        if (!uploadOperation(() => upload.end())) return;
        ended = true; return;
      }
      const chunk = bytes(next.value);
      const length = apply(lengthOf, chunk, []);
      credit = length === 0;
      if (credit && ++emptyChunks >= 16) {
        await new Promise((resolve) => setImmediate(resolve));
        emptyChunks = 0;
      } else if (!credit) emptyChunks = 0;
      for (let offset = 0; offset < length; offset += 65536) {
        if (offset !== 0 && !await upload.ready()) return;
        // The native call copies this view synchronously on this environment.
        const view = Buffer.from(apply(backingOf, chunk, []), apply(offsetOf, chunk, []) + offset, Math.min(65536, length - offset));
        if (!uploadOperation(() => upload.write(view))) return;
      }
    }
  } catch (error) {
    outcome.error = error instanceof PhantomError ? error : new PhantomError('UploadSource', 'upload source failed');
    if (!(error instanceof PhantomError)) { outcome.original = error; outcome.originalPresent = true; }
    outcome.error = uploadError(outcome.error, outcome);
    upload.fail();
  } finally {
    upload.stop();
    try {
      if (!ended && typeof iterator.return === 'function') await iterator.return();
    } catch (error) {
      outcome.cleanupOriginal = error;
      outcome.cleanupError = uploadError(new PhantomError('UploadSource', 'upload cleanup failed'), outcome);
      outcome.error ??= outcome.cleanupError;
      upload.fail();
    } finally { upload.settled(); }
  }
}

async function pumpMultipart(sources, upload, outcome) {
  let terminated = false;
  const stopped = upload.stopped().then(() => { terminated = true; return {stopped: true}; });
  const closed = new Set();
  const cleanupFailures = [];
  const rememberCleanup = (error) => {
    cleanupFailures.push(error);
    outcome.cleanupOriginal = cleanupFailures.length === 1 ? error : new AggregateError([...cleanupFailures], 'multipart cleanup failed');
    outcome.cleanupError ??= uploadError(new PhantomError('UploadSource', 'multipart cleanup failed'), outcome);
    outcome.error ??= outcome.cleanupError;
  };
  const closeSource = async (source) => {
    if (source === undefined || closed.has(source)) return;
    closed.add(source);
    try {
      if (source instanceof Readable) {
        const wasErrored = source.errored;
        const done = finished(source, {cleanup: true});
        source.destroy();
        try { await done; } catch (error) {
          if (wasErrored || error?.code !== 'ERR_STREAM_PREMATURE_CLOSE') throw error;
        }
      } else {
        const result = await source.return();
        if (result === null || typeof result !== 'object' || !result.done) throw new PhantomError('UploadSource', 'multipart source did not close');
      }
    } catch (error) { rememberCleanup(error); }
  };
  try {
    while (!terminated) {
      const selected = await Promise.race([upload.nextPart().then((index) => ({index})), stopped]);
      if (selected.stopped || selected.index === null || selected.index === undefined) return;
      const source = sources[selected.index];
      if (source === undefined || closed.has(source)) throw new PhantomError('UploadSource', 'multipart source demand is invalid');
      let iterator;
      try {
        iterator = source[Symbol.asyncIterator]();
        if (iterator === null || typeof iterator?.next !== 'function' || (!(source instanceof Readable) && iterator !== source)) throw new PhantomError('UploadSource', 'multipart stream must be its own async iterator');
      } catch (error) { outcome.original = error; outcome.originalPresent = true; throw new PhantomError('UploadSource', 'multipart source failed'); }
      let credit = false, empties = 0;
      while (!terminated) {
        if (!credit && !await upload.ready()) return;
        if (terminated) return;
        const next = await Promise.race([Promise.resolve().then(async () => {
          try {
            if (terminated) return {stopped: true};
            const result = await iterator.next();
            if (result === null || typeof result !== 'object') throw new PhantomError('UploadSource', 'multipart iterator returned an invalid result');
            return result;
          } catch (error) { outcome.original = error; outcome.originalPresent = true; throw new PhantomError('UploadSource', 'multipart source failed'); }
        }), stopped]);
        if (next.stopped) return;
        if (next.done) {
          // A child cannot advance the encoder until its host cleanup settles.
          await closeSource(source);
          if (outcome.error) { upload.fail(); return; }
          if (!uploadOperation(() => upload.end())) return;
          break;
        }
        const chunk = bytes(next.value), length = apply(lengthOf, chunk, []);
        credit = length === 0;
        if (credit && ++empties >= 16) { await new Promise((resolve) => setImmediate(resolve)); empties = 0; }
        else if (!credit) empties = 0;
        for (let offset = 0; offset < length; offset += 65536) {
          if (offset && !await upload.ready()) return;
          const view = Buffer.from(apply(backingOf, chunk, []), apply(offsetOf, chunk, []) + offset, Math.min(65536, length - offset));
          if (!uploadOperation(() => upload.write(view))) return;
        }
      }
    }
  } catch (error) {
    outcome.error = error instanceof PhantomError ? error : new PhantomError('UploadSource', 'multipart source failed');
    if (!(error instanceof PhantomError)) { outcome.original = error; outcome.originalPresent = true; }
    outcome.error = uploadError(outcome.error, outcome); upload.fail();
  } finally {
    upload.stop();
    // Begin all terminal closes before awaiting any cooperative source.
    await Promise.all(sources.map(closeSource));
    upload.settled();
  }
}

function uploadOperation(operation) {
  try { operation(); return true; }
  catch (error) {
    const translatedError = translated(error);
    if (translatedError.code === 'UploadClosed') return false;
    throw translatedError;
  }
}

module.exports = { AttemptBudget, Client, ClientCertificate, PhantomError, PreparedBody, Profile, RequestDiagnostics, Response, TransferControl, profiles: () => native.profileIds() };
