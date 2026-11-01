'use strict';

const { types } = require('node:util');

const { bytes, apply, lengthOf } = require('./bytes.cjs');
const { PhantomError } = require('./errors.cjs');
const { policyFields, orderedDataArray, integer } = require('./validation.cjs');

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

function receivingRoutes(options, limitCode = 'SessionSnapshot') {
  const limit = () => limitCode === 'InputLimit'
    ? new PhantomError('InputLimit', 'route input exceeds its limit')
    : stateFailure('SessionSnapshot', 'too_large');
  const fields = policyFields(options, ['receivingRoutes']);
  const routes = fields.receivingRoutes === undefined ? [] : fields.receivingRoutes;
  if (!Array.isArray(routes) || types.isProxy(routes)) throw new PhantomError('InvalidArgument', 'receivingRoutes must be a data array');
  if (routes.length > 256) throw limit();
  if (Reflect.ownKeys(routes).length !== routes.length + 1) throw new PhantomError('InvalidArgument', 'receivingRoutes must contain only route entries');
  const result = [];
  let remaining = 65536;
  for (let index = 0; index < routes.length; index++) {
    const field = Object.getOwnPropertyDescriptor(routes, String(index));
    if (!field || !Object.hasOwn(field, 'value')) throw new PhantomError('InvalidArgument', 'receivingRoutes must contain data entries');
    const route = policyFields(field.value, ['route', 'proxy', 'proxyUsername', 'proxyPassword', 'proxyUserId']);
    if (route.proxyUserId !== undefined && typeof route.proxyUserId !== 'string') socks4UserId(route.proxyUserId);
    if (route.route === 'direct') {
      if (route.proxy !== undefined || route.proxyUsername !== undefined || route.proxyPassword !== undefined || route.proxyUserId !== undefined) throw new PhantomError('InvalidArgument', 'a direct receiving route cannot include a proxy');
    } else if (route.route !== 'proxy' || typeof route.proxy !== 'string'
      || (route.proxyUsername !== undefined && typeof route.proxyUsername !== 'string')
      || (route.proxyPassword !== undefined && typeof route.proxyPassword !== 'string')
      || (route.proxyUsername === undefined) !== (route.proxyPassword === undefined)) {
      throw new PhantomError('InvalidArgument', 'receiving proxy routes require a URI and paired string credentials');
    }
    for (const text of [route.proxy, route.proxyUsername, route.proxyPassword, route.proxyUserId]) {
      if (text === undefined) continue;
      if (typeof text !== 'string' || !text.isWellFormed()) throw new PhantomError('InvalidArgument', 'receiving route fields must be UTF-8 strings');
      if (text.length > remaining) throw limit();
      remaining -= Buffer.byteLength(text);
      if (remaining < 0) throw limit();
    }
    if (route.proxyUserId !== undefined) route.proxyUserId = socks4UserId(route.proxyUserId);
    result.push(route);
  }
  return result;
}

function socks4UserId(value) {
  if (typeof value !== 'string' || value.length > 255 || !value.isWellFormed()
    || value.includes('\0') || Buffer.byteLength(value) > 255) {
    throw new PhantomError('InvalidProxy', 'proxyUserId must be at most 255 UTF-8 bytes without NUL');
  }
  return value;
}

function stateFailure(category, kind) {
  return new PhantomError(category, 'state transfer failed', undefined, undefined, kind);
}

function ticketKey(value) {
  const key = bytes(value);
  if (apply(lengthOf, key, []) !== 32) throw stateFailure('SessionTickets', 'invalid_key_length');
  return key;
}

function ticketBytes(value) {
  const input = bytes(value);
  if (apply(lengthOf, input, []) > 16 * 1024 * 1024) throw stateFailure('SessionTickets', 'too_large');
  return input;
}

function ticketRoutes(options) {
  try { return receivingRoutes(options); }
  catch (error) {
    if (error instanceof PhantomError && error.code === 'SessionSnapshot') throw stateFailure('SessionTickets', error.kind);
    throw error;
  }
}

function snapshotEntries(input, cookies) {
  const category = cookies ? 'CookieSnapshot' : 'AltSvcSnapshot';
  const maximum = cookies ? 16384 : 32768;
  if (!types.isProxy(input) && Array.isArray(input) && input.length > maximum) throw stateFailure(category, 'too_large');
  const entries = orderedDataArray(input, maximum, 'snapshot entries');
  let remaining = 32 * 1024 * 1024;
  const text = (value) => {
    if (typeof value !== 'string' || !value.isWellFormed()) throw stateFailure(category, 'invalid_entry');
    if (value.length > remaining) throw stateFailure(category, 'too_large');
    remaining -= Buffer.byteLength(value);
    if (remaining < 0) throw stateFailure(category, 'too_large');
    return value;
  };
  const expiry = (value) => {
    // Duration has u64 seconds; SystemTime additionally checks its host range.
    if (typeof value !== 'bigint' || value > 18446744073709551615999999999n
      || value < -18446744073709551615999999999n) throw stateFailure(category, 'invalid_expiry');
    return value;
  };
  return entries.map((entry) => {
    const fields = policyFields(entry, cookies
      ? ['sourceScheme', 'name', 'value', 'domain', 'path', 'hostOnly', 'secure', 'httpOnly', 'sameSite', 'partitionKey', 'expiresAtNanoseconds']
      : ['origin', 'alternativeHost', 'alternativePort', 'expiresAtNanoseconds']);
    if (!cookies) return Object.freeze({origin: text(fields.origin), alternativeHost: text(fields.alternativeHost),
      alternativePort: integer(fields.alternativePort, 'alternativePort', 1, 65535), expiresAtNanoseconds: expiry(fields.expiresAtNanoseconds)});
    if (!['http', 'https'].includes(fields.sourceScheme) || ![null, 'strict', 'lax', 'none'].includes(fields.sameSite)
      || typeof fields.hostOnly !== 'boolean' || typeof fields.secure !== 'boolean' || typeof fields.httpOnly !== 'boolean') {
      throw stateFailure(category, 'invalid_entry');
    }
    return Object.freeze({sourceScheme: text(fields.sourceScheme), name: text(fields.name), value: text(fields.value),
      domain: text(fields.domain), path: text(fields.path), hostOnly: fields.hostOnly, secure: fields.secure, httpOnly: fields.httpOnly,
      sameSite: fields.sameSite === null ? null : text(fields.sameSite), partitionKey: fields.partitionKey === null ? null : text(fields.partitionKey),
      expiresAtNanoseconds: fields.expiresAtNanoseconds === null ? null : expiry(fields.expiresAtNanoseconds)});
  });
}

/** @returns {readonly import('../index.js').CookieSnapshotEntry[]} */
function cookieEntries(input) {
  return /** @type {import('../index.js').CookieSnapshotEntry[]} */ (snapshotEntries(input, true));
}

/** @returns {readonly import('../index.js').AltSvcSnapshotEntry[]} */
function altSvcEntries(input) {
  return /** @type {import('../index.js').AltSvcSnapshotEntry[]} */ (snapshotEntries(input, false));
}

module.exports = { socks4UserId, sessionSharing, checkpointKey, receivingRoutes, ticketKey, ticketBytes, ticketRoutes,
  cookieEntries, altSvcEntries };
