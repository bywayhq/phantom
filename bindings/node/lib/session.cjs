'use strict';

const { types } = require('node:util');

const { bytes, apply, lengthOf } = require('./bytes.cjs');
const { PhantomError } = require('./errors.cjs');
const { policyFields } = require('./validation.cjs');

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
    const route = policyFields(field.value, ['route', 'proxy', 'proxyUsername', 'proxyPassword', 'proxyUserId']);
    if (route.proxyUserId !== undefined) route.proxyUserId = socks4UserId(route.proxyUserId);
    if (route.route === 'direct') {
      if (route.proxy !== undefined || route.proxyUsername !== undefined || route.proxyPassword !== undefined || route.proxyUserId !== undefined) throw new PhantomError('InvalidArgument', 'a direct receiving route cannot include a proxy');
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

function socks4UserId(value) {
  if (typeof value !== 'string' || value.length > 255 || !value.isWellFormed()
    || value.includes('\0') || Buffer.byteLength(value) > 255) {
    throw new PhantomError('InvalidProxy', 'proxyUserId must be at most 255 UTF-8 bytes without NUL');
  }
  return value;
}

module.exports = { socks4UserId, sessionSharing, checkpointKey, receivingRoutes };
