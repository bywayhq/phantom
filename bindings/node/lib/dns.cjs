// @ts-check
'use strict';

const { PhantomError } = require('./errors.cjs');
const { toUSVString } = require('node:util');
const { bytes, apply, lengthOf } = require('./bytes.cjs');
const { integer, orderedDataArray, policyFields, positiveCount } = require('./validation.cjs');

/**
 * @typedef {object} NativeDnsSettings
 * @property {readonly string[]} bootstrap
 * @property {number} timeoutMs
 * @property {bigint} maxConcurrent
 * @property {'dual' | 'ipv4'} families
 * @property {readonly Buffer[]} roots
 * @property {number | null | 'inherit'} paddingBlock
 */
/** @typedef {NativeDnsSettings & ({kind: 'https', endpoint: string, method: 'post' | 'get', wire: 'standard' | 'chromium154', queryId: number} | {kind: 'tls', serverName: string})} NativeDnsOptions */

/** @param {unknown} value @returns {NativeDnsOptions | undefined} */
function dnsOptions(value) {
  if (value === undefined) return undefined;
  const fields = policyFields(value, ['kind', 'endpoint', 'serverName', 'bootstrap',
    'timeoutMs', 'maxConcurrent', 'families', 'roots', 'paddingBlock', 'method', 'wire', 'queryId']);
  const kind = fields.kind;
  if (kind !== 'https' && kind !== 'tls') throw new PhantomError('InvalidArgument', 'dns.kind must be https or tls');
  if ((kind === 'https' && Object.hasOwn(fields, 'serverName')) || (kind === 'tls'
    && ['endpoint', 'method', 'wire', 'queryId'].some((name) => Object.hasOwn(fields, name)))) {
    throw new PhantomError('InvalidArgument', 'DNS fields do not match their transport');
  }

  let remaining = 65536;
  /** @param {unknown} input @returns {string} */
  const text = (input) => {
    if (typeof input !== 'string') throw new PhantomError('InvalidArgument', 'DNS fields require UTF-8 strings');
    if (input.length > remaining) throw new PhantomError('InputLimit', 'DNS configuration exceeds its byte limit');
    if (toUSVString(input) !== input) throw new PhantomError('InvalidArgument', 'DNS fields require UTF-8 strings');
    remaining -= Buffer.byteLength(input);
    if (remaining < 0) throw new PhantomError('InputLimit', 'DNS configuration exceeds its byte limit');
    return input;
  };
  const identity = text(kind === 'https' ? fields.endpoint : fields.serverName);
  const bootstrap = orderedDataArray(fields.bootstrap, 1024, 'DNS bootstrap').map(text);
  if (bootstrap.length === 0) throw new PhantomError('InvalidArgument', 'DNS bootstrap must not be empty');
  const roots = orderedDataArray(fields.roots === undefined ? [] : fields.roots,
    1024 - bootstrap.length, 'DNS roots').map((value) => {
    const root = bytes(value);
    remaining -= apply(lengthOf, root, []);
    if (remaining < 0) throw new PhantomError('InputLimit', 'DNS configuration exceeds its byte limit');
    return root;
  });
  const timeoutMs = fields.timeoutMs;
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new PhantomError('InvalidArgument', 'dns.timeoutMs must be finite positive milliseconds');
  }
  const maxConcurrent = positiveCount(fields.maxConcurrent);
  if (kind === 'tls' && maxConcurrent > 32767n) throw new PhantomError('InvalidArgument', 'DNS-over-TLS maxConcurrent must be at most 32767');
  const families = fields.families === undefined ? 'dual' : fields.families;
  if (families !== 'dual' && families !== 'ipv4') throw new PhantomError('InvalidArgument', 'dns.families must be dual or ipv4');
  // Keep inherited padding distinct from null at the native object boundary.
  const paddingBlock = fields.paddingBlock === undefined ? 'inherit' : fields.paddingBlock === null
    ? null : integer(fields.paddingBlock, 'dns.paddingBlock', 1, 65535);
  /** @type {NativeDnsSettings} */
  const common = {bootstrap: Object.freeze(bootstrap), timeoutMs, maxConcurrent,
    families, roots: Object.freeze(roots), paddingBlock};
  if (kind === 'tls') return Object.freeze({...common, kind, serverName: identity});

  const method = fields.method === undefined ? 'post' : fields.method;
  const wire = fields.wire === undefined ? 'standard' : fields.wire;
  if (method !== 'post' && method !== 'get') throw new PhantomError('InvalidArgument', 'dns.method must be post or get');
  if (wire !== 'standard' && wire !== 'chromium154') throw new PhantomError('InvalidArgument', 'dns.wire must be standard or chromium154');
  const queryId = fields.queryId === undefined ? 0 : integer(fields.queryId, 'dns.queryId', 0, 65535);
  return Object.freeze({...common, kind, endpoint: identity, method, wire, queryId});
}

module.exports = { dnsOptions };
