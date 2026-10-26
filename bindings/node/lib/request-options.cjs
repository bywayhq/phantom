'use strict';

const { types } = require('node:util');

const { bytes, apply, lengthOf } = require('./bytes.cjs');
const { PhantomError } = require('./errors.cjs');
const { policyFields, integer, positiveCount, orderedDataArray } = require('./validation.cjs');

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
  const copy = policyFields(value, ['mode', 'maximumHops', 'credentialHeaders']);
  const names = copy.credentialHeaders === undefined ? undefined
    : orderedDataArray(copy.credentialHeaders, 256, 'redirect credential names');
  let remaining = 65536;
  for (const name of names ?? []) {
    if (typeof name !== 'string') throw new PhantomError('InvalidArgument', 'credentialHeaders require strings');
    remaining -= Buffer.byteLength(name);
    if (remaining < 0) throw new PhantomError('InputLimit', 'redirect credential names exceed 65536 bytes');
  }
  const credentials = names === undefined ? {} : {credentialHeaders: Object.freeze(names)};
  if (copy.mode === 'none' && !Object.hasOwn(copy, 'maximumHops')) return {mode: 'none', ...credentials};
  if (copy.mode === 'limited') return {
    mode: 'limited', maximumHops: positiveCount(copy.maximumHops), ...credentials,
  };
  throw new PhantomError('InvalidArgument', 'choose none or limited with a positive hop count');
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

module.exports = { phaseTimeouts, redirectPolicy, retryPolicy, requestFields, expectContinue, contentDecoding };
