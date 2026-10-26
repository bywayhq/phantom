'use strict';

const { types } = require('node:util');

const { PhantomError } = require('./errors.cjs');
const { orderedDataArray, integer } = require('./validation.cjs');

function networkOptions(options) {
  const field = Object.getOwnPropertyDescriptor(options, 'network');
  if (field === undefined) return undefined;
  if (!Object.hasOwn(field, 'value')) throw new PhantomError('InvalidArgument', 'network must be a data field');
  if (field.value === undefined) return undefined;
  const fields = (value, names) => {
    if (value === null || typeof value !== 'object' || types.isProxy(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      throw new PhantomError('InvalidArgument', 'network settings must be data objects');
    }
    const result = Object.getOwnPropertyDescriptors(value);
    for (const key of Reflect.ownKeys(result)) {
      if (!names.includes(key) || !Object.hasOwn(result[key], 'value')) {
        throw new PhantomError('InvalidArgument', 'network settings contain an unknown or executable field');
      }
    }
    return result;
  };
  const input = fields(field.value, ['hostOverrides', 'localAddresses', 'interface', 'unixSocket', 'publicOnly']);
  let remainingBytes = 65536, remainingEntries = 1024;
  const string = (value) => {
    if (typeof value !== 'string') throw new PhantomError('InvalidArgument', 'network fields require strings');
    if (value.length > remainingBytes) throw new PhantomError('InputLimit', 'network configuration exceeds its byte limit');
    remainingBytes -= Buffer.byteLength(value);
    if (remainingBytes < 0) throw new PhantomError('InputLimit', 'network configuration exceeds its byte limit');
    return value;
  };
  const array = (value) => {
    const result = orderedDataArray(value, remainingEntries, 'network entries');
    remainingEntries -= result.length;
    return result;
  };
  const hostOverrides = array(input.hostOverrides?.value === undefined ? [] : input.hostOverrides.value).map((value) => {
    const entry = fields(value, ['host', 'addresses']);
    const host = string(entry.host?.value);
    const addresses = Object.freeze(array(entry.addresses?.value).map(string));
    return Object.freeze({host, addresses});
  });
  const localAddresses = array(input.localAddresses?.value === undefined ? [] : input.localAddresses.value).map(string);
  const interfaceName = input.interface?.value === undefined ? undefined : string(input.interface.value);
  const unixSocket = input.unixSocket?.value === undefined ? undefined : string(input.unixSocket.value);
  if (unixSocket !== undefined && (!unixSocket.length || !unixSocket.isWellFormed() || unixSocket.includes('\0'))) {
    throw new PhantomError('InvalidArgument', 'unixSocket must be a nonempty UTF-8 pathname without NUL');
  }
  const publicOnly = input.publicOnly?.value;
  if (publicOnly !== undefined && typeof publicOnly !== 'boolean') {
    throw new PhantomError('InvalidArgument', 'publicOnly must be boolean');
  }
  return Object.freeze({...(publicOnly === undefined ? {} : {publicOnly}), hostOverrides: Object.freeze(hostOverrides), localAddresses: Object.freeze(localAddresses),
    interface: interfaceName, ...(unixSocket === undefined ? {} : {unixSocket})});
}

function poolOptions(options) {
  const field = Object.getOwnPropertyDescriptor(options, 'pool');
  if (field === undefined) return undefined;
  if (!Object.hasOwn(field, 'value')) throw new PhantomError('InvalidArgument', 'pool must be a data field');
  const value = field.value;
  if (value === undefined) return undefined;
  if (value === null || typeof value !== 'object' || types.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new PhantomError('InvalidArgument', 'pool settings must be a data object');
  }
  const counts = [
    'maxRetainedHttp1Connections',
    'maxConcurrentHttp1RequestsPerOrigin',
    'maxPendingHttp1RequestsPerOrigin',
    'maxRetainedHttp2Connections',
    'maxConcurrentHttp2RequestsPerOrigin',
    'maxPendingHttp2RequestsPerOrigin',
    'maxHttp2ConnectionsPerOrigin',
    'maxRetainedHttp3Connections',
    'maxConcurrentHttp3RequestsPerOrigin',
    'maxPendingHttp3RequestsPerOrigin',
    'maxHttp3ConnectionsPerOrigin',
  ];
  const result = {};
  for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if ((!counts.includes(name) && name !== 'negotiatedSetupWaitLimitMs') || !Object.hasOwn(descriptor, 'value')) {
      throw new PhantomError('InvalidArgument', 'pool settings contain an unknown or executable field');
    }
    if (descriptor.value !== undefined) {
      result[name] = integer(descriptor.value, name, name === 'negotiatedSetupWaitLimitMs' ? 0 : 1, Number.MAX_SAFE_INTEGER);
    }
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) throw new PhantomError('InvalidArgument', 'pool settings contain an unknown field');
  return Object.freeze(result);
}

module.exports = { networkOptions, poolOptions };
