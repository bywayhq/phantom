'use strict';

const { types, inspect } = require('node:util');

const { bytes, apply, lengthOf } = require('./bytes.cjs');
const { PhantomError, translated } = require('./errors.cjs');
const native = require('./native.cjs');
const { orderedDataArray } = require('./validation.cjs');

const certificateHandles = new WeakMap();
const certificateToken = {};

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
      const chain = orderedDataArray(certificateChain, 256, 'certificateChain');
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
  const input = orderedDataArray(origins, 256, 'clientCertificatesFor');
  let total = 0;
  const pairs = [];
  for (const value of input) {
    const pair = orderedDataArray(value, 2, 'clientCertificatesFor pair');
    if (pair.length !== 2 || typeof pair[0] !== 'string') throw new PhantomError('InvalidArgument', 'clientCertificatesFor requires origin and certificate pairs');
    const count = Buffer.byteLength(pair[0]);
    total += count;
    if (count > 65536 || total > 16 * 1024 * 1024) throw new PhantomError('InputLimit', 'clientCertificatesFor exceeds its byte limit');
    pairs.push({origin: pair[0], certificate: certificateHandle(pair[1])});
  }
  result.clientCertificatesFor = pairs;
  return result;
}

module.exports = { ClientCertificate, clientPins, clientCertificates };
