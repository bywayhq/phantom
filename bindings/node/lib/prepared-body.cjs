'use strict';

const { types, inspect } = require('node:util');

const { bytes, apply, lengthOf } = require('./bytes.cjs');
const { PhantomError, translated } = require('./errors.cjs');
const native = require('./native.cjs');
const { policyFields } = require('./validation.cjs');

const preparedHandles = new WeakMap();
const preparedToken = {};

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

function preparedBodyHandle(value) { return preparedHandles.get(value); }

/** @returns {import('../index.js').PreparedBody} */
function encodedBody(input, contentType, maximumBytes) {
  return new PreparedBody(native.preparedEncoded(bytes(input), contentType, BigInt(maximumBytes)), preparedToken);
}

module.exports = { PreparedBody, preparedOptions, preparedFailure, preparedArray, preparedBodyHandle, encodedBody };
