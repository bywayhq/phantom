'use strict';

const { types } = require('node:util');

const { PhantomError } = require('./errors.cjs');

const apply = Reflect.apply;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype);
const backingOf = Object.getOwnPropertyDescriptor(typedArray, 'buffer').get;
const offsetOf = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset').get;
const lengthOf = Object.getOwnPropertyDescriptor(typedArray, 'byteLength').get;

function bytes(value) {
  if (!types.isUint8Array(value)) {
    throw new PhantomError('InvalidArgument', 'bytes must be a non-shared Uint8Array or Buffer');
  }
  const backing = apply(backingOf, value, []);
  if (types.isSharedArrayBuffer(backing)) throw new PhantomError('InvalidArgument', 'shared byte buffers are unsupported');
  return Buffer.isBuffer(value) ? value : Buffer.from(backing, apply(offsetOf, value, []), apply(lengthOf, value, []));
}

module.exports = { bytes, apply, lengthOf, backingOf, offsetOf };
