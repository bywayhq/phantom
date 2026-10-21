'use strict';

const { types } = require('node:util');

const { PhantomError } = require('./errors.cjs');

function integer(value, name, minimum = 0, maximum = 0xffffffff) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new PhantomError('InvalidArgument', `${name} is outside its supported integer range`);
  }
  return value;
}

function orderedDataArray(input, maximum, name) {
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

function positiveCount(value) {
  if ((typeof value === 'bigint' && value > 0n && value <= 18446744073709551615n)
    || (typeof value === 'number' && Number.isSafeInteger(value) && value > 0)) {
    return BigInt(value);
  }
  throw new PhantomError('InvalidArgument', 'count must be a positive exact integer fitting the native pointer size');
}

module.exports = { orderedDataArray, integer, policyFields, positiveCount };
