'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { inspect } = require('node:util');

const { translated, PhantomError } = require('../lib/errors.cjs');

test('unknown native failures preserve their cause without claiming caller error or exposing it', () => {
  const cause = new Error('private native detail');
  const error = translated(cause);
  assert.equal(error.code, 'NativeFailure');
  assert.equal(error.cause, cause);
  assert.ok(!String(error).includes('private'));
  assert.ok(!inspect(error).includes('private'));
  assert.ok(!JSON.stringify(error).includes('private'));
  assert.equal(translated(error), error);

  const conversion = Object.assign(new Error('private argument'), {code: 'InvalidArg'});
  assert.equal(translated(conversion).code, 'InvalidArgument');
  assert.equal(translated(conversion).cause, conversion);
  assert.equal(translated(new Error('PHANTOM:Closed:client is closed')).code, 'Closed');
  assert.ok(error instanceof PhantomError);
});

test('error translation does not execute arbitrary error getters or proxy traps', () => {
  const hostile = {get message() {throw new Error('do not invoke');}};
  assert.equal(translated(hostile).code, 'NativeFailure');
  const proxy = new Proxy({}, {getPrototypeOf() {throw new Error('do not invoke');}});
  assert.equal(translated(proxy).cause, proxy);
});
