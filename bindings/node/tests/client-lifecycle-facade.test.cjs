'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');

const {loadFacade} = require('./load-facade.cjs');

function client(owner) {
  const native = {NativeEnvironment: class {client() {return owner;}}};
  const {Client} = loadFacade(path.resolve(__dirname, '../index.cjs'), native);
  return new Client({profile: 'exact', route: 'direct'});
}

test('concurrent graceful closes join one shutdown without destroying work', async () => {
  let finish, calls = 0, destroyed = false;
  const value = client({close(timeout) {
    calls++; assert.equal(timeout, 1000);
    return new Promise((resolve) => {finish = resolve;});
  }, destroy() {destroyed = true;}});
  const first = value.close({timeoutMs: 1000});
  const second = value.close({timeoutMs: 1});
  assert.equal(calls, 1); assert.equal(destroyed, false);
  finish(); await Promise.all([first, second]);
});

test('destroy aborts work and joins an already pending graceful close', async () => {
  let finish, calls = 0, destroyed = 0;
  const value = client({close() {calls++; return new Promise((resolve) => {finish = resolve;});},
    destroy() {destroyed++; finish();}});
  const closing = value.close();
  await value.destroy(); await closing;
  assert.equal(calls, 1); assert.equal(destroyed, 1);
});

test('a timed out graceful close can be retried and destroy validates before aborting', async () => {
  let calls = 0, destroyed = false;
  const value = client({async close() {if (++calls === 1) throw Error('PHANTOM:Timeout:shutdown deadline expired');},
    destroy() {destroyed = true;}});
  await assert.rejects(value.close({timeoutMs: 0}), {code: 'Timeout'});
  await value.close(); assert.equal(calls, 2);
  await assert.rejects(value.destroy({timeoutMs: -1}), {code: 'InvalidArgument'});
  assert.equal(destroyed, false);
});
