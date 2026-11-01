// @ts-check
'use strict';

const {addAbortListener} = require('node:events');
const {performance} = require('node:perf_hooks');
const {toUSVString} = require('node:util');
const {bytes, apply, lengthOf} = require('./bytes.cjs');
const {PhantomError, caused} = require('./errors.cjs');
const {checkpointKey, receivingRoutes} = require('./session.cjs');
const {policyFields} = require('./validation.cjs');

/** @param {string} name @param {import('../index.js').SessionStorageOptions} options
 * @param {boolean} loading */
function operation(name, options, loading) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 256
    || toUSVString(name) !== name || Buffer.byteLength(name) > 256 || /\p{Cc}/u.test(name)) {
    throw new PhantomError('SessionStorage', 'session storage failed', undefined, undefined, 'invalid_name');
  }
  const fields = policyFields(options, loading ? ['timeoutMs', 'signal', 'receivingRoutes'] : ['timeoutMs', 'signal']);
  const timeout = fields.timeoutMs;
  if (typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout <= 0 || timeout > 2147483647) {
    throw new PhantomError('InvalidArgument', 'timeoutMs must be positive milliseconds at most 2147483647');
  }
  const signal = fields.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw new PhantomError('InvalidArgument', 'signal must be an AbortSignal');
  const routes = loading ? receivingRoutes({receivingRoutes: fields.receivingRoutes}) : [];
  const deadline = performance.now() + timeout;
  const controller = new AbortController();
  const expired = () => new PhantomError('SessionStorage', 'session storage failed', undefined, undefined, 'deadline');
  const parent = signal === undefined ? undefined : addAbortListener(signal, () => controller.abort(signal.reason));
  if (signal?.aborted) controller.abort(signal.reason);
  const timer = setTimeout(() => controller.abort(expired()), timeout);
  const check = () => {
    if (performance.now() >= deadline && !controller.signal.aborted) controller.abort(expired());
    controller.signal.throwIfAborted();
  };
  return {
    signal: controller.signal, routes, check,
    dispose() { clearTimeout(timer); parent?.[Symbol.dispose](); },
    /** @template T @param {() => Promise<T>} action @returns {Promise<T>} */
    async backend(action) {
      check();
      return await new Promise((resolve, reject) => {
        const listener = addAbortListener(controller.signal, () => reject(controller.signal.reason));
        // Both handlers stay attached after cancellation, observing late rejection.
        Promise.resolve().then(() => { check(); return action(); }).then((value) => {
          listener[Symbol.dispose]();
          try { check(); resolve(value); } catch (error) { reject(error); }
        }, (error) => {
          listener[Symbol.dispose]();
          try { check(); } catch (cancelled) { reject(cancelled); return; }
          reject(caused(new PhantomError('SessionStorage', 'session storage failed', undefined, undefined, 'backend'), error));
        });
      });
    },
  };
}

/** @param {import('./client.cjs').Client} client @param {import('../index.js').SessionStore} store
 * @param {string} name @param {Uint8Array} key @param {import('../index.js').SessionStorageOptions} options */
async function saveSession(client, store, name, key, options) {
  const scope = operation(name, options, false);
  let secret;
  try {
    scope.check();
    secret = Buffer.from(checkpointKey(key));
    const snapshot = await client.exportSession(secret).catch((error) => {
      scope.check();
      throw error;
    });
    scope.check();
    await scope.backend(() => store.save(name, snapshot, {signal: scope.signal}));
  } finally { secret?.fill(0); scope.dispose(); }
}

/** @param {import('./client.cjs').Client} client @param {import('../index.js').SessionStore} store
 * @param {string} name @param {Uint8Array} key @param {import('../index.js').LoadSessionOptions} options
 * @returns {Promise<import('./client.cjs').Client | null>} */
async function loadSession(client, store, name, key, options) {
  const scope = operation(name, options, true);
  let secret;
  try {
    scope.check();
    secret = Buffer.from(checkpointKey(key));
    const snapshot = await scope.backend(() => store.load(name, {signal: scope.signal}));
    if (snapshot === null) return null;
    const input = bytes(snapshot);
    if (apply(lengthOf, input, []) > 32 * 1024 * 1024) throw new PhantomError('SessionSnapshot', 'session checkpoint failed', undefined, undefined, 'too_large');
    const restored = await client.restoreSession(input, secret, {receivingRoutes: scope.routes}).catch((error) => {
      scope.check();
      throw error;
    });
    try { scope.check(); }
    catch (error) {
      try { await restored.destroy(); }
      catch (cleanup) {
        throw caused(new PhantomError('SessionStorage', 'session storage cleanup failed', undefined, undefined, 'cleanup'), {original: error, cleanup});
      }
      throw error;
    }
    return restored;
  } finally { secret?.fill(0); scope.dispose(); }
}

module.exports = {saveSession, loadSession};
