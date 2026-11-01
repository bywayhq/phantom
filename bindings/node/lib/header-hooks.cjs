// @ts-check
'use strict';

const {AsyncLocalStorage} = require('node:async_hooks');
const {validateHeaderName, validateHeaderValue} = require('node:http');
const {inspect} = require('node:util');

const {PhantomError, translated} = require('./errors.cjs');
const {requestFields} = require('./request-options.cjs');
const {orderedDataArray} = require('./validation.cjs');

/** @typedef {import('../index.js').HeaderHook} HeaderHook */
/** @typedef {import('./client-native.cjs').NativeHeaderHooks} NativeHeaderHooks */
/** @typedef {import('./client-native.cjs').NativeHeader} NativeHeader */
/** @typedef {import('./client-native.cjs').NativeHeaderEdit} NativeHeaderEdit */
/** @typedef {{failed: boolean, error?: unknown, bridgeFailure?: {error: unknown}}} HookOutcome */

/** @type {AsyncLocalStorage<object>} */
const callbackContext = new AsyncLocalStorage();
const contextToken = {};
/** @type {readonly HeaderHook[]} */
const noHooks = Object.freeze([]);

/** @param {unknown} input @returns {readonly HeaderHook[]} */
function headerHooks(input) {
  if (input === undefined) return noHooks;
  const hooks = orderedDataArray(input, 256, 'headerHooks');
  if (!hooks.every((hook) => typeof hook === 'function')) {
    throw new PhantomError('InvalidArgument', 'headerHooks require functions');
  }
  return Object.freeze(/** @type {HeaderHook[]} */ (hooks));
}

class HeaderHookContext {
  /** @type {NativeHeader[]} */
  #headers;
  /** @type {NativeHeaderEdit[]} */
  #edits = [];
  #active = true;
  #method;
  #url;
  #signal;

  /** @param {object} token @param {import('./client-native.cjs').NativeHeaderInvocation} invocation
   * @param {AbortSignal} signal */
  constructor(token, invocation, signal) {
    if (token !== contextToken) throw new PhantomError('InvalidOperation', 'header contexts belong to callbacks');
    this.#headers = invocation.headers;
    this.#method = invocation.method;
    this.#url = invocation.uri;
    this.#signal = signal;
  }

  get method() { return this.#method; }
  get url() { return this.#url; }
  get signal() { return this.#signal; }
  get headers() {
    return Object.freeze(this.#headers.map((header) => Object.freeze({...header, value: Buffer.from(header.value)})));
  }

  /** @param {import('../index.js').Header} field */
  append(field) { this.#change('append', field); }

  /** @param {import('../index.js').Header} field */
  set(field) { this.#change('set', field); }

  /** @param {string} name */
  remove(name) {
    this.#check();
    validateHeaderName(name);
    this.#edits.push({action: 'remove', name});
    this.#headers = this.#headers.filter((header) => header.name.toLowerCase() !== name.toLowerCase());
  }

  /** @param {'append' | 'set'} action @param {import('../index.js').Header} field */
  #change(action, field) {
    this.#check();
    const header = requestFields([field], undefined).headers?.[0];
    if (header === undefined) throw new PhantomError('InvalidArgument', 'a header is required');
    validateHeaderName(header.name);
    validateHeaderValue(header.name, header.value.toString('latin1'));
    const owned = {...header, value: Buffer.from(header.value)};
    this.#edits.push({action, ...owned});
    const name = owned.name.toLowerCase();
    const position = action === 'set' ? this.#headers.findIndex((old) => old.name.toLowerCase() === name) : -1;
    if (position < 0) this.#headers.push(owned);
    else {
      this.#headers[position] = owned;
      this.#headers = this.#headers.filter((old, index) => index <= position || old.name.toLowerCase() !== name);
    }
  }

  #check() {
    if (!this.#active) throw new PhantomError('InvalidOperation', 'header callback has finished');
    this.#signal.throwIfAborted();
    if (this.#edits.length >= 256) throw new PhantomError('InputLimit', 'a header hook exceeds 256 edits');
  }

  /** @returns {NativeHeaderEdit[]} */
  _finish() {
    this.#active = false;
    return this.#edits;
  }

  [inspect.custom]() { return 'HeaderHookContext { headers and URL redacted }'; }
}

/** @param {object} client */
function isHeaderHookContext(client) { return callbackContext.getStore() === client; }

/** @param {object} client @param {NativeHeaderHooks} owner
 * @param {readonly HeaderHook[]} hooks @param {HookOutcome} outcome */
async function pumpHeaderHooks(client, owner, hooks, outcome) {
  const controller = new AbortController();
  const stopped = owner.closed().then(() => {
    controller.abort(new PhantomError('Cancelled', 'header callback was cancelled'));
  }, (error) => {
    outcome.bridgeFailure ??= {error: translated(error)};
    controller.abort(outcome.bridgeFailure.error);
  });
  try {
    while (true) {
      const invocation = await owner.next();
      if (invocation === null) break;
      const context = new HeaderHookContext(contextToken, invocation, controller.signal);
      try {
        controller.signal.throwIfAborted();
        const hook = hooks[invocation.index];
        if (hook === undefined) throw new PhantomError('Internal', 'header callback index is unavailable');
        await callbackContext.run(client, () => hook(context));
        controller.signal.throwIfAborted();
        owner.complete(invocation.index, context._finish());
      } catch (error) {
        context._finish();
        outcome.failed = true;
        outcome.error = error;
        if (controller.signal.aborted && error !== controller.signal.reason) {
          outcome.bridgeFailure ??= {error};
        }
        try { owner.fail(invocation.index); }
        catch (failure) {
          if (!controller.signal.aborted) outcome.bridgeFailure ??= {error: translated(failure)};
        }
        break;
      }
    }
  } catch (error) {
    outcome.bridgeFailure ??= {error: translated(error)};
  } finally {
    owner.stop();
    await stopped;
    owner.settled();
  }
}

module.exports = {HeaderHookContext, headerHooks, isHeaderHookContext, pumpHeaderHooks};
