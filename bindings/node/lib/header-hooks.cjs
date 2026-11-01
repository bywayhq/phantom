// @ts-check
'use strict';

const {AsyncLocalStorage} = require('node:async_hooks');
const {validateHeaderName, validateHeaderValue} = require('node:http');
const {inspect} = require('node:util');

const {PhantomError, translated} = require('./errors.cjs');
const {requestFields} = require('./request-options.cjs');
const {orderedDataArray} = require('./validation.cjs');
const {logicalMask, invokeLogical} = require('./request-hooks.cjs');

/** @typedef {import('../index.js').HeaderHook} HeaderHook */
/** @typedef {import('./client-native.cjs').NativeHeaderHooks} NativeHeaderHooks */
/** @typedef {import('./client-native.cjs').NativeHeader} NativeHeader */
/** @typedef {import('./client-native.cjs').NativeHeaderEdit} NativeHeaderEdit */
/** @typedef {{error: unknown, serial?: bigint, observed?: boolean}} HookFailure */
/** @typedef {{failed: boolean, error?: unknown, failureSerial?: bigint, bridgeFailure?: HookFailure,
 * logical?: {primary?: HookFailure, secondary?: HookFailure, origin?: Readonly<{scheme: string, host: string, port: number}>}}} HookOutcome */

/** @type {AsyncLocalStorage<{client: object | undefined, source?: NativeHeaderHooks}>} */
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

/** @param {object} client @param {NativeHeaderHooks} [source] */
function isHeaderHookContext(client, source) {
  const scope = callbackContext.getStore();
  return scope?.client === client && (source === undefined || scope.source === source);
}

/** @template T @param {object} client @param {NativeHeaderHooks | undefined} source
 * @param {() => T | PromiseLike<T>} callback */
async function runCallback(client, source, callback) {
  const scope = {client: /** @type {object | undefined} */ (client), source};
  try { return await callbackContext.run(scope, callback); }
  finally {
    // Descendant async resources can outlive this invocation.
    scope.client = undefined;
    scope.source = undefined;
  }
}

/** @param {object} client @param {NativeHeaderHooks} owner
 * @param {readonly HeaderHook[]} hooks @param {HookOutcome} outcome
 * @param {import('../index.js').RedirectCallback} [redirect] @param {boolean} [source]
 * @param {readonly (Readonly<import('../index.js').RequestHooks> | undefined)[]} [logicalBundles] */
async function pumpHeaderHooks(client, owner, hooks, outcome, redirect, source = false, logicalBundles = []) {
  const serialLifetime = source || logicalMask(logicalBundles) !== 0;
  let controller = new AbortController();
  /** @type {{serial: bigint, context: {_finish(): unknown}, controller: AbortController} | undefined} */
  let active;
  const abort = () => {
    active?.context._finish();
    controller.abort(new PhantomError('Cancelled', 'request callback was cancelled'));
  };
  const stopped = (serialLifetime ? (async () => {
    let cancelled = 0n;
    while (true) {
      const serial = await owner.nextCancelled(cancelled);
      if (serial === null) break;
      cancelled = serial;
      if (active && active.serial <= serial) {
        active.context._finish();
        active.controller.abort(new PhantomError('Cancelled', 'event source GET callback was cancelled'));
      }
    }
  })() : owner.closed()).then(abort, (error) => {
    outcome.bridgeFailure ??= {error: translated(error)};
    abort();
  });
  try {
    while (true) {
      const invocation = await owner.next();
      if (invocation === null) break;
      const serial = invocation.serial ?? undefined;
      if (serialLifetime) {
        if (typeof serial !== 'bigint') throw new PhantomError('Internal', 'callback serial is unavailable');
        if (!owner.isActive(serial)) continue;
        controller = new AbortController();
        active = {serial, context: {_finish() {}}, controller};
      }
      if (invocation.logical) {
        const logical = invocation.logical;
        if (!Number.isInteger(logical.phase) || logical.phase < 0 || logical.phase > 2 || serial === undefined) throw new PhantomError('Internal', 'logical callback phase is unavailable');
        let failed = false;
        try {
          controller.signal.throwIfAborted();
          for (const bundle of logicalBundles) {
            await runCallback(client, source ? owner : undefined, () => invokeLogical(bundle, logical, controller.signal, outcome));
            controller.signal.throwIfAborted();
          }
        } catch (error) {
          failed = true;
          if (!controller.signal.aborted || error !== controller.signal.reason) {
            const retained = {error, serial};
            outcome.logical ??= {};
            outcome.logical[logical.phase === 2 ? 'secondary' : 'primary'] = retained;
            outcome.bridgeFailure ??= retained;
          }
        } finally { active = undefined; }
        if (owner.isActive(serial)) {
          try { owner.completeLogical(serial, failed); }
          catch (error) { if (owner.isActive(serial) || translated(error).code !== 'InvalidOperation') throw error; }
        }
        continue;
      }
      if (invocation.redirect) {
        const attempt = Object.freeze(Object.defineProperty({...invocation.redirect, signal: controller.signal}, inspect.custom, {
          value: () => 'RedirectAttempt { URLs redacted }',
        }));
        try {
          controller.signal.throwIfAborted();
          if (!redirect) throw new PhantomError('Internal', 'redirect callback is unavailable');
          const decision = await runCallback(client, undefined, () => redirect(attempt));
          controller.signal.throwIfAborted();
          if (decision !== 'follow' && decision !== 'stop' && decision !== 'reject') {
            throw new PhantomError('InvalidArgument', 'redirect callbacks must return Follow, Stop or Reject');
          }
          owner.completeRedirect(attempt.hop, decision, serial);
        } catch (error) {
          outcome.failed = true;
          outcome.error = error;
          outcome.failureSerial = serial;
          if (serialLifetime || (controller.signal.aborted && error !== controller.signal.reason)) outcome.bridgeFailure ??= {error, serial};
          try { owner.failRedirect(attempt.hop, serial); }
          catch (failure) {
            if (!controller.signal.aborted) outcome.bridgeFailure ??= {error: translated(failure)};
          }
          if (!serialLifetime) break;
        } finally {
          active = undefined;
        }
        continue;
      }
      if (source) {
        // Only the current invocation can explain a returned core HeaderHook error.
        // An earlier error discarded by a GET deadline remains in bridgeFailure.
        outcome.failed = false;
        outcome.error = undefined;
        outcome.failureSerial = undefined;
      }
      const context = new HeaderHookContext(contextToken, invocation, controller.signal);
      if (serialLifetime && serial !== undefined) active = {serial, context, controller};
      try {
        controller.signal.throwIfAborted();
        const hook = hooks[invocation.index];
        if (hook === undefined) throw new PhantomError('Internal', 'header callback index is unavailable');
        await runCallback(client, source ? owner : undefined, () => hook(context));
        controller.signal.throwIfAborted();
        const edits = context._finish();
        if (!serialLifetime || owner.isActive(/** @type {bigint} */ (serial))) {
          try { owner.complete(invocation.index, edits, serial); }
          catch (delivery) {
            if (!serialLifetime || owner.isActive(/** @type {bigint} */ (serial)) || translated(delivery).code !== 'InvalidOperation') throw delivery;
          }
        }
      } catch (error) {
        context._finish();
        if (serialLifetime && !owner.isActive(/** @type {bigint} */ (serial))) {
          if (!controller.signal.aborted || error !== controller.signal.reason) outcome.bridgeFailure ??= {error, serial};
          continue;
        }
        outcome.failed = true;
        outcome.error = error;
        outcome.failureSerial = serial;
        if (serialLifetime || (controller.signal.aborted && error !== controller.signal.reason)) {
          outcome.bridgeFailure ??= {error, serial};
        }
        try { owner.fail(invocation.index, serial); }
        catch (failure) {
          if (!controller.signal.aborted) outcome.bridgeFailure ??= {error: translated(failure)};
        }
        if (!serialLifetime) break;
      } finally {
        active = undefined;
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
