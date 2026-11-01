// @ts-check
'use strict';

const {inspect} = require('node:util');
const {PhantomError, translated, caused} = require('./errors.cjs');
const {policyFields} = require('./validation.cjs');
/** @type {readonly Readonly<import('../index.js').RequestHooks>[]} */
const noBundles = Object.freeze([]);

/** @param {unknown} input @returns {Readonly<import('../index.js').RequestHooks> | undefined} */
function requestHooks(input) {
  if (input === undefined) return undefined;
  const fields = policyFields(input, ['onRequest', 'onResponse', 'onError']);
  for (const value of Object.values(fields)) {
    if (value !== undefined && typeof value !== 'function') throw new PhantomError('InvalidArgument', 'request hook callbacks must be functions');
  }
  if (!Object.values(fields).some((value) => typeof value === 'function')) return undefined;
  return Object.freeze(fields);
}

/** @param {readonly (Readonly<import('../index.js').RequestHooks> | undefined)[]} bundles */
function logicalMask(bundles) {
  if (bundles.length === 0) return 0;
  return bundles.reduce((mask, bundle) => mask | (bundle?.onRequest ? 1 : 0) | (bundle?.onResponse ? 2 : 0) | (bundle?.onError ? 4 : 0), 0);
}

/** @param {Readonly<import('../index.js').RequestHooks> | undefined} inherited @param {unknown} input */
function requestHookBundles(inherited, input) {
  const supplied = requestHooks(input);
  return inherited ? supplied ? [inherited, supplied] : [inherited] : supplied ? [supplied] : noBundles;
}

/** @param {unknown} input @param {import('./header-hooks.cjs').HookOutcome} outcome @param {boolean} [observe] */
function requestFailure(input, outcome, observe = true) {
  const error = /** @type {import('../index.js').PhantomError & {callbackSerial?: bigint, hookSerial?: bigint}} */ (translated(input));
  const state = outcome.logical;
  for (const [name, target, serial] of /** @type {const} */ ([
    ['primary', error, error.callbackSerial], ['secondary', error.hookError, error.hookSerial],
  ])) {
    const retained = state?.[name];
    if (target && retained && retained.serial === serial) {
      caused(target, retained.error);
      if (observe) retained.observed = true;
    }
  }
  if (error.code === 'HeaderHook' || error.code === 'Redirect') {
    if (outcome.failed) {
      caused(error, outcome.error);
      if (observe && outcome.bridgeFailure?.serial === outcome.failureSerial && outcome.bridgeFailure) outcome.bridgeFailure.observed = true;
    }
  }
  if (state?.origin && !Object.hasOwn(error, 'origin')) Object.defineProperty(error, 'origin', {value: state.origin});
  return error;
}

/** @param {import('./client-native.cjs').NativeLogicalInvocation} invocation
 * @param {AbortSignal} signal @param {import('./header-hooks.cjs').HookOutcome} outcome */
function logicalContext(invocation, signal, outcome) {
  const redacted = {value: () => 'RequestHookContext { metadata redacted }'};
  const request = Object.freeze(Object.defineProperty({method: invocation.method, url: invocation.url, signal}, inspect.custom, redacted));
  if (invocation.phase === 0) return Object.freeze(Object.defineProperty({...request}, inspect.custom, redacted));
  if (invocation.phase === 1) {
    if (typeof invocation.status !== 'number') throw new PhantomError('Internal', 'response callback status is unavailable');
    const context = {request, signal, status: invocation.status, protocol: invocation.protocol ?? undefined,
      url: invocation.effectiveUrl ?? undefined, redirects: invocation.redirects ?? undefined,
      connectionRetries: invocation.retries ?? undefined,
      decodedContentCodings: Object.freeze([...invocation.decodedContentCodings])};
    Object.defineProperty(context, 'headers', {enumerable: true, get: () => Object.freeze(invocation.headers.map((field) => Object.freeze({...field, sensitive: field.sensitive ?? false, value: Buffer.from(field.value)})))});
    return Object.freeze(Object.defineProperty(context, inspect.custom, redacted));
  }
  if (invocation.phase !== 2 || typeof invocation.error !== 'string') throw new PhantomError('Internal', 'logical callback phase is unavailable');
  if (invocation.originScheme && invocation.originHost && invocation.originPort !== undefined && invocation.originPort !== null) {
    outcome.logical ??= {};
    outcome.logical.origin = Object.freeze({scheme: invocation.originScheme, host: invocation.originHost, port: invocation.originPort});
  }
  const error = requestFailure(new Error(invocation.error), outcome, false);
  return Object.freeze(Object.defineProperty({request, signal, error: Object.freeze(error)}, inspect.custom, redacted));
}

/** @param {Readonly<import('../index.js').RequestHooks> | undefined} bundle
 * @param {import('./client-native.cjs').NativeLogicalInvocation} invocation
 * @param {AbortSignal} signal @param {import('./header-hooks.cjs').HookOutcome} outcome */
async function invokeLogical(bundle, invocation, signal, outcome) {
  if (!bundle) return;
  if (invocation.phase === 0 && bundle.onRequest) await bundle.onRequest(/** @type {import('../index.js').RequestHookContext} */ (logicalContext(invocation, signal, outcome)));
  else if (invocation.phase === 1 && bundle.onResponse) await bundle.onResponse(/** @type {import('../index.js').ResponseHookContext} */ (logicalContext(invocation, signal, outcome)));
  else if (invocation.phase === 2 && bundle.onError) await bundle.onError(/** @type {import('../index.js').RequestErrorHookContext} */ (logicalContext(invocation, signal, outcome)));
}

/** @param {import('./header-hooks.cjs').HookOutcome | undefined} outcome */
function pendingCallbackFailure(outcome) {
  return Boolean(outcome && ((outcome.bridgeFailure && !outcome.bridgeFailure.observed)
    || (outcome.logical?.primary && !outcome.logical.primary.observed)
    || (outcome.logical?.secondary && !outcome.logical.secondary.observed)));
}

/** Consume at most the two unreported host causes, without retaining the owner.
 * @param {import('./header-hooks.cjs').HookOutcome | undefined} outcome */
function consumeCallbackFailure(outcome) {
  if (!outcome) return undefined;
  const primary = outcome.logical?.primary, secondary = outcome.logical?.secondary;
  const first = outcome.bridgeFailure && !outcome.bridgeFailure.observed ? outcome.bridgeFailure
    : primary && !primary.observed ? primary : secondary && !secondary.observed ? secondary : undefined;
  if (!first) return undefined;
  const second = secondary && !secondary.observed && secondary !== first ? secondary
    : primary && !primary.observed && primary !== first ? primary : undefined;
  first.observed = true;
  if (second) second.observed = true;
  if (!outcome.logical) return {error: first.error};
  const error = caused(new PhantomError('RequestHookCleanup', 'request callback cleanup failed'), first.error);
  if (second) Object.defineProperty(error, 'hookError', {value: caused(new PhantomError('RequestHook', 'error callback cleanup failed'), second.error)});
  return {error};
}

module.exports = {requestHooks, requestHookBundles, logicalMask, invokeLogical, requestFailure, pendingCallbackFailure, consumeCallbackFailure};
