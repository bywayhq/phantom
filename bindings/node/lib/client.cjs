'use strict';

const { addAbortListener } = require('node:events');
const { types } = require('node:util');

const { bytes, apply, lengthOf } = require('./bytes.cjs');
const { attemptBudgetHandle, transferControlHandle, requestDiagnosticsHandle } = require('./controls.cjs');
const { PhantomError, translated } = require('./errors.cjs');
const native = require('./native.cjs');
const { networkOptions, poolOptions } = require('./network.cjs');
const { preparedBodyHandle } = require('./prepared-body.cjs');
const { profileHandle } = require('./profile.cjs');
const { requestDefaults, prepareRequest } = require('./request-preparation.cjs');
const { phaseTimeouts, redirectPolicy, retryPolicy, expectContinue, contentDecoding } = require('./request-options.cjs');
const { Response } = require('./response.cjs');
const { socks4UserId, sessionSharing, checkpointKey, receivingRoutes } = require('./session.cjs');
const { clientPins, clientCertificates } = require('./tls.cjs');
const { runUpload, pumpMultipart, pumpUpload, multipartOptions, uploadLength, claimMultipart, uploadError, isUploadContext } = require('./upload.cjs');
const { integer, positiveCount } = require('./validation.cjs');

const clientToken = {};
const environment = new native.NativeEnvironment();

class Client {
  #native;
  #defaults;
  #uploads = new Set();
  #uploadCleanupError;
  #trackUpload(iterator, upload, outcome) {
    outcome.context = this;
    const pumping = runUpload(this, () => outcome.multipart ? pumpMultipart(iterator, upload, outcome) : pumpUpload(iterator, upload, outcome));
    outcome.finished = pumping;
    this.#uploads.add(pumping);
    const settled = () => {
      this.#uploads.delete(pumping);
      outcome.context = undefined;
      this.#uploadCleanupError ??= outcome.cleanupError;
    };
    pumping.then(settled, settled);
  }
  constructor(options, token, defaults) {
    if (token === clientToken) { this.#native = options; this.#defaults = defaults; return; }
    try {
      if (options === null || typeof options !== 'object') throw new PhantomError('InvalidArgument', 'client options are required');
      const serverSpkiPins = clientPins(options, 'serverSpkiPins');
      const proxyServerSpkiPins = clientPins(options, 'proxyServerSpkiPins');
      const certificates = clientCertificates(options);
      const network = networkOptions(options);
      const userId = Object.getOwnPropertyDescriptor(options, 'proxyUserId');
      if (userId && !Object.hasOwn(userId, 'value')) throw new PhantomError('InvalidArgument', 'proxyUserId must be a data field');
      const proxyUserId = userId?.value === undefined ? undefined : socks4UserId(userId.value);
      const pool = poolOptions(options);
      if (options.maximumActiveRequests !== undefined) integer(options.maximumActiveRequests, 'maximumActiveRequests', 1, 1024);
      const profile = typeof options.profile === 'string' ? undefined : profileHandle(options.profile);
      this.#defaults = requestDefaults(options, profile?.contexts.includes('profile') ? 'profile' : undefined);
      const {protocol, context, headers, ...nativeOptions} = options;
      this.#native = environment.client({
        ...nativeOptions, profile: typeof options.profile === 'string' ? options.profile : undefined,
        additionalRoots: options.additionalRoots?.map(bytes),
        additionalProxyRoots: options.additionalProxyRoots?.map(bytes),
        serverSpkiPins, proxyServerSpkiPins, ...certificates,
        timeouts: phaseTimeouts(options.timeouts),
        redirectPolicy: redirectPolicy(options.redirectPolicy),
        retryPolicy: retryPolicy(options.retryPolicy),
        network,
        proxyUserId,
        pool,
      }, profile);
    } catch (error) { throw translated(error); }
  }
  fork(sharing = {}) {
    try { return new Client(environment.fork(this.#native, sessionSharing(sharing)), clientToken, this.#defaults); }
    catch (error) { throw translated(error); }
  }
  async exportSession(key) {
    try { return await this.#native.exportSession(checkpointKey(key)); }
    catch (error) { throw translated(error); }
  }
  async restoreSession(snapshot, key, options = {}) {
    try {
      const input = bytes(snapshot);
      if (apply(lengthOf, input, []) > 32 * 1024 * 1024) throw new PhantomError('SessionSnapshot', 'session checkpoint failed', undefined, undefined, 'too_large');
      const restored = await environment.restoreSession(this.#native, input, checkpointKey(key), receivingRoutes(options));
      return new Client(restored, clientToken, this.#defaults);
    } catch (error) { throw translated(error); }
  }
  async request(url, options) {
    const cancellation = new native.NativeCancellation();
    let signal;
    let abortListener;
    let upload;
    let producer;
    let iterator;
    let multipartUpload = false;
    const abort = () => cancellation.cancel();
    const cleanup = () => { upload?.stop(); abortListener?.[Symbol.dispose](); abortListener = undefined; };
    try {
      ({url, options} = prepareRequest(this.#defaults, url, options));
      if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new PhantomError('InvalidArgument', 'signal must be an AbortSignal');
      signal = options.signal;
      if (options.timeoutMs !== undefined) integer(options.timeoutMs, 'timeoutMs');
      if (options.file) integer(options.file.maximumBytes, 'maximumBytes');
      const fields = {headers: options.headers, trailers: options.trailers};
      const continueWait = expectContinue(options.expectContinueMs);
      if (options.multipart !== undefined && (options.body !== undefined || options.file !== undefined || options.bodyLength !== undefined)) throw new PhantomError('InvalidArgument', 'multipart cannot be combined with body, file or bodyLength');
      const multipart = multipartOptions(options.multipart);
      const prepared = options.body === undefined ? undefined : preparedBodyHandle(options.body);
      const streaming = options.body !== undefined && prepared === undefined && !types.isUint8Array(options.body);
      if (options.file !== undefined && options.body !== undefined) throw new PhantomError('InvalidArgument', 'choose body or file');
      if (options.bodyLength !== undefined && (options.body === undefined || options.file !== undefined)) {
        throw new PhantomError('InvalidArgument', 'bodyLength requires a body');
      }
      const length = options.bodyLength === undefined ? undefined : uploadLength(options.bodyLength);
      if (prepared !== undefined && length !== undefined && prepared.byteLength !== length) {
        throw new PhantomError('UploadLength', 'body does not match bodyLength');
      }
      const byteBody = options.body === undefined || streaming || prepared !== undefined ? undefined : bytes(options.body);
      if (byteBody !== undefined && length !== undefined && BigInt(apply(lengthOf, byteBody, [])) !== length) {
        throw new PhantomError('UploadLength', 'body does not match bodyLength');
      }
      if (streaming) {
        if (typeof options.body?.[Symbol.asyncIterator] !== 'function') throw new PhantomError('InvalidArgument', 'body must be bytes or an AsyncIterable of bytes');
        iterator = options.body[Symbol.asyncIterator]();
        if (iterator === null || typeof iterator?.next !== 'function') throw new PhantomError('InvalidArgument', 'body must provide an async iterator');
        upload = new native.NativeUpload(length);
      }
      if (signal) abortListener = addAbortListener(signal, abort);
      if (signal?.aborted) abort();
      const budget = options.attemptBudget === undefined ? undefined : attemptBudgetHandle(options.attemptBudget);
      if (options.attemptBudget !== undefined && budget === undefined) throw new PhantomError('InvalidArgument', 'attemptBudget must be an AttemptBudget');
      const transfer = options.transferControl === undefined ? undefined : transferControlHandle(options.transferControl);
      if (options.transferControl !== undefined && transfer === undefined) throw new PhantomError('InvalidArgument', 'transferControl must be a TransferControl');
      const diagnostics = options.diagnostics === undefined ? undefined : requestDiagnosticsHandle(options.diagnostics);
      if (options.diagnostics !== undefined && diagnostics === undefined) throw new PhantomError('InvalidArgument', 'diagnostics must be RequestDiagnostics');
      const policies = {
        timeouts: phaseTimeouts(options.timeouts), contentDecoding: contentDecoding(options.contentDecoding),
        redirectPolicy: redirectPolicy(options.redirectPolicy), retryPolicy: retryPolicy(options.retryPolicy),
        redirectHistoryLimit: options.redirectHistoryLimit === undefined ? undefined : positiveCount(options.redirectHistoryLimit),
      };
      if (multipart) {
        const candidate = new native.NativeUpload();
        candidate.configureMultipart(multipart.boundary, multipart.fields, multipart.maximumBytes);
        claimMultipart(multipart.descriptor);
        upload = candidate; iterator = multipart.sources; multipartUpload = true;
      }
      const extra = diagnostics === undefined ? [] : [diagnostics];
      const pending = this.#native.request({
        url, method: options.method, protocol: options.protocol, context: options.context,
        ...fields, expectContinueMs: continueWait,
        body: byteBody,
        preparedBody: prepared,
        file: options.file, timeoutMs: options.timeoutMs, ...policies,
      }, cancellation, budget, upload, transfer, ...extra);
      if (upload) {
        producer = {error: undefined, multipart: multipartUpload};
        this.#trackUpload(iterator, upload, producer);
      }
      const response = await pending;
      if (signal?.aborted) { response.close(); throw new PhantomError('Cancelled', 'request was cancelled'); }
      return new Response(response, cleanup, this, producer);
    } catch (error) {
      cancellation.cancel(); cleanup();
      if (upload && !producer) {
        producer = {error: undefined, multipart: multipartUpload};
        this.#trackUpload(iterator, upload, producer);
      }
      throw uploadError(error, producer, true);
    }
  }
  #requestMethod(method, url, options) {
    if (options !== undefined && (options === null || typeof options !== 'object')) return this.request(url, options);
    return this.request(url, {...options, method});
  }
  get(url, options) { return this.#requestMethod('GET', url, options); }
  head(url, options) { return this.#requestMethod('HEAD', url, options); }
  post(url, options) { return this.#requestMethod('POST', url, options); }
  put(url, options) { return this.#requestMethod('PUT', url, options); }
  patch(url, options) { return this.#requestMethod('PATCH', url, options); }
  delete(url, options) { return this.#requestMethod('DELETE', url, options); }
  options(url, options) { return this.#requestMethod('OPTIONS', url, options); }
  setCookie(url, cookie) {
    try { this.#native.setCookie(url, cookie); } catch (error) { throw translated(error); }
  }
  cookieValue(url) {
    try { return this.#native.cookieValue(url); } catch (error) { throw translated(error); }
  }
  clearCookies() {
    try { this.#native.clearCookies(); } catch (error) { throw translated(error); }
  }
  clearDnsCache() {
    try { this.#native.clearDnsCache(); } catch (error) { throw translated(error); }
  }
  clearAltSvc() {
    try { this.#native.clearAltSvc(); } catch (error) { throw translated(error); }
  }
  clearAltSvcRacingHistory() {
    try { this.#native.clearAltSvcRacingHistory(); } catch (error) { throw translated(error); }
  }
  clearClientHints() {
    try { this.#native.clearClientHints(); } catch (error) { throw translated(error); }
  }
  clearSessionTickets() {
    try { return this.#native.clearSessionTickets(); } catch (error) { throw translated(error); }
  }
  async closeIdleConnections() {
    try { await this.#native.closeIdleConnections(); } catch (error) { throw translated(error); }
  }
  async refreshConnections() {
    try { await this.#native.refreshConnections(); } catch (error) { throw translated(error); }
  }
  async close({ timeoutMs = 5000 } = {}) {
    integer(timeoutMs, 'timeoutMs');
    if (isUploadContext(this)) throw new PhantomError('InvalidOperation', 'an upload producer cannot await its own client shutdown');
    const started = performance.now();
    try {
      await this.#native.close(timeoutMs);
      if (this.#uploads.size) {
        let timer;
        try {
          await Promise.race([Promise.all([...this.#uploads]), new Promise((_, reject) => {
            timer = setTimeout(() => reject(new PhantomError('Timeout', 'upload cleanup deadline expired')), Math.max(0, timeoutMs - (performance.now() - started)));
          })]);
        } finally { clearTimeout(timer); }
      }
      if (this.#uploadCleanupError) throw this.#uploadCleanupError;
    } catch (error) { throw translated(error); }
  }
  async [Symbol.asyncDispose]() { await this.close(); }
}

module.exports = { Client };
