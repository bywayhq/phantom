// @ts-check
'use strict';

/** @typedef {import('../index.js').ClientOptions} ClientOptions */
/** @typedef {import('../index.js').RequestOptions} RequestOptions */
/** @typedef {import('../index.js').MethodOptions} MethodOptions */
/** @typedef {import('./request-preparation.cjs').RequestDefaults} RequestDefaults */
/** @typedef {import('./client-native.cjs').NativeClient} NativeClient */
/** @typedef {import('./upload.cjs').UploadIterator} UploadIterator */
/** @typedef {import('./upload.cjs').MultipartSource} MultipartSource */
/** @typedef {import('./upload.cjs').UploadProgress} UploadProgress */
/** @typedef {import('./upload.cjs').UploadOutcome} UploadOutcome */
/** @typedef {import('./upload.cjs').UploadFailure} UploadFailure */
/** @typedef {import('./client-native.cjs').NativeUpload} NativeUpload */

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
const { openWebSocket } = require('./websocket.cjs');

const clientToken = {};
/** @type {import('./client-native.cjs').NativeEnvironment} */
const environment = new native.NativeEnvironment();

class Client {
  /** @type {NativeClient} */
  #native;
  /** @type {RequestDefaults} */
  #defaults;
  /** @type {Set<Promise<void>>} */
  #uploads = new Set();
  /** @type {Promise<void> | undefined} */
  #closing;
  /** @type {UploadFailure | undefined} */
  #uploadCleanupError;

  /** @param {unknown} iterator
   * @param {NativeUpload} upload @param {UploadProgress} outcome
   * @returns {asserts outcome is UploadOutcome} */
  #trackUpload(iterator, upload, outcome) {
    outcome.context = this;
    // Request preparation selects the matching producer before admitting upload.
    const pumping = runUpload(this, () => outcome.multipart ? pumpMultipart(/** @type {(MultipartSource | undefined)[]} */ (iterator), upload, outcome) : pumpUpload(/** @type {UploadIterator} */ (iterator), upload, outcome));
    outcome.finished = pumping;
    this.#uploads.add(pumping);

    const settled = () => {
      this.#uploads.delete(pumping);
      outcome.context = undefined;
      this.#uploadCleanupError ??= outcome.cleanupError;
    };
    pumping.then(settled, settled);
  }

  /** @overload @param {ClientOptions} options */
  /** @overload @param {NativeClient} options @param {object} token
   * @param {RequestDefaults} defaults */
  /** @param {ClientOptions | NativeClient} options @param {object} [token]
   * @param {RequestDefaults} [defaults] */
  constructor(options, token, defaults) {
    if (token === clientToken) {
      // Only fork and restore pass this token with their registered native owner.
      this.#native = /** @type {NativeClient} */ (options);
      this.#defaults = /** @type {RequestDefaults} */ (defaults);
      return;
    }

    try {
      if (options === null || typeof options !== 'object') throw new PhantomError('InvalidArgument', 'client options are required');

      const config = /** @type {ClientOptions} */ (options);

      const serverSpkiPins = clientPins(config, 'serverSpkiPins');
      const proxyServerSpkiPins = clientPins(config, 'proxyServerSpkiPins');
      /** @type {Pick<import('./client-native.cjs').NativeClientOptions, 'clientCertificate' | 'clientCertificatesFor'>} */
      const certificates = clientCertificates(config);
      const network = networkOptions(config);
      const userId = Object.getOwnPropertyDescriptor(config, 'proxyUserId');
      if (userId && !Object.hasOwn(userId, 'value')) throw new PhantomError('InvalidArgument', 'proxyUserId must be a data field');
      const proxyUserId = userId?.value === undefined ? undefined : socks4UserId(userId.value);
      const pool = poolOptions(config);
      if (config.maximumActiveRequests !== undefined) integer(config.maximumActiveRequests, 'maximumActiveRequests', 1, 1024);
      const profile = typeof config.profile === 'string' ? undefined : profileHandle(config.profile);
      this.#defaults = requestDefaults(config, profile?.contexts.includes('profile') ? 'profile' : undefined);

      /** @type {Omit<ClientOptions, 'clientCertificate' | 'clientCertificatesFor'>} */
      const { protocol, context, headers, ...nativeOptions } = config;
      this.#native = environment.client({
        ...nativeOptions, profile: typeof config.profile === 'string' ? config.profile : undefined,
        additionalRoots: config.additionalRoots?.map(bytes),
        additionalProxyRoots: config.additionalProxyRoots?.map(bytes),
        serverSpkiPins, proxyServerSpkiPins, ...certificates,
        timeouts: phaseTimeouts(config.timeouts),
        redirectPolicy: redirectPolicy(config.redirectPolicy),
        retryPolicy: retryPolicy(config.retryPolicy),
        network,
        proxyUserId,
        pool,
      }, profile);
    } catch (error) {
      throw translated(error);
    }
  }

  /** @param {import('../index.js').SessionSharing} [sharing] */
  fork(sharing = {}) {
    try {
      return new Client(environment.fork(this.#native, sessionSharing(sharing)), clientToken, this.#defaults);
    } catch (error) {
      throw translated(error);
    }
  }

  /** @param {Uint8Array} key */
  async exportSession(key) {
    try {
      return await this.#native.exportSession(checkpointKey(key));
    } catch (error) {
      throw translated(error);
    }
  }

  /** @param {Uint8Array} snapshot @param {Uint8Array} key
   * @param {import('../index.js').RestoreSessionOptions} [options] */
  async restoreSession(snapshot, key, options = {}) {
    try {
      const input = bytes(snapshot);
      if (apply(lengthOf, input, []) > 32 * 1024 * 1024) throw new PhantomError('SessionSnapshot', 'session checkpoint failed', undefined, undefined, 'too_large');

      const restored = await environment.restoreSession(this.#native, input, checkpointKey(key), receivingRoutes(options));
      return new Client(restored, clientToken, this.#defaults);
    } catch (error) {
      throw translated(error);
    }
  }

  /** @param {string | URL} url @param {RequestOptions} [inputOptions] */
  async request(url, inputOptions) {
    /** @type {import('./client-native.cjs').NativeCancellation} */
    const cancellation = new native.NativeCancellation();
    let signal;
    /** @type {Disposable | undefined} */
    let abortListener;
    /** @type {NativeUpload | undefined} */
    let upload;
    let producer;
    /** @type {UploadIterator | (MultipartSource | undefined)[] | undefined} */
    let iterator;
    let multipartUpload = false;
    const abort = () => cancellation.cancel();
    const cleanup = () => {
      upload?.stop();
      abortListener?.[Symbol.dispose]();
      abortListener = undefined;
    };

    try {
      const { url: preparedUrl, options } = prepareRequest(this.#defaults, url, inputOptions);
      if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new PhantomError('InvalidArgument', 'signal must be an AbortSignal');
      signal = options.signal;
      if (options.timeoutMs !== undefined) integer(options.timeoutMs, 'timeoutMs');
      if (options.file) integer(options.file.maximumBytes, 'maximumBytes');

      const fields = { headers: options.headers, trailers: options.trailers };
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
        if (typeof (/** @type {AsyncIterable<Uint8Array> | undefined} */ (options.body))?.[Symbol.asyncIterator] !== 'function') throw new PhantomError('InvalidArgument', 'body must be bytes or an AsyncIterable of bytes');
        iterator = (/** @type {AsyncIterable<Uint8Array>} */ (options.body))[Symbol.asyncIterator]();
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
        upload = candidate;
        iterator = multipart.sources;
        multipartUpload = true;
      }

      const extra = diagnostics === undefined ? [] : [diagnostics];
      const pending = this.#native.request({
        url: preparedUrl, method: options.method, protocol: options.protocol, context: options.context,
        ...fields, expectContinueMs: continueWait,
        body: byteBody,
        preparedBody: prepared,
        file: options.file, timeoutMs: options.timeoutMs, ...policies,
      }, cancellation, budget, upload, transfer, ...extra);

      if (upload) {
        producer = { error: undefined, multipart: multipartUpload };
        this.#trackUpload(iterator, upload, producer);
      }

      const response = await pending;
      if (signal?.aborted) {
        response.close();
        throw new PhantomError('Cancelled', 'request was cancelled');
      }

      return new Response(response, cleanup, this, producer);
    } catch (error) {
      cancellation.cancel();
      cleanup();

      if (upload && !producer) {
        producer = { error: undefined, multipart: multipartUpload };
        this.#trackUpload(iterator, upload, producer);
      }

      throw uploadError(error, producer, true);
    }
  }

  /** @param {string} method @param {string | URL} url @param {MethodOptions} [options] */
  #requestMethod(method, url, options) {
    if (options !== undefined && (options === null || typeof options !== 'object')) return this.request(url, options);
    return this.request(url, { ...options, method });
  }

  /** @param {string | URL} url @param {import('../index.js').WebSocketOptions} [options] */
  websocket(url, options) { return openWebSocket(this.#native, this, url, options, this.#defaults.headers); }
  /** @param {string | URL} url @param {MethodOptions} [options] */
  get(url, options) { return this.#requestMethod('GET', url, options); }
  /** @param {string | URL} url @param {MethodOptions} [options] */
  head(url, options) { return this.#requestMethod('HEAD', url, options); }
  /** @param {string | URL} url @param {MethodOptions} [options] */
  post(url, options) { return this.#requestMethod('POST', url, options); }
  /** @param {string | URL} url @param {MethodOptions} [options] */
  put(url, options) { return this.#requestMethod('PUT', url, options); }
  /** @param {string | URL} url @param {MethodOptions} [options] */
  patch(url, options) { return this.#requestMethod('PATCH', url, options); }
  /** @param {string | URL} url @param {MethodOptions} [options] */
  delete(url, options) { return this.#requestMethod('DELETE', url, options); }
  /** @param {string | URL} url @param {MethodOptions} [options] */
  options(url, options) { return this.#requestMethod('OPTIONS', url, options); }

  /** @param {string} url @param {string} cookie */
  setCookie(url, cookie) {
    try {
      this.#native.setCookie(url, cookie);
    } catch (error) {
      throw translated(error);
    }
  }

  /** @param {string} url */
  cookieValue(url) {
    try {
      return this.#native.cookieValue(url);
    } catch (error) {
      throw translated(error);
    }
  }

  clearCookies() {
    try {
      this.#native.clearCookies();
    } catch (error) {
      throw translated(error);
    }
  }

  clearDnsCache() {
    try {
      this.#native.clearDnsCache();
    } catch (error) {
      throw translated(error);
    }
  }

  clearAltSvc() {
    try {
      this.#native.clearAltSvc();
    } catch (error) {
      throw translated(error);
    }
  }

  clearAltSvcRacingHistory() {
    try {
      this.#native.clearAltSvcRacingHistory();
    } catch (error) {
      throw translated(error);
    }
  }

  clearClientHints() {
    try {
      this.#native.clearClientHints();
    } catch (error) {
      throw translated(error);
    }
  }

  clearSessionTickets() {
    try {
      return this.#native.clearSessionTickets();
    } catch (error) {
      throw translated(error);
    }
  }

  async closeIdleConnections() {
    try {
      await this.#native.closeIdleConnections();
    } catch (error) {
      throw translated(error);
    }
  }

  async refreshConnections() {
    try {
      await this.#native.refreshConnections();
    } catch (error) {
      throw translated(error);
    }
  }

  /** @param {{timeoutMs?: number}} [options] */
  async close({ timeoutMs = 5000 } = {}) {
    this.#checkShutdown(timeoutMs);
    if (this.#closing) return this.#closing;

    const pending = this.#finishClose(timeoutMs);
    this.#closing = pending;

    try {
      await pending;
    } finally {
      if (this.#closing === pending) this.#closing = undefined;
    }
  }

  /** @param {{timeoutMs?: number}} [options] */
  async destroy({ timeoutMs = 5000 } = {}) {
    this.#checkShutdown(timeoutMs);
    try {
      this.#native.destroy();
    } catch (error) {
      throw translated(error);
    }
    await this.close({ timeoutMs });
  }

  /** @param {number} timeoutMs */
  #checkShutdown(timeoutMs) {
    integer(timeoutMs, 'timeoutMs');
    if (isUploadContext(this)) throw new PhantomError('InvalidOperation', 'an upload producer cannot await its own client shutdown');
  }

  /** @param {number} timeoutMs */
  async #finishClose(timeoutMs) {
    const started = performance.now();
    try {
      await this.#native.close(timeoutMs);

      if (this.#uploads.size) {
        let timer;
        try {
          await Promise.race([Promise.all([...this.#uploads]), new Promise((_, reject) => {
            timer = setTimeout(() => reject(new PhantomError('Timeout', 'upload cleanup deadline expired')), Math.max(0, timeoutMs - (performance.now() - started)));
          })]);
        } finally {
          clearTimeout(timer);
        }
      }
      if (this.#uploadCleanupError) throw this.#uploadCleanupError;
    } catch (error) {
      throw translated(error);
    }
  }

  async [Symbol.asyncDispose]() {
    await this.close();
  }
}

module.exports = { Client };
