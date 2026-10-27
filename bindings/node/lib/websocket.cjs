// @ts-check
'use strict';

/** @typedef {import('../index.js').Header} Header */
/** @typedef {import('../index.js').WebSocketOptions} WebSocketOptions */
/** @typedef {import('../index.js').WebSocketMessage} WebSocketMessage */
/** @typedef {import('../index.js').WebSocketHandshake} WebSocketHandshake */
/** @typedef {{kind: string, text?: string | null, data?: Buffer | null, code?: number | null, reason?: string | null}} NativeMessage */
/** @typedef {{abort(): void, receive(): Promise<NativeMessage | null>, send(kind: string, text?: string, data?: Buffer, code?: number, reason?: string): Promise<void>}} NativeSocket */

const { addAbortListener } = require('node:events');

const { bytes, apply, lengthOf } = require('./bytes.cjs');
const { PhantomError, translated } = require('./errors.cjs');
const native = require('./native.cjs');
const { mergeHeaders } = require('./request-preparation.cjs');
const { requestFields } = require('./request-options.cjs');
const { integer } = require('./validation.cjs');

const token = {};
/** @type {FinalizationRegistry<() => void>} */
const abandoned = new FinalizationRegistry((cleanup) => cleanup());

class WebSocketConnection {
  #native;
  #cleanup;
  #owner;
  #reading = false;
  #writing = false;
  #ended = false;
  /** @param {NativeSocket} socket @param {WebSocketHandshake} handshake
   * @param {() => void} cleanup @param {unknown} owner @param {object} internal */
  constructor(socket, handshake, cleanup, owner, internal) {
    if (internal !== token) throw new PhantomError('InvalidOperation', 'use client.websocket to open a WebSocket');
    this.#native = socket;
    this.#cleanup = cleanup;
    this.#owner = owner;
    Object.defineProperties(this, {
      handshake: {value: Object.freeze({
        status: handshake.status, protocol: handshake.protocol,
        selectedProtocol: handshake.selectedProtocol ?? null,
        headers: Object.freeze(handshake.headers.map((field) => Object.freeze({...field}))),
      }), enumerable: true},
    });
    abandoned.register(this, cleanup, this);
  }
  #finish() {
    abandoned.unregister(this);
    this.#cleanup();
    this.#owner = undefined;
    this.#ended = true;
  }
  /** @returns {Promise<WebSocketMessage | null>} */
  async receive() {
    if (this.#ended) return null;
    if (this.#reading) throw new PhantomError('InvalidOperation', 'a WebSocket receive is already pending');
    this.#reading = true;
    try {
      const message = await this.#native.receive();
      if (message == null) { this.#finish(); return null; }
      switch (message.kind) {
        case 'text':
          if (typeof message.text !== 'string') throw new PhantomError('NativeFailure', 'WebSocket text is unavailable');
          return Object.freeze({type: 'text', data: message.text});
        case 'binary': case 'ping': case 'pong':
          if (!Buffer.isBuffer(message.data)) throw new PhantomError('NativeFailure', 'WebSocket bytes are unavailable');
          return Object.freeze({type: message.kind, data: message.data});
        case 'close':
          this.#finish();
          return Object.freeze({type: 'close', code: message.code ?? null, reason: message.reason ?? null});
        default: throw new PhantomError('NativeFailure', 'unsupported WebSocket message kind');
      }
    } catch (error) { this.#finish(); throw translated(error); }
    finally { this.#reading = false; }
  }
  /** @param {string} kind @param {string} [text] @param {Buffer} [data]
   * @param {number} [code] @param {string} [reason] */
  async #send(kind, text, data, code, reason) {
    if (this.#ended) throw new PhantomError('WebSocketClosed', 'WebSocket is closed');
    if (this.#writing) throw new PhantomError('InvalidOperation', 'a WebSocket send is already pending');
    this.#writing = true;
    try { await this.#native.send(kind, text, data, code, reason); }
    catch (error) { throw translated(error); }
    finally { this.#writing = false; }
  }
  /** @param {string | Uint8Array} data */
  send(data) {
    if (typeof data === 'string') {
      if (Buffer.byteLength(data) > 64 * 1024 * 1024) return Promise.reject(new PhantomError('InputLimit', 'WebSocket text exceeds 64 MiB'));
      return this.#send('text', data);
    }
    try { return this.#send('binary', undefined, bytes(data)); }
    catch (error) { return Promise.reject(translated(error)); }
  }
  /** @param {string} kind @param {Uint8Array} [data] */
  #control(kind, data = Buffer.alloc(0)) {
    try {
      const input = bytes(data);
      if (lengthOf === undefined) throw new PhantomError('NativeFailure', 'typed array byte length is unavailable');
      if (apply(lengthOf, input, []) > 125) throw new PhantomError('InputLimit', 'WebSocket control payload exceeds 125 bytes');
      return this.#send(kind, undefined, input);
    } catch (error) { return Promise.reject(translated(error)); }
  }
  /** @param {Uint8Array} [data] */
  ping(data) { return this.#control('ping', data); }
  /** @param {Uint8Array} [data] */
  pong(data) { return this.#control('pong', data); }
  close(code = 1000, reason = '') {
    try {
      integer(code, 'code', 0, 65535);
      if (typeof reason !== 'string') throw new PhantomError('InvalidArgument', 'WebSocket close reason must be a string');
      if (Buffer.byteLength(reason) > 123) throw new PhantomError('InputLimit', 'WebSocket close reason exceeds 123 UTF-8 bytes');
      return this.#send('close', undefined, undefined, code, reason);
    } catch (error) { return Promise.reject(translated(error)); }
  }
  abort() { this.#finish(); }
  [Symbol.dispose]() { this.abort(); }
  async *[Symbol.asyncIterator]() {
    try {
      while (true) {
        const message = await this.receive();
        if (message === null) return;
        yield message;
        if (message.type === 'close') return;
      }
    } finally { this.abort(); }
  }
}

/** @param {{websocket(settings: object, socket: NativeSocket): Promise<WebSocketHandshake>}} client
 * @param {unknown} owner @param {string | URL} input @param {WebSocketOptions} [options]
 * @param {readonly Header[]} [defaults] */
async function openWebSocket(client, owner, input, options = {}, defaults = []) {
  /** @type {NativeSocket} */
  const socket = new native.NativeWebSocket();
  /** @type {Disposable | undefined} */
  let listener;
  const cleanup = () => { socket.abort(); listener?.[Symbol.dispose](); listener = undefined; };
  try {
    if (options === null || typeof options !== 'object') throw new PhantomError('InvalidArgument', 'WebSocket options must be an object');
    if (typeof input !== 'string' && !(input instanceof URL)) throw new PhantomError('InvalidArgument', 'WebSocket URL must be a string or URL');
    const url = typeof input === 'string' ? input : input.href;
    if (Buffer.byteLength(url) > 65536) throw new PhantomError('InputLimit', 'WebSocket URL exceeds 65536 bytes');
    const protocol = options.protocol === undefined ? 'http1' : options.protocol;
    if (!['profile', 'http1', 'http2', 'http3'].includes(protocol)) throw new PhantomError('InvalidProtocol', 'WebSocket protocol must be profile, http1, http2 or http3');
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new PhantomError('InvalidArgument', 'signal must be an AbortSignal');
    /** @type {{-readonly [K in keyof WebSocketOptions]?: WebSocketOptions[K]}} */
    const settings = {};
    for (const name of /** @type {const} */ (['maximumFrameBytes', 'maximumMessageBytes', 'maximumMessageFragments'])) {
      if (options[name] !== undefined) settings[name] = integer(options[name], name, 1, name === 'maximumMessageBytes' ? 64 * 1024 * 1024 : 0xffffffff);
    }
    if (options.handshakeTimeoutMs !== undefined) settings.handshakeTimeoutMs = options.handshakeTimeoutMs === null ? 0 : integer(options.handshakeTimeoutMs, 'handshakeTimeoutMs', 1);
    if (options.maximumConnectionFailures !== undefined) settings.maximumConnectionFailures = integer(options.maximumConnectionFailures, 'maximumConnectionFailures');
    if (options.retryDelayMs !== undefined) settings.retryDelayMs = integer(options.retryDelayMs, 'retryDelayMs');
    const fields = requestFields(options.headers, undefined);
    const headers = requestFields(mergeHeaders(defaults, fields.headers), undefined).headers;
    if (options.signal) listener = addAbortListener(options.signal, () => socket.abort());
    if (options.signal?.aborted) socket.abort();
    const handshake = await client.websocket({url, protocol, headers, ...settings}, socket);
    if (options.signal?.aborted) throw new PhantomError('Cancelled', 'WebSocket was aborted');
    return new WebSocketConnection(socket, handshake, cleanup, owner, token);
  } catch (error) { cleanup(); throw translated(error); }
}

module.exports = { WebSocketConnection, openWebSocket };
