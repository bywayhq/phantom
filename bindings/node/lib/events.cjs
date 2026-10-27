// @ts-check
'use strict';

const {PhantomError} = require('./errors.cjs');
const {integer, policyFields} = require('./validation.cjs');

/** @typedef {import('../index.js').SseEvent} SseEvent */
/** @typedef {{read(): Promise<SseEvent | null>, close(): void, readonly lastEventId: string, readonly retryMs: bigint | null}} NativeEvents */

/** @param {import('../index.js').SseOptions | undefined} options */
function eventLimits(options) {
  const fields = options === undefined ? {} : policyFields(options, ['maximumLineBytes', 'maximumEventBytes']);
  return [integer(fields.maximumLineBytes === undefined ? 65536 : fields.maximumLineBytes, 'maximumLineBytes'),
    integer(fields.maximumEventBytes === undefined ? 1048576 : fields.maximumEventBytes, 'maximumEventBytes')];
}

class EventStream {
  #native;
  #finish;
  #settle;
  #error;
  #check;
  #reading = false;
  #ended = false;
  /** @param {NativeEvents} native @param {() => void} finish
   * @param {() => Promise<void>} settle @param {(error: unknown) => Error} error
   * @param {() => void} check */
  constructor(native, finish, settle, error, check) {
    this.#native = native; this.#finish = finish; this.#settle = settle; this.#error = error;
    this.#check = check;
  }
  get lastEventId() {return this.#native.lastEventId;}
  get retryMs() {return this.#native.retryMs ?? null;}
  #finished() {
    if (this.#ended) return;
    this.#ended = true; this.#finish();
  }
  /** @returns {Promise<SseEvent | null>} */
  async read() {
    this.#check();
    if (this.#ended) return null;
    if (this.#reading) throw new PhantomError('ConcurrentRead', 'only one event read may be pending');
    this.#reading = true;
    try {
      const value = await this.#native.read();
      if (value === null) {this.#finished(); await this.#settle(); return null;}
      return Object.freeze({...value, retryMs: value.retryMs ?? null});
    } catch (error) {this.close(); throw this.#error(error);}
    finally {this.#reading = false;}
  }
  close() {if (!this.#ended) {this.#native.close(); this.#finished();}}
  /** @returns {Promise<IteratorResult<SseEvent>>} */
  async next() {
    const value = await this.read();
    return value === null ? {done: true, value: undefined} : {done: false, value};
  }
  /** @returns {Promise<IteratorResult<SseEvent>>} */
  async return() {this.#check(); this.close(); await this.#settle(); return {done: true, value: undefined};}
  /** @param {unknown} error */
  async throw(error) {this.close(); throw error;}
  [Symbol.asyncIterator]() {return this;}
  [Symbol.dispose]() {this.close();}
  async [Symbol.asyncDispose]() {this.#check(); this.close(); await this.#settle();}
}

module.exports = {EventStream, eventLimits};
