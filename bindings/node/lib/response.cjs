'use strict';

const { inspect, TextDecoder } = require('node:util');

const { bytes } = require('./bytes.cjs');
const { PhantomError, translated } = require('./errors.cjs');
const { EventStream, eventLimits } = require('./events.cjs');
const { isUploadContext, uploadError } = require('./upload.cjs');
const { integer } = require('./validation.cjs');

const abandonedResponses = new FinalizationRegistry((cleanup) => cleanup());

class Response {
  #native;
  #cleanup;
  #owner;
  #upload;
  #reading = false;
  #bodyStarted = false;
  #events = false;

  constructor(response, cleanup, owner, upload) {
    this.#native = response;
    this.#cleanup = cleanup;
    this.#owner = owner;
    this.#upload = upload;
    abandonedResponses.register(this, cleanup, this);

    this.status = response.status;
    this.protocol = response.protocol;
    this.url = response.url;
    this.redirects = response.redirects;
    this.connectionRetries = response.connectionRetries ?? null;
    Object.defineProperty(this, 'decodedContentCodings', {
      value: Object.freeze(response.decodedContentCodings), enumerable: true,
    });

    const history = response.redirectHistory;
    Object.defineProperty(this, 'redirectHistory', {
      value: history == null ? null : Object.freeze(Object.defineProperty({
        entries: Object.freeze(history.entries.map((hop) => Object.freeze(Object.defineProperty(
          { ...hop }, inspect.custom, { value: () => 'RedirectHop { URLs redacted }' },
        )))),
        omittedHops: history.omittedHops,
      }, inspect.custom, { value: () => 'RedirectHistory { URLs redacted }' })), enumerable: true,
    });

    this.headers = Object.freeze(response.headers.map(({ name, value, sensitive }) =>
      Object.freeze({ name, value, sensitive })));
  }

  get trailers() {
    try {
      const snapshot = this.#native.trailers;
      switch (snapshot.state) {
        case 'pending': case 'unavailable':
          return Object.freeze({ state: snapshot.state, headers: null });
        case 'complete':
          return Object.freeze({
            state: 'complete', headers: Object.freeze(snapshot.headers.map(
              ({ name, value, sensitive }) => Object.freeze({ name, value, sensitive }),
            ))
          });
        default: throw new PhantomError('UnsupportedResponseTrailers', 'unsupported response trailer state');
      }
    } catch (error) {
      throw translated(error);
    }
  }

  #finished() {
    this.#cleanup?.();
    this.#cleanup = undefined;
    this.#owner = undefined;
    abandonedResponses.unregister(this);
  }

  #checkMultipartWait() {
    if (this.#upload?.multipart && this.#upload.context !== undefined && isUploadContext(this.#upload.context)) throw new PhantomError('InvalidOperation', 'an upload producer cannot await its own response');
  }

  async #settleMultipart() {
    if (!this.#upload?.multipart) return;
    await this.#upload.finished;
    if (this.#upload.error) throw uploadError(this.#upload.error, this.#upload, true);
  }

  async read(maximumBytes = 65536) {
    this.#checkMultipartWait();
    integer(maximumBytes, 'maximumBytes', 1, 65536);
    if (this.#events) throw new PhantomError('BodyUsed', 'response body belongs to its event stream');
    if (this.#reading) throw new PhantomError('ConcurrentRead', 'only one body read may be pending');

    this.#reading = true;
    this.#bodyStarted = true;

    try {
      const part = await this.#native.read(maximumBytes);
      if (part === null) {
        this.#finished();
        await this.#settleMultipart();
      }

      return part;
    } catch (error) {
      this.close();
      throw uploadError(error, this.#upload);
    } finally {
      this.#reading = false;
    }
  }

  async bytes(maximumBytes) {
    this.#checkMultipartWait();
    integer(maximumBytes, 'maximumBytes');
    if (this.#events) throw new PhantomError('BodyUsed', 'response body belongs to its event stream');
    if (this.#reading) {
      throw new PhantomError('ConcurrentRead', 'only one body read may be pending');
    }

    this.#reading = true;
    this.#bodyStarted = true;

    try {
      const body = await this.#native.collect(maximumBytes);
      this.#finished();
      await this.#settleMultipart();
      return body;
    } catch (error) {
      this.close();
      throw uploadError(error, this.#upload);
    } finally {
      this.#reading = false;
    }
  }

  async text(maximumBytes) {
    const body = await this.bytes(maximumBytes);
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(body);
    } catch {
      throw new PhantomError('TextDecode', 'response UTF-8 decoding failed');
    } finally {
      this.close();
    }
  }

  async json(maximumBytes) {
    const text = await this.text(maximumBytes);
    try {
      return JSON.parse(text);
    } catch {
      throw new PhantomError('JsonDecode', 'response JSON parsing failed');
    }
  }

  events(options) {
    this.#checkMultipartWait();
    const limits = eventLimits(options);
    if (this.#reading) throw new PhantomError('ConcurrentRead', 'only one body read may be pending');
    if (this.#bodyStarted || this.#events) throw new PhantomError('BodyUsed', 'events require an unread response body');

    let native;
    try {
      native = this.#native.events(...limits);
    } catch (error) {
      throw translated(error);
    }

    this.#events = true;
    return new EventStream(native, () => this.#finished(), () => this.#settleMultipart(),
      (error) => uploadError(error, this.#upload), () => this.#checkMultipartWait());
  }

  close() {
    this.#native.close();
    this.#finished();
  }

  [Symbol.asyncIterator]() {
    const response = this;
    return {
      async next() {
        const value = await response.read();
        return value === null ? { done: true, value: undefined } : { done: false, value };
      },
      async return() {
        response.close();
        return { done: true, value: undefined };
      },
      async throw(error) {
        response.close();
        throw error;
      },
      [Symbol.asyncIterator]() {
        return this;
      },
    };
  }

  async [Symbol.asyncDispose]() {
    this.#checkMultipartWait();
    this.close();
    await this.#settleMultipart();
  }
}

module.exports = { Response };
