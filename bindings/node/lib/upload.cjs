'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const { Readable } = require('node:stream');
const { finished } = require('node:stream/promises');
const { inspect, types } = require('node:util');

const { bytes, apply, lengthOf, backingOf, offsetOf } = require('./bytes.cjs');
const { translated, PhantomError } = require('./errors.cjs');
const { preparedOptions, preparedFailure, preparedArray } = require('./prepared-body.cjs');
const { policyFields, integer } = require('./validation.cjs');

const multipartClaims = new WeakSet();
const uploadContext = new AsyncLocalStorage();

function uploadError(error, outcome, preferSource = false) {
  const nativeError = translated(error);
  if (!outcome) return nativeError;
  const result = (preferSource || nativeError.code === 'RequestBody')
    && outcome.error && outcome.error !== outcome.cleanupError
    && !['Cancelled', 'Timeout'].includes(nativeError.code)
    ? outcome.error : nativeError;
  if (result !== nativeError) {
    for (const field of ['protocol', 'timeoutPhase', 'kind', 'field']) {
      if (result[field] === undefined) result[field] = nativeError[field];
    }
  }
  if (!Object.hasOwn(result, 'cleanupError')) {
    Object.defineProperties(result, {
      cause: { get: () => outcome.originalPresent ? outcome.original : outcome.cleanupOriginal },
      cleanupError: { get: () => outcome.cleanupOriginal },
      [inspect.custom]: { value: () => `PhantomError { code: ${inspect(result.code)}, protocol: ${inspect(result.protocol)}, timeoutPhase: ${inspect(result.timeoutPhase)}, upload details redacted }` },
    });
  }
  return result;
}

function multipartOptions(value) {
  if (value === undefined) return undefined;
  const options = policyFields(value, ['boundary', 'maximumBytes', 'parts']);
  const { boundary, maximumBytes } = preparedOptions({ boundary: options.boundary, maximumBytes: options.maximumBytes }, true);
  const parts = options.parts;
  if (!Array.isArray(parts) || types.isProxy(parts)) throw new PhantomError('InvalidArgument', 'multipart parts must be an ordered array');
  if (parts.length > 1024) throw preparedFailure('too_many_parts');
  preparedArray(parts);
  let metadata = 65536, remaining = maximumBytes;
  const fields = [], sources = [], identities = new Set();
  for (const input of parts) {
    const part = policyFields(input, ['name', 'text', 'bytes', 'stream', 'file', 'filename', 'contentType']);
    if (['text', 'bytes', 'stream', 'file'].filter((key) => part[key] !== undefined).length !== 1) throw new PhantomError('InvalidArgument', 'multipart part requires one payload');
    for (const key of ['name', 'filename', 'contentType']) {
      if (part[key] === undefined && key !== 'name') continue;
      if (typeof part[key] !== 'string') throw new PhantomError('InvalidArgument', `multipart ${key} must be a string`);
      const count = Buffer.byteLength(part[key]);
      metadata -= count;
      if (count > 4096 || metadata < 0) throw new PhantomError('InputLimit', 'multipart metadata exceeds its limit');
    }
    const field = { ...part };
    let source;
    if (part.text !== undefined) {
      if (typeof part.text !== 'string') throw new PhantomError('InvalidArgument', 'multipart text must be a string');
      remaining -= BigInt(Buffer.byteLength(part.text));
    } else if (part.bytes !== undefined) {
      field.bytes = bytes(part.bytes);
      remaining -= BigInt(apply(lengthOf, field.bytes, []));
    } else if (part.file !== undefined) {
      const file = policyFields(part.file, ['path', 'maximumBytes']);
      if (typeof file.path !== 'string' || !file.path.length || Buffer.byteLength(file.path) > 4096) throw new PhantomError('InvalidArgument', 'multipart file requires a bounded path');
      integer(file.maximumBytes, 'multipart file maximumBytes');
      metadata -= Buffer.byteLength(file.path);
      if (metadata < 0) throw new PhantomError('InputLimit', 'multipart metadata exceeds its limit');
      field.file = file;
    } else {
      source = part.stream;
      if (source === null || typeof source !== 'object' || types.isProxy(source)
        || (!(source instanceof Readable) && (typeof source.next !== 'function' || typeof source.return !== 'function' || typeof source[Symbol.asyncIterator] !== 'function'))) {
        throw new PhantomError('InvalidArgument', 'multipart stream must be a Readable or closeable async iterator');
      }
      if (identities.has(source)) throw new PhantomError('InvalidArgument', 'multipart sources must be distinct');
      identities.add(source);
      field.stream = true;
    }
    if (remaining < 0n) throw preparedFailure('too_large');

    fields.push(field);
    sources.push(source);
  }
  if (multipartClaims.has(value)) throw new PhantomError('InvalidOperation', 'multipart belongs to one request');

  return { descriptor: value, boundary, maximumBytes, fields, sources };
}

function uploadLength(value) {
  if ((typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
    || (typeof value === 'bigint' && value >= 0n && value <= 0xffffffffffffffffn)) return BigInt(value);
  throw new PhantomError('InvalidArgument', 'bodyLength must be an exact unsigned 64-bit integer');
}

async function pumpUpload(iterator, upload, outcome) {
  let ended = false;
  let terminated = false;
  const stopped = upload.stopped().then(() => {
    terminated = true;
    return { stopped: true };
  });

  try {
    let credit = false;
    let emptyChunks = 0;
    while (true) {
      if (!credit) {
        const ready = await Promise.race([upload.ready().then((ready) => ({ ready })), stopped]);
        if (!ready.ready) return;
      }

      if (terminated) return;

      const next = await Promise.race([Promise.resolve().then(async () => {
        try {
          if (terminated) return { stopped: true };
          const result = await iterator.next();
          if (result === null || typeof result !== 'object') throw new Error();
          return { done: Boolean(result.done), value: result.value };
        } catch (error) {
          outcome.original = error;
          outcome.originalPresent = true;
          throw new PhantomError('UploadSource', 'upload source failed');
        }
      }), stopped]);
      if (next.stopped) return;
      if (next === null || typeof next !== 'object') throw new PhantomError('UploadSource', 'upload iterator returned an invalid result');
      if (next.done) {
        if (!uploadOperation(() => upload.end())) return;
        ended = true;
        return;
      }

      const chunk = bytes(next.value);
      const length = apply(lengthOf, chunk, []);
      credit = length === 0;
      if (credit && ++emptyChunks >= 16) {
        await new Promise((resolve) => setImmediate(resolve));
        emptyChunks = 0;
      } else if (!credit) emptyChunks = 0;

      for (let offset = 0; offset < length; offset += 65536) {
        if (offset !== 0 && !await upload.ready()) return;
        // The native call copies this view synchronously on this environment.
        const view = Buffer.from(apply(backingOf, chunk, []), apply(offsetOf, chunk, []) + offset, Math.min(65536, length - offset));
        if (!uploadOperation(() => upload.write(view))) return;
      }
    }
  } catch (error) {
    outcome.error = error instanceof PhantomError ? error : new PhantomError('UploadSource', 'upload source failed');
    if (!(error instanceof PhantomError)) {
      outcome.original = error;
      outcome.originalPresent = true;
    }

    outcome.error = uploadError(outcome.error, outcome);
    upload.fail();
  } finally {
    upload.stop();
    try {
      if (!ended && typeof iterator.return === 'function') await iterator.return();
    } catch (error) {
      outcome.cleanupOriginal = error;
      outcome.cleanupError = uploadError(new PhantomError('UploadSource', 'upload cleanup failed'), outcome);
      outcome.error ??= outcome.cleanupError;
      upload.fail();
    } finally {
      upload.settled();
    }
  }
}

async function pumpMultipart(sources, upload, outcome) {
  let terminated = false;
  const stopped = upload.stopped().then(() => {
    terminated = true;
    return { stopped: true };
  });
  const closed = new Set();
  const cleanupFailures = [];
  const rememberCleanup = (error) => {
    cleanupFailures.push(error);
    outcome.cleanupOriginal = cleanupFailures.length === 1 ? error : new AggregateError([...cleanupFailures], 'multipart cleanup failed');
    outcome.cleanupError ??= uploadError(new PhantomError('UploadSource', 'multipart cleanup failed'), outcome);
    outcome.error ??= outcome.cleanupError;
  };

  const closeSource = async (source) => {
    if (source === undefined || closed.has(source)) return;

    closed.add(source);
    try {
      if (source instanceof Readable) {
        const wasErrored = source.errored;
        const done = finished(source, { cleanup: true });
        source.destroy();
        try {
          await done;
        } catch (error) {
          if (wasErrored || error?.code !== 'ERR_STREAM_PREMATURE_CLOSE') throw error;
        }
      } else {
        const result = await source.return();
        if (result === null || typeof result !== 'object' || !result.done) throw new PhantomError('UploadSource', 'multipart source did not close');
      }
    } catch (error) {
      rememberCleanup(error);
    }
  };

  try {
    while (!terminated) {
      const selected = await Promise.race([upload.nextPart().then((index) => ({ index })), stopped]);
      if (selected.stopped || selected.index === null || selected.index === undefined) return;

      const source = sources[selected.index];
      if (source === undefined || closed.has(source)) throw new PhantomError('UploadSource', 'multipart source demand is invalid');

      let iterator;
      try {
        iterator = source[Symbol.asyncIterator]();
        if (iterator === null || typeof iterator?.next !== 'function' || (!(source instanceof Readable) && iterator !== source)) throw new PhantomError('UploadSource', 'multipart stream must be its own async iterator');
      } catch (error) {
        outcome.original = error;
        outcome.originalPresent = true;
        throw new PhantomError('UploadSource', 'multipart source failed');
      }

      let credit = false, empties = 0;
      while (!terminated) {
        if (!credit && !await upload.ready()) return;
        if (terminated) return;

        const next = await Promise.race([Promise.resolve().then(async () => {
          try {
            if (terminated) return { stopped: true };
            const result = await iterator.next();
            if (result === null || typeof result !== 'object') throw new PhantomError('UploadSource', 'multipart iterator returned an invalid result');
            return result;
          } catch (error) {
            outcome.original = error;
            outcome.originalPresent = true;
            throw new PhantomError('UploadSource', 'multipart source failed');
          }
        }), stopped]);
        if (next.stopped) return;
        if (next.done) {
          // A child cannot advance the encoder until its host cleanup settles.
          await closeSource(source);
          if (outcome.error) {
            upload.fail();
            return;
          }
          if (!uploadOperation(() => upload.end())) return;
          break;
        }

        const chunk = bytes(next.value), length = apply(lengthOf, chunk, []);
        credit = length === 0;
        if (credit && ++empties >= 16) {
          await new Promise((resolve) => setImmediate(resolve));
          empties = 0;
        }
        else if (!credit) empties = 0;

        for (let offset = 0; offset < length; offset += 65536) {
          if (offset && !await upload.ready()) return;
          const view = Buffer.from(apply(backingOf, chunk, []), apply(offsetOf, chunk, []) + offset, Math.min(65536, length - offset));
          if (!uploadOperation(() => upload.write(view))) return;
        }
      }
    }
  } catch (error) {
    outcome.error = error instanceof PhantomError ? error : new PhantomError('UploadSource', 'multipart source failed');
    if (!(error instanceof PhantomError)) {
      outcome.original = error;
      outcome.originalPresent = true;
    }

    outcome.error = uploadError(outcome.error, outcome);
    upload.fail();
  } finally {
    upload.stop();
    // Begin all terminal closes before awaiting any cooperative source.
    await Promise.all(sources.map(closeSource));
    upload.settled();
  }
}

function uploadOperation(operation) {
  try {
    operation();
    return true;
  } catch (error) {
    const translatedError = translated(error);
    if (translatedError.code === 'UploadClosed') return false;
    throw translatedError;
  }
}

function claimMultipart(descriptor) { multipartClaims.add(descriptor); }

function runUpload(owner, operation) { return uploadContext.run(owner, operation); }

function isUploadContext(owner) { return uploadContext.getStore() === owner; }

module.exports = { isUploadContext, uploadError, runUpload, pumpMultipart, pumpUpload, multipartOptions, uploadLength, claimMultipart };
