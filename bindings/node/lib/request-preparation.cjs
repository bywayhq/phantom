// @ts-check
'use strict';

const { types } = require('node:util');

const { PhantomError, caused } = require('./errors.cjs');
const { encodedBody } = require('./prepared-body.cjs');
const { requestFields } = require('./request-options.cjs');

/** @typedef {import('../index.js').Header} Header */
/** @typedef {import('../index.js').RequestOptions} RequestOptions */
/** @typedef {import('../index.js').RequestContext} RequestContext */
/** @typedef {import('../index.js').RequestProtocol} RequestProtocol */
/** @typedef {Readonly<{protocol: RequestProtocol, context?: RequestContext, headers: readonly Header[]}>} RequestDefaults */

const maximumBodyBytes = 16 * 1024 * 1024;
const maximumUrlBytes = 65536;

/** @param {import('../index.js').ClientOptions} options
 * @param {RequestContext | undefined} attachedContext
 * @returns {RequestDefaults} */
function requestDefaults(options, attachedContext) {
  if (options === null || typeof options !== 'object') {
    throw new PhantomError('InvalidArgument', 'client options are required');
  }
  for (const name of ['protocol', 'context', 'headers']) {
    const field = Object.getOwnPropertyDescriptor(options, name);
    if (field !== undefined && !Object.hasOwn(field, 'value')) {
      throw new PhantomError('InvalidArgument', `${name} must be a data field`);
    }
  }
  const protocol = options.protocol === undefined ? 'negotiated' : options.protocol;
  const context = options.context === undefined ? attachedContext : options.context;
  validateSelections(protocol, context);

  /** @type {Header[]} */
  const headers = requestFields(options.headers, undefined).headers ?? [];
  return Object.freeze({
    protocol, context,
    headers: Object.freeze(headers.map((header) => Object.freeze({
      ...header, value: Buffer.from(header.value),
    }))),
  });
}

/** @param {unknown} protocol @param {unknown} context */
function validateSelections(protocol, context) {
  if (typeof protocol !== 'string' || !['http1', 'http2', 'http3', 'negotiated'].includes(protocol)) {
    throw new PhantomError('InvalidProtocol', 'protocol must be http1, http2, http3 or negotiated');
  }
  if (context !== undefined && (typeof context !== 'string' || !['raw', 'profile', 'navigation', 'fetch', 'fetchNoStore', 'fetchUpload', 'script', 'stylesheet', 'image', 'font'].includes(context))) {
    throw new PhantomError('InvalidContext', 'context must be raw, profile or a catalog request context');
  }
}

/** @param {unknown} input @param {string} name @param {number} maximum */
function encodedFields(input, name, maximum) {
  if (!(input instanceof URLSearchParams) && (!Array.isArray(input) || types.isProxy(input))) {
    throw new PhantomError('InvalidArgument', `${name} must be URLSearchParams or ordered string pairs`);
  }
  const pieces = [];
  let length = 0;
  for (const pair of input) {
    if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'string' || typeof pair[1] !== 'string') {
      throw new PhantomError('InvalidArgument', `${name} entries must be string pairs`);
    }
    const separator = pieces.length === 0 ? 0 : 1;
    if (pair[0].length + pair[1].length + 1 + separator > maximum - length) {
      throw new PhantomError('InputLimit', `${name} exceeds its encoded byte limit`);
    }
    const encoded = new URLSearchParams([[pair[0], pair[1]]]).toString();
    length += encoded.length + separator;
    if (length > maximum) throw new PhantomError('InputLimit', `${name} exceeds its encoded byte limit`);
    pieces.push(encoded);
  }
  return pieces.join('&');
}

/** @param {string | URL} input @param {RequestOptions['query']} query */
function requestUrl(input, query) {
  if (typeof input !== 'string' && !(input instanceof URL)) {
    throw new PhantomError('InvalidArgument', 'url must be a string or URL');
  }
  const url = typeof input === 'string' ? input : input.href;
  if (Buffer.byteLength(url) > maximumUrlBytes) throw new PhantomError('InputLimit', 'url exceeds 65536 bytes');
  if (query === undefined) return url;
  const encoded = encodedFields(query, 'query', maximumUrlBytes);
  if (encoded === '') return url;

  const fragment = url.indexOf('#');
  const head = fragment < 0 ? url : url.slice(0, fragment);
  const tail = fragment < 0 ? '' : url.slice(fragment);
  const separator = head.includes('?') ? (head.endsWith('?') || head.endsWith('&') ? '' : '&') : '?';
  const joined = head + separator + encoded + tail;
  if (Buffer.byteLength(joined) > maximumUrlBytes) throw new PhantomError('InputLimit', 'url exceeds 65536 bytes');
  return joined;
}

/** @param {RequestDefaults} defaults @param {string | URL} url
 * @param {RequestOptions} [options]
 * @returns {{url: string, options: Omit<RequestOptions, 'body'> & {body?: Exclude<RequestOptions['body'], string>}}} */
function prepareRequest(defaults, url, options = {}) {
  if (options === null || typeof options !== 'object') {
    throw new PhantomError('InvalidArgument', 'request options must be an object');
  }
  const protocol = options.protocol === undefined ? defaults.protocol : options.protocol;
  const context = options.context === undefined ? defaults.context : options.context;
  validateSelections(protocol, context);
  if (context === undefined) {
    throw new PhantomError('InvalidArgument', 'set a request context on the client or request');
  }
  const resolvedUrl = requestUrl(url, options.query);
  const payloads = [options.body, options.json, options.form, options.file, options.multipart].filter((value) => value !== undefined);
  if (payloads.length > 1) throw new PhantomError('InvalidArgument', 'choose one of body, json, form, file or multipart');
  if ((options.json !== undefined || options.form !== undefined) && options.bodyLength !== undefined) {
    throw new PhantomError('InvalidArgument', 'bodyLength cannot be combined with json or form');
  }

  let body = options.body;
  let contentType;
  if (options.json !== undefined) {
    let encoded;
    try { encoded = JSON.stringify(options.json); }
    catch (cause) {
      throw caused(new PhantomError('JsonEncode', 'request JSON serialization failed'), cause);
    }
    if (encoded === undefined) throw new PhantomError('JsonEncode', 'request JSON must serialize to a value');
    if (Buffer.byteLength(encoded) > maximumBodyBytes) throw new PhantomError('InputLimit', 'request body exceeds 16777216 bytes');
    body = Buffer.from(encoded);
    contentType = 'application/json';
  } else if (options.form !== undefined) {
    body = Buffer.from(encodedFields(options.form, 'form', maximumBodyBytes));
    contentType = 'application/x-www-form-urlencoded;charset=UTF-8';
  } else if (typeof body === 'string') {
    if (Buffer.byteLength(body) > maximumBodyBytes) throw new PhantomError('InputLimit', 'request body exceeds 16777216 bytes');
    body = Buffer.from(body);
    contentType = 'text/plain;charset=UTF-8';
  }
  // Validate caller fields before using their names to replace default fields.
  /** @type {{headers?: Header[], trailers?: Header[]}} */
  const fields = requestFields(options.headers, options.trailers);
  let headers = mergeHeaders(defaults.headers, fields.headers);
  const addedContentType = contentType !== undefined && !headers?.some((header) => header.name.toLowerCase() === 'content-type');
  if (addedContentType && contentType !== undefined) {
    headers ??= [];
    headers.push({name: 'content-type', value: Buffer.from(contentType)});
  }
  const combined = defaults.headers.length > 0 || addedContentType ? requestFields(headers, fields.trailers) : fields;
  if (contentType !== undefined && types.isUint8Array(body)) {
    body = encodedBody(body, contentType, maximumBodyBytes);
  }
  return {url: resolvedUrl, options: {
    ...options, method: options.method === undefined ? 'GET' : options.method, protocol, context,
    ...combined, body,
  }};
}

/** @param {readonly Header[]} defaults @param {Header[] | undefined} headers */
function mergeHeaders(defaults, headers) {
  if (defaults.length === 0) return headers;
  const replaced = new Set(headers?.map((header) => header.name.toLowerCase()));
  return [...defaults.filter((header) => !replaced.has(header.name.toLowerCase())), ...(headers ?? [])];
}

module.exports = { requestDefaults, prepareRequest, mergeHeaders };
