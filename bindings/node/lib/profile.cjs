'use strict';

const { types } = require('node:util');

const { bytes } = require('./bytes.cjs');
const { PhantomError, translated } = require('./errors.cjs');
const native = require('./native.cjs');

const profileHandles = new WeakMap();
const profileToken = {};

function profileHandle(value) {
  const handle = profileHandles.get(value);
  if (handle === undefined) throw new PhantomError('InvalidProfile', 'profile must be an exact identifier or a Profile');
  return handle;
}

function descriptionError(kind = 'InvalidValue') {
  return new PhantomError('ProfileImport', 'profile description rejected', undefined, undefined, kind, 'document');
}

function encodeDescription(document) {
  let remaining = 16 * 1024 * 1024;
  let nodes = 0;
  const active = new WeakSet();
  const charge = (length) => {
    remaining -= length;
    if (remaining < 0) throw descriptionError('TooLarge');
  };
  const string = (value) => {
    if (value.length > 65536 || Buffer.byteLength(value) > 65536) throw descriptionError('TooLarge');
    charge(Buffer.byteLength(JSON.stringify(value)));
  };
  // Snapshot data descriptors before stringify: getters/toJSON cannot change
  // validated values or expand them after the resource checks.
  const snapshot = (value, depth) => {
    if (depth > 16 || ++nodes > 1048576) throw descriptionError('TooLarge');
    if (typeof value === 'string') { string(value); return value; }
    if (typeof value === 'bigint') {
      if (value < 0n || value > 18446744073709551615n) throw descriptionError();
      charge(value.toString().length);
      return value;
    }
    if (value === null || typeof value === 'boolean') { charge(value === null ? 4 : value ? 4 : 5); return value; }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) throw descriptionError();
      charge(JSON.stringify(value).length);
      return value;
    }
    if (typeof value !== 'object' || types.isProxy(value) || active.has(value)) throw descriptionError();
    const array = Array.isArray(value);
    if (!array && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw descriptionError();
    if (Object.getOwnPropertySymbols(value).length !== 0) throw descriptionError();
    if (array && value.length > 65535) throw descriptionError('TooLarge');
    const result = array ? [] : Object.create(null);
    active.add(value);
    charge(2);
    let count = 0;
    for (const name in value) {
      if (!Object.hasOwn(value, name)) continue;
      if (++count > (array ? 65535 : 64)) throw descriptionError('TooLarge');
      if (array && name !== String(count - 1)) throw descriptionError();
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!Object.hasOwn(descriptor, 'value')) throw descriptionError();
      if (count > 1) charge(1);
      if (!array) { string(name); charge(1); }
      Object.defineProperty(result, name, {value: snapshot(descriptor.value, depth + 1), enumerable: true});
    }
    if (array && count !== value.length) throw descriptionError();
    active.delete(value);
    return result;
  };
  if (document === null || typeof document !== 'object' || types.isProxy(document) || Array.isArray(document)) throw descriptionError();
  const copy = snapshot(document, 0);
  return Buffer.from(JSON.stringify(copy, (_name, value) => typeof value === 'bigint' ? JSON.rawJSON(value.toString()) : value));
}

class Profile {
  constructor(token, handle) {
    if (token !== profileToken) throw new PhantomError('InvalidProfile', 'use Profile.fromCatalog or Profile.importJson');
    profileHandles.set(this, handle);
    Object.freeze(this);
  }
  static fromCatalog(identifier, context) {
    if (typeof identifier !== 'string' || (context !== undefined && typeof context !== 'string')) {
      throw new PhantomError('InvalidArgument', 'catalog identifier and optional context must be strings');
    }
    try { return new Profile(profileToken, native.profileCatalog(identifier, context)); }
    catch (error) { throw translated(error); }
  }
  static importJson(input) {
    try { return new Profile(profileToken, native.profileImportJson(bytes(input))); }
    catch (error) { throw translated(error); }
  }
  static fromDescription(document) { return Profile.importJson(encodeDescription(document)); }
  static #import(input, options, method, binary = false) {
    if (options === null || typeof options !== 'object' || types.isProxy(options) || Array.isArray(options)) {
      throw new PhantomError('InvalidArgument', 'imports require an explicit base Profile');
    }
    const properties = Object.getOwnPropertyDescriptors(options);
    if (Object.keys(properties).some((name) => !['base', ...(method === 'importJa4' ? ['format'] : [])].includes(name))
      || Object.values(properties).some((property) => !Object.hasOwn(property, 'value'))) {
      throw new PhantomError('InvalidArgument', 'import options must contain only base and the required JA4 format');
    }
    const handle = profileHandle(properties.base?.value);
    const format = properties.format?.value;
    if (method === 'importJa4' && format !== 'sorted' && format !== 'original') {
      throw new PhantomError('ProfileImport', 'profile description rejected', undefined, undefined, 'InvalidValue', 'ja4.format');
    }
    if (!binary && typeof input !== 'string') throw new PhantomError('InvalidArgument', 'fingerprint description must be a string');
    try {
      const imported = method === 'importJa4' ? handle[method](input, format) : handle[method](binary ? bytes(input) : input);
      return Object.freeze({
        profile: new Profile(profileToken, imported.profile),
        observedFields: Object.freeze([...imported.observedFields]),
        supplementedFields: Object.freeze([...imported.supplementedFields]),
      });
    } catch (error) { throw translated(error); }
  }
  static importJa3(description, options) { return Profile.#import(description, options, 'importJa3'); }
  static importClientHello(handshake, options) { return Profile.#import(handshake, options, 'importClientHello', true); }
  static importAkamai(description, options) { return Profile.#import(description, options, 'importAkamai'); }
  static importJa4(description, options) { return Profile.#import(description, options, 'importJa4'); }
  static importQuicTransport(parameters, options) { return Profile.#import(parameters, options, 'importQuicTransport', true); }
  get catalogId() { return profileHandle(this).catalogId; }
  get contexts() { return Object.freeze(profileHandle(this).contexts); }
  exportJson() {
    try { return profileHandle(this).exportJson(); }
    catch (error) { throw translated(error); }
  }
  describe() {
    return JSON.parse(this.exportJson().toString('utf8'), (_name, value, context) =>
      typeof value === 'number' && !Number.isSafeInteger(value) ? BigInt(context.source) : value);
  }
}

module.exports = { Profile, profileHandle };
