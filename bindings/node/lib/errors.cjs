'use strict';

const { inspect, types } = require('node:util');

class PhantomError extends Error {
  constructor(code, message, protocol, timeoutPhase, kind, field) {
    super(message);
    this.name = 'PhantomError';
    this.code = code;
    this.protocol = protocol;
    this.timeoutPhase = timeoutPhase;
    this.kind = kind;
    this.field = field;
  }
}

function translated(error) {
  if (types.isProxy(error)) return caused(new PhantomError('NativeFailure', 'native operation failed'), error);
  if (error instanceof PhantomError) return error;
  const properties = error !== null && typeof error === 'object' ? Object.getOwnPropertyDescriptors(error) : {};
  const message = typeof properties.message?.value === 'string' ? properties.message.value : '';
  const websocket = /^PHANTOM_WEBSOCKET:([A-Za-z0-9_]+):([A-Za-z0-9_]*):([0-9]*):([\s\S]*)$/.exec(message);
  if (websocket) {
    const failure = new PhantomError('WebSocket', websocket[4], undefined, websocket[2] || undefined, websocket[1]);
    if (websocket[3]) Object.defineProperty(failure, 'status', {value: Number(websocket[3]), enumerable: true});
    return failure;
  }
  const certificate = /^PHANTOM_CERTIFICATE:([A-Za-z0-9_]+):([\s\S]*)$/.exec(message);
  if (certificate) return new PhantomError('ClientCertificate', certificate[2], undefined, undefined, certificate[1]);
  const prepared = /^PHANTOM_PREPARED:([A-Za-z0-9_]+):([\s\S]*)$/.exec(message);
  if (prepared) return new PhantomError('PreparedBody', prepared[2], undefined, undefined, prepared[1]);
  const snapshot = /^PHANTOM_SNAPSHOT:([A-Za-z0-9_]+):([\s\S]*)$/.exec(message);
  if (snapshot) return new PhantomError('SessionSnapshot', snapshot[2], undefined, undefined, snapshot[1]);
  const profile = /^PHANTOM_PROFILE:(ProfileImport|ProfileExport):([A-Za-z0-9_]+):([^:]*):([\s\S]*)$/.exec(message);
  if (profile) return new PhantomError(profile[1], profile[4], undefined, undefined, profile[2], profile[3]);
  const request = /^PHANTOM_REQUEST:([A-Za-z0-9_]+):([A-Za-z0-9_]*):([A-Za-z0-9_]*):([\s\S]*)$/.exec(message);
  if (request) return new PhantomError(request[1], request[4], request[2] || undefined, request[3] || undefined);
  const match = /^PHANTOM:([A-Za-z0-9_]+):([\s\S]*)$/.exec(message);
  if (match) return new PhantomError(match[1], match[2]);
  return caused(properties.code?.value === 'InvalidArg'
    ? new PhantomError('InvalidArgument', 'native argument conversion failed')
    : new PhantomError('NativeFailure', 'native operation failed'), error);
}

function caused(error, cause) {
  Object.defineProperties(error, {
    cause: {value: cause, configurable: true},
    [inspect.custom]: {value: () => `PhantomError { code: ${inspect(error.code)}, message: ${inspect(error.message)}, cause redacted }`, configurable: true},
  });
  return error;
}

module.exports = { PhantomError, translated, caused };
