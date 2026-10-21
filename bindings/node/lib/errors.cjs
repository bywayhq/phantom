'use strict';


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
  if (error instanceof PhantomError) return error;
  const certificate = /^PHANTOM_CERTIFICATE:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  if (certificate) return new PhantomError('ClientCertificate', certificate[2], undefined, undefined, certificate[1]);
  const prepared = /^PHANTOM_PREPARED:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  if (prepared) return new PhantomError('PreparedBody', prepared[2], undefined, undefined, prepared[1]);
  const snapshot = /^PHANTOM_SNAPSHOT:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  if (snapshot) return new PhantomError('SessionSnapshot', snapshot[2], undefined, undefined, snapshot[1]);
  const profile = /^PHANTOM_PROFILE:(ProfileImport|ProfileExport):([A-Za-z0-9_]+):([^:]*):([\s\S]*)$/.exec(error?.message ?? '');
  if (profile) return new PhantomError(profile[1], profile[4], undefined, undefined, profile[2], profile[3]);
  const request = /^PHANTOM_REQUEST:([A-Za-z0-9_]+):([A-Za-z0-9_]*):([A-Za-z0-9_]*):([\s\S]*)$/.exec(error?.message ?? '');
  if (request) return new PhantomError(request[1], request[4], request[2] || undefined, request[3] || undefined);
  const match = /^PHANTOM:([A-Za-z0-9_]+):([\s\S]*)$/.exec(error?.message ?? '');
  return match
    ? new PhantomError(match[1], match[2])
    : new PhantomError('InvalidArgument', 'native argument conversion failed');
}

module.exports = { PhantomError, translated };
