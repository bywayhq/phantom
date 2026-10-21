'use strict';

const { Client } = require('./lib/client.cjs');
const { AttemptBudget, RequestDiagnostics, TransferControl } = require('./lib/controls.cjs');
const { PhantomError } = require('./lib/errors.cjs');
const native = require('./lib/native.cjs');
const { PreparedBody } = require('./lib/prepared-body.cjs');
const { Profile } = require('./lib/profile.cjs');
const { Response } = require('./lib/response.cjs');
const { ClientCertificate } = require('./lib/tls.cjs');

module.exports = {
  AttemptBudget, Client, ClientCertificate, PhantomError, PreparedBody, Profile,
  RequestDiagnostics, Response, TransferControl, profiles: () => native.profileIds(),
};
