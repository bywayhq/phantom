'use strict';

const { Client } = require('./lib/client.cjs');
const { AttemptBudget, RequestDiagnostics, TransferControl } = require('./lib/controls.cjs');
const { PhantomError } = require('./lib/errors.cjs');
const { EventStream } = require('./lib/events.cjs');
const native = require('./lib/native.cjs');
const { PreparedBody } = require('./lib/prepared-body.cjs');
const { Profile } = require('./lib/profile.cjs');
const { Response } = require('./lib/response.cjs');
const { ClientCertificate } = require('./lib/tls.cjs');
const { WebSocketConnection } = require('./lib/websocket.cjs');

module.exports = {
  AttemptBudget, Client, ClientCertificate, EventStream, PhantomError, PreparedBody, Profile,
  RequestDiagnostics, Response, TransferControl, WebSocketConnection, profiles: () => native.profileIds(),
};
