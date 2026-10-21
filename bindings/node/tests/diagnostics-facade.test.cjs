'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const {inspect} = require('node:util');
const {test} = require('node:test');

function facade() {
  const observers = [], requests = [];
  const native = {
    NativeEnvironment: class {client() {return {async close() {}, async request(...args) {
      requests.push(args);
      const observer = args[5];
      if (observer) {
        if (observer.used) throw new Error('PHANTOM:DiagnosticsAlreadyUsed:diagnostics belong to one request');
        observer.used = true;
      }
      return {status: 204, headers: [], protocol: 'http1', url: 'http://example.test/', redirects: 0,
        connectionRetries: 0, decodedContentCodings: [], redirectHistory: null, close() {}};
    }};}},
    NativeCancellation: class {cancel() {}},
    NativeRequestDiagnostics: class {
      constructor(maximum) {this.maximum = maximum; this.value = null; observers.push(this);}
      snapshot() {if (this.error) throw this.error; return this.value;}
    },
  };
  const filename = path.resolve(__dirname, '../index.cjs');
  const loaded = new Module(filename, module); loaded.filename = filename; loaded.paths = module.paths;
  loaded.require = (id) => id === './phantom.node' ? native
    : id === 'node:fs' ? {...fs, existsSync: (file) => file === path.join(path.dirname(filename), 'phantom.node') || fs.existsSync(file)}
    : Module.createRequire(filename)(id);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return {...loaded.exports, observers, requests};
}

test('diagnostics validate owned plain options, exact capacity and authentic request handle', async () => {
  const {Client, RequestDiagnostics, observers, requests} = facade();
  let invoked = 0;
  for (const options of [null, true, [], new Proxy({}, {}), {unknown: 1},
    {get maximumEvents() {invoked++; throw new Error('private');}}]) {
    assert.throws(() => new RequestDiagnostics(options), {code: 'InvalidArgument'});
  }
  for (const maximumEvents of [null, true, 0, 0n, -1, -1n, 1.5, NaN, Infinity,
    Number.MAX_SAFE_INTEGER + 1, 18446744073709551616n, 'private']) {
    assert.throws(() => new RequestDiagnostics({maximumEvents}), (error) => error.code === 'InvalidArgument' && !String(error).includes('private'));
  }
  assert.equal(invoked, 0); assert.equal(observers.length, 0);
  const trace = new RequestDiagnostics();
  assert.equal(observers[0].maximum, 128n); assert.equal(trace.snapshot(), null); assert.ok(Object.isFrozen(trace));
  const exact = new RequestDiagnostics({maximumEvents: 18446744073709551615n});
  assert.equal(observers[1].maximum, 18446744073709551615n);
  assert.throws(() => RequestDiagnostics.prototype.snapshot.call({}), {code: 'InvalidArgument'});
  const client = new Client({profile: 'exact', route: 'direct'});
  const options = {method: 'GET', protocol: 'http1', context: 'raw'};
  (await client.request('http://example.test/', options)).close();
  assert.equal(requests[0].length, 5);
  (await client.request('http://example.test/', {...options, diagnostics: trace})).close();
  assert.equal(requests[1][5], observers[0]); assert.equal(requests[1][0].diagnostics, undefined);
  await assert.rejects(client.request('http://example.test/', {...options, diagnostics: trace}), {code: 'DiagnosticsAlreadyUsed'});
  for (const diagnostics of [null, {}, Object.create(RequestDiagnostics.prototype), exact.snapshot()]) {
    await assert.rejects(client.request('http://example.test/', {...options, diagnostics}), {code: 'InvalidArgument'});
  }
  await client.close();
});

test('snapshot projection freezes records, preserves absences/exactness and redacts inspection', () => {
  const {RequestDiagnostics, observers} = facade();
  const trace = new RequestDiagnostics({maximumEvents: 4});
  const certificate = Buffer.from('private certificate'), alpn = Buffer.from('h2');
  observers[0].value = {outcome: 'response_head', sendElapsedNs: 18446744073709551616n,
    admittedAttempts: 2n, droppedEvents: 3n, events: [{id: 1n, hop: 0n, phase: 'connection_use',
      outcome: 'completed', startedNs: 0n, finishedNs: 1n, connection: {reused: false,
        endpointScope: 'tcp_socket', peerAddress: 'private endpoint', originTls: {state: 'established',
          info: {peerVerified: false, sessionResumed: false, alpn, peerCertificatesDer: [certificate]}},
        proxyTls: {state: 'not_used'}}}]};
  const snapshot = trace.snapshot(), event = snapshot.events[0], connection = event.connection;
  assert.equal(snapshot.sendElapsedNs, 18446744073709551616n);
  assert.equal(event.admission, null); assert.equal(event.protocol, null);
  assert.equal(connection.localAddress, null); assert.equal(connection.originTls.info.versionId, null);
  assert.equal(connection.proxyTls.info, null); assert.equal(connection.originTls.info.peerVerified, false);
  assert.deepEqual(connection.originTls.info.peerCertificatesDer, [certificate]);
  for (const value of [snapshot, snapshot.events, event, connection, connection.originTls,
    connection.originTls.info, connection.originTls.info.peerCertificatesDer]) assert.ok(Object.isFrozen(value));
  assert.throws(() => {event.outcome = 'pending';}, TypeError);
  assert.ok(!inspect(snapshot).includes('private')); assert.ok(!inspect(connection).includes('private'));
  assert.ok(!inspect(connection.originTls.info).includes('private'));
  assert.equal(connection.originTls.info.alpn, alpn); // Already owned by this native snapshot; no facade copy.
  observers[0].error = new Error('PHANTOM:UnsupportedDiagnosticsValue:core diagnostics value is unsupported');
  assert.throws(() => trace.snapshot(), {code: 'UnsupportedDiagnosticsValue'});
  observers[0].error = new Error('PHANTOM:DiagnosticsLimit:diagnostics snapshot exceeds 16 MiB');
  assert.throws(() => trace.snapshot(), {code: 'DiagnosticsLimit'});
});
