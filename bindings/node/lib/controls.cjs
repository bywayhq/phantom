'use strict';

const { inspect } = require('node:util');

const { PhantomError, translated } = require('./errors.cjs');
const native = require('./native.cjs');
const { policyFields, positiveCount } = require('./validation.cjs');

const budgetHandles = new WeakMap();
const transferHandles = new WeakMap();
const diagnosticsHandles = new WeakMap();

class AttemptBudget {
  constructor(maximum) {
    if (typeof maximum === 'number' && Number.isSafeInteger(maximum) && maximum >= 0) maximum = BigInt(maximum);
    if (typeof maximum !== 'bigint' || maximum < 0n) {
      throw new PhantomError('InvalidArgument', 'maximum must be a nonnegative safe integer or bigint');
    }
    try { budgetHandles.set(this, new native.NativeAttemptBudget(maximum)); }
    catch (error) { throw translated(error); }
  }
  get remaining() { return budgetHandles.get(this).remaining; }
  tryAdmit() {
    try { budgetHandles.get(this).tryAdmit(); }
    catch (error) { throw translated(error); }
  }
}

function diagnosticRecord(value, label) {
  return Object.freeze(Object.defineProperty(value, inspect.custom, {
    value: () => `${label} { details omitted }`,
  }));
}

function diagnosticTls(value) {
  const info = value.info;
  return diagnosticRecord({state: value.state, info: info == null ? null : diagnosticRecord({
    ...info, versionId: info.versionId ?? null, cipherSuiteId: info.cipherSuiteId ?? null,
    alpn: info.alpn ?? null,
    peerCertificatesDer: info.peerCertificatesDer == null ? null : Object.freeze(info.peerCertificatesDer),
  }, 'TLSConnectionInfo')}, 'TLSConnectionState');
}

class RequestDiagnostics {
  constructor(options = {}) {
    const copy = policyFields(options, ['maximumEvents']);
    const maximum = copy.maximumEvents === undefined ? 128n : positiveCount(copy.maximumEvents);
    try { diagnosticsHandles.set(this, new native.NativeRequestDiagnostics(maximum)); }
    catch (error) { throw translated(error); }
    Object.freeze(this);
  }
  snapshot() {
    const handle = diagnosticsHandles.get(this);
    if (handle === undefined) throw new PhantomError('InvalidArgument', 'receiver must be RequestDiagnostics');
    let snapshot;
    try { snapshot = handle.snapshot(); } catch (error) { throw translated(error); }
    if (snapshot == null) return null;
    return diagnosticRecord({...snapshot, sendElapsedNs: snapshot.sendElapsedNs ?? null,
      events: Object.freeze(snapshot.events.map((event) => diagnosticRecord({...event,
        admission: event.admission ?? null, protocol: event.protocol ?? null,
        finishedNs: event.finishedNs ?? null,
        connection: event.connection == null ? null : diagnosticRecord({...event.connection,
          localAddress: event.connection.localAddress ?? null, peerAddress: event.connection.peerAddress ?? null,
          originTls: diagnosticTls(event.connection.originTls), proxyTls: diagnosticTls(event.connection.proxyTls),
        }, 'RequestConnection'),
      }, 'RequestTiming'))),
    }, 'RequestTimeline');
  }
}

class TransferControl {
  constructor(limits = {}) {
    const copy = policyFields(limits, ['uploadBytes', 'downloadBytes', 'uploadBytesPerSecond', 'downloadBytesPerSecond']);
    const options = {};
    for (const [name, value] of Object.entries(copy)) {
      if (value === undefined) continue;
      const minimum = name.endsWith('PerSecond') ? 1n : 0n;
      const exact = typeof value === 'number' && Number.isSafeInteger(value) ? BigInt(value) : value;
      if (typeof exact !== 'bigint' || exact < minimum || exact > 0xffffffffffffffffn) {
        throw new PhantomError('InvalidArgument', `${name} must be an exact u64 ${minimum === 1n ? 'positive rate' : 'byte cap'}`);
      }
      options[name] = exact;
    }
    try { transferHandles.set(this, new native.NativeTransferControl(options)); }
    catch (error) { throw translated(error); }
    Object.freeze(this);
  }
  snapshot() {
    const handle = transferHandles.get(this);
    if (handle === undefined) throw new PhantomError('InvalidArgument', 'receiver must be a TransferControl');
    try { return Object.freeze(handle.snapshot()); }
    catch (error) { throw translated(error); }
  }
}

function attemptBudgetHandle(value) { return budgetHandles.get(value); }

function transferControlHandle(value) { return transferHandles.get(value); }

function requestDiagnosticsHandle(value) { return diagnosticsHandles.get(value); }

module.exports = { AttemptBudget, RequestDiagnostics, TransferControl, attemptBudgetHandle, transferControlHandle, requestDiagnosticsHandle };
