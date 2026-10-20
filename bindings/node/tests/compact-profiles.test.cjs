'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const http = require('node:http');
const {test} = require('node:test');
const {Client, PhantomError, Profile} = require('..');

// Retained Chrome154 Windows fields, normalized for GREASE; independent of
// the exporter: fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt.
const ciphers = '1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035';
const extensions = '001b,002d,000b,000a,0005,ca34,000d,0000,44cd,0012,0023,fe0d,0010,0033,0017,002b,ff01';
const signatures = '0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601';
const akamai = '6:131072;4:16777216;2:0;1:65536|16711681|0|m,p,a,s';
const catalog = 'chrome/154.0.8037.97/windows-11-26200/r1';
const baseProfile = () => Profile.fromCatalog(catalog, 'fetch');
const decimal = (input) => input.split(',').map((value) => parseInt(value, 16)).join('-');
const ja3 = (input = ciphers) => `771,${decimal(input)},${decimal(extensions)},${decimal('11ec,001d,0017,0018')},0`;
function ja4(input = ciphers, sorted = false) {
  const fields = extensions.split(',');
  return `t13d1517h2_${sorted ? input.split(',').sort().join(',') : input}_${sorted
    ? fields.filter((value) => value !== '0000' && value !== '0010').sort().join(',') : extensions}_${signatures}`;
}
const failure = (kind, field) => (error) => error instanceof PhantomError
  && error.code === 'ProfileImport' && error.kind === kind && error.field === field
  && !String(error).includes('private-secret');

test('raw TLS imports preserve order, explicit supplements and immutable reports', () => {
  const base = baseProfile();
  const before = base.exportJson();
  const changed = ciphers.split(','); [changed[0], changed[1]] = [changed[1], changed[0]];
  const expected = base.describe().profile.tls.cipher_suites;
  [expected[0], expected[1]] = [expected[1], expected[0]];
  for (const result of [Profile.importJa3(ja3(changed.join(',')), {base}),
    Profile.importJa4(ja4(changed.join(',')), {base, format: 'original'})]) {
    assert.equal(result.profile.catalogId, null);
    assert.deepEqual(result.profile.describe().profile.tls.cipher_suites, expected);
    assert.equal(result.profile.describe().profile.tls.extension_order.kind, 'Fixed');
    assert.deepEqual(result.profile.contexts, ['raw', 'profile']);
    assert(result.observedFields.includes('tls.extension_order'));
    assert(result.supplementedFields.includes('tls.ech'));
    for (const value of [result, result.profile, result.observedFields, result.supplementedFields]) assert(Object.isFrozen(value));
    assert.throws(() => result.observedFields.push('invented'), TypeError);
    const sorted = Profile.importJa4(ja4(ciphers, true), {base: result.profile, format: 'sorted'});
    assert.deepEqual(sorted.profile.describe().profile.tls, result.profile.describe().profile.tls);
    assert(!sorted.observedFields.includes('tls.extension_order'));
    assert(sorted.supplementedFields.includes('tls.extension_order'));
    assert.notEqual(sorted.observedFields, result.observedFields);
    assert.deepEqual(Profile.importJson(sorted.profile.exportJson()).describe(), sorted.profile.describe());
  }
  assert.deepEqual(base.exportJson(), before);
});

test('Akamai import retains base templates and client ownership after source references disappear', async (t) => {
  const identifier = process.platform === 'win32' ? catalog : process.platform === 'darwin'
    ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1' : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
  let base = Profile.fromCatalog(identifier, 'fetch');
  let result = Profile.importAkamai(akamai, {base});
  const settings = result.profile.describe().profile;
  assert.deepEqual(settings.http2.initial_settings.map((entry) => entry.kind),
    ['MaxHeaderListSize', 'InitialWindowSize', 'EnablePush', 'HeaderTableSize']);
  assert.deepEqual(settings.http2.pseudo_header_order, ['Method', 'Path', 'Authority', 'Scheme']);
  assert.deepEqual(settings.request_template, base.describe().profile.request_template);
  assert(result.supplementedFields.includes('tls'));
  const client = new Client({profile: result.profile, route: 'direct'});
  t.after(() => client.close());
  base = null; result = null;
  if (global.gc) global.gc();
  const sockets = new Set();
  const server = http.createServer((_request, response) => response.end('ok'));
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); });
  const url = `http://127.0.0.1:${server.address().port}`;
  const options = {method: 'GET', protocol: 'http1', context: 'profile', timeoutMs: 5000,
    headers: [{name: 'User-Agent', value: Buffer.from('Phantom-Test Chrome/154.0.0.0')}]};
  const response = await client.request(url, options);
  try { assert.equal(await response.text(2), 'ok'); } finally { response.close(); }
  await assert.rejects(client.request(url, {...options, context: 'fetch'}), (error) => error.code === 'UnavailableContext');
});

test('QUIC import copies actual Uint8Array view offsets and keeps wire widths', () => {
  // Supported subsequence of retained quic-client-hello-1.txt extension57.
  const payload = Buffer.from('08024064070480600000040480f0000009024067060480600000010480007530200480010000030245c00504806000000f00', 'hex');
  const backing = new Uint8Array(payload.length + 9); backing.set(payload, 4);
  const view = backing.subarray(4, 4 + payload.length);
  const result = Profile.importQuicTransport(view, {base: baseProfile()});
  backing.fill(255);
  const quic = result.profile.describe().profile.http3.quic_transport;
  assert.equal(quic.parameter_order, 'Fixed');
  assert.equal(quic.initial_max_data, 15728640);
  assert.equal(quic.wire_parameters[0].kind.kind, 'InitialMaxStreamsBidi');
  assert.equal(quic.wire_parameters[0].kind.value_width, 'Two');
  assert.equal(quic.wire_parameters[0].length_width, 'One');
  assert(result.observedFields.includes('http3.quic_transport.initial_max_data'));
  assert(result.supplementedFields.includes('http3.tls'));
  assert.equal(result.profile.catalogId, null);
});

test('compact imports reject lossy descriptions and malformed inputs with redacted paths', () => {
  const base = baseProfile();
  for (const [call, kind, field] of [
    [() => Profile.importJa3('a'.repeat(32), {base}), 'LossyDescription', 'ja3'],
    [() => Profile.importAkamai('b'.repeat(64), {base}), 'LossyDescription', 'akamai'],
    [() => Profile.importJa4('t13d1516h2_8daaf6152771_b186095e22b6', {base, format: 'original'}), 'LossyDescription', 'ja4'],
    [() => Profile.importJa3('private-secret', {base}), 'InvalidValue', 'ja3.version'],
    [() => Profile.importClientHello(Buffer.from('private-secret'), {base}), 'MalformedDescription', 'client_hello'],
    [() => Profile.importClientHello(Buffer.alloc(65537), {base}), 'TooLarge', 'client_hello'],
    [() => Profile.importQuicTransport(Buffer.from([1]), {base}), 'MalformedDescription', 'http3.quic_transport'],
    [() => Profile.importJa3('x'.repeat(32769), {base}), 'TooLarge', 'ja3'],
    ...[undefined, 'guess', null, 0].map((format) => [() => Profile.importJa4('private-secret', {base, format}), 'InvalidValue', 'ja4.format']),
  ]) assert.throws(call, failure(kind, field));
});

test('imports require real base owners, strict input types and ordinary backing storage', () => {
  const base = baseProfile();
  for (const options of [undefined, null, {}, {base: catalog}, {base: Object.create(Profile.prototype)}, {base, extra: true}]) {
    assert.throws(() => Profile.importJa3(ja3(), options), (error) => error instanceof PhantomError);
  }
  assert.throws(() => Profile.importJa3(Buffer.from(ja3()), {base}), (error) => error.code === 'InvalidArgument');
  assert.throws(() => Profile.importClientHello('private-secret', {base}), (error) => error.code === 'InvalidArgument');
  for (const method of ['importClientHello', 'importQuicTransport']) {
    assert.throws(() => Profile[method](new Uint8Array(new SharedArrayBuffer(8)), {base}), (error) => error.code === 'InvalidArgument');
    const detached = new Uint8Array(8); structuredClone(detached, {transfer: [detached.buffer]});
    assert.throws(() => Profile[method](detached, {base}), (error) => error.code === 'InvalidArgument');
  }
  let invoked = false;
  assert.throws(() => Profile.importJa3(ja3(), {get base() { invoked = true; return base; }}));
  assert.equal(invoked, false);
});
