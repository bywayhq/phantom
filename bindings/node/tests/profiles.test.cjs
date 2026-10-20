'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const http = require('node:http');
const http2 = require('node:http2');
const { test } = require('node:test');
const { Client, PhantomError, Profile, profiles } = require('..');

const identifier = process.platform === 'win32'
  ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';
const options = {method: 'GET', protocol: 'http1', context: 'profile', timeoutMs: 5000,
  headers: [{name: 'User-Agent', value: Buffer.from('Phantom-Test Chrome/154.0.0.0')}]};
const encode = (document) => Buffer.from(JSON.stringify(document));
const code = (expected) => (error) => error instanceof PhantomError && error.code === expected;

function custom() {
  const document = Profile.fromCatalog(identifier, 'navigation').describe();
  // Preserve the existing required Host, client-hint and caller slots.
  for (const protocol of ['http1', 'http2', 'http3']) {
    const fields = document.profile.request_template[`${protocol}_fields`];
    if (fields) fields.unshift(
      {variant: 'Literal', name: protocol === 'http1' ? 'X-Custom-First' : 'x-custom-first', value: 'first'},
      {variant: 'Literal', name: protocol === 'http1' ? 'X-Custom-Last' : 'x-custom-last', value: 'last'},
    );
  }
  document.profile.http2.initial_settings.reverse();
  return document;
}

test('catalog profiles export editable documents without assigning evidence to imports', () => {
  for (const id of profiles()) {
    const exact = Profile.fromCatalog(id);
    const imported = Profile.importJson(exact.exportJson());
    assert.equal(exact.catalogId, id);
    assert.equal(imported.catalogId, null);
    assert.deepEqual(imported.describe(), exact.describe());
    assert.deepEqual(imported.contexts, ['raw']);
    assert(Object.isFrozen(exact));
  }
  const selected = Profile.fromCatalog(identifier, 'navigation');
  assert(selected.contexts.includes('navigation'));
  assert(selected.contexts.includes('profile'));
  const fresh = selected.describe();
  fresh.profile.tls.session_ticket_order = 'OldestFirst';
  assert.notDeepEqual(fresh, selected.describe());
  assert.throws(() => selected.contexts.push('fetch'), TypeError);
  assert.throws(() => new Profile(), code('InvalidProfile'));
  assert.throws(() => Profile.fromCatalog('unknown/exact/id'), code('UnknownProfile'));
  assert.throws(() => Profile.fromCatalog(identifier, 'raw'), code('InvalidContext'));
});

test('strict native profile input retains view bounds and redacts category/field errors', () => {
  const source = custom();
  const json = encode(source);
  const surrounding = Buffer.concat([Buffer.from('garbage'), json, Buffer.from('tail')]);
  const imported = Profile.importJson(surrounding.subarray(7, 7 + json.length));
  surrounding.fill(0);
  assert.deepEqual(imported.describe(), source);
  const exported = imported.exportJson();
  exported.fill(0);
  assert.deepEqual(imported.describe(), source);
  assert.deepEqual(Profile.importJson(imported.exportJson()).describe(), source);
  assert.deepEqual(imported.contexts, ['raw', 'profile']);

  source.profile.tls.session_ticket_order = 'secret-supplied-value';
  assert.throws(() => Profile.importJson(encode(source)), (error) => {
    assert(error instanceof PhantomError);
    assert.equal(error.code, 'ProfileImport');
    assert.equal(error.kind, 'UnsupportedSetting');
    assert.equal(error.field, 'tls.session_ticket_order');
    assert(!String(error).includes('secret-supplied-value'));
    return true;
  });
  assert.throws(() => Profile.importJson(Buffer.from('{"secret":"unterminated')), (error) =>
    code('ProfileImport')(error) && error.kind === 'MalformedJson' && error.field === 'document');
  assert.throws(() => Profile.importJson(Buffer.from('{"format":"ja3"}')), (error) =>
    code('ProfileImport')(error) && error.kind === 'LossyDescription');
  assert.throws(() => Profile.importJson(Buffer.alloc(16 * 1024 * 1024 + 1)), code('InputLimit'));
  assert.throws(() => Profile.importJson(new Uint8Array(new SharedArrayBuffer(8))), code('InvalidArgument'));
  assert.throws(() => Profile.importJson('{}'), code('InvalidArgument'));
  assert.throws(() => new Client({profile: Object.create(Profile.prototype), route: 'direct'}), code('InvalidProfile'));
});

test('editable descriptions preserve native u64 precision and reject lossy JavaScript values', () => {
  const document = custom();
  document.profile.dns_cache.ttl.seconds = 9007199254740993n;
  const imported = Profile.fromDescription(document);
  assert.equal(imported.describe().profile.dns_cache.ttl.seconds, 9007199254740993n);
  assert(imported.exportJson().includes(Buffer.from('9007199254740993')));
  assert.deepEqual(Profile.fromDescription(imported.describe()).describe(), document);
  assert.deepEqual(Profile.importJson(imported.exportJson()).describe(), document);
  for (const invalid of [undefined, NaN, Infinity, 9007199254740992, -1n, 18446744073709551616n, () => 'secret', new Date()]) {
    assert.throws(() => Profile.fromDescription({secret: invalid}), (error) =>
      code('ProfileImport')(error) && error.kind === 'InvalidValue' && error.field === 'document'
      && !String(error).includes('secret'));
  }
  let invoked = false;
  const getter = {get secret() { invoked = true; throw Error('secret'); }};
  const proxy = new Proxy({}, {ownKeys() { invoked = true; throw Error('secret'); }});
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  const cycle = {}; cycle.self = cycle;
  for (const invalid of [getter, proxy, revoked.proxy, cycle, {array: Array(1)}, {toJSON() { invoked = true; return {}; }}]) {
    assert.throws(() => Profile.fromDescription(invalid), code('ProfileImport'));
  }
  assert.equal(invoked, false);
  for (const invalid of [{value: 'a'.repeat(65537)}, {value: Array(65536).fill(0)}, Object.fromEntries(Array.from({length: 65}, (_, n) => [n, null]))]) {
    assert.throws(() => Profile.fromDescription(invalid), (error) => code('ProfileImport')(error) && error.kind === 'TooLarge');
  }
  const invalid = custom();
  invalid.profile.tls.session_ticket_order = 'secret';
  assert.throws(() => Profile.fromDescription(invalid), (error) =>
    code('ProfileImport')(error) && error.kind === 'UnsupportedSetting' && error.field === 'tls.session_ticket_order');
});

test('an imported profile drives ordered HTTP/1 fields while raw and catalog contexts stay explicit', {timeout: 30000}, async (t) => {
  const observed = [];
  const sockets = new Set();
  const server = http.createServer((request, response) => { observed.push(request.rawHeaders); response.end('ok'); });
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise((resolve) => server.close(resolve)); });
  const document = custom();
  const selected = Profile.importJson(encode(document));
  const client = new Client({profile: selected, route: 'direct'});
  t.after(() => client.close());
  document.profile.request_template.http1_fields[0].value = 'changed-after-import';
  const url = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await (await client.request(url, options)).bytes(2)).toString(), 'ok');
  const index = observed[0].indexOf('X-Custom-First');
  assert(index >= 0);
  assert.deepEqual(observed[0].slice(index, index + 4), ['X-Custom-First', 'first', 'X-Custom-Last', 'last']);
  assert.equal((await (await client.request(url, {...options, context: 'raw'})).bytes(2)).toString(), 'ok');
  assert(!observed[1].includes('X-Custom-First'));
  await assert.rejects(client.request(url, {...options, context: 'navigation'}), code('UnavailableContext'));
  assert.equal(observed.length, 2);

  const exact = new Client({profile: Profile.fromCatalog(identifier, 'navigation'), route: 'direct'});
  t.after(() => exact.close());
  assert.equal((await (await exact.request(url, {...options, context: 'navigation'})).bytes(2)).toString(), 'ok');
  const noTemplate = new Client({profile: Profile.importJson(Profile.fromCatalog(identifier).exportJson()), route: 'direct'});
  t.after(() => noTemplate.close());
  await assert.rejects(noTemplate.request(url, options), code('UnavailableContext'));
  assert.equal(observed.length, 3);
});

test('edited profile templates retain their HTTP/2 field order on a real client', {timeout: 30000}, async (t) => {
  const sessions = new Set();
  const server = http2.createServer();
  server.on('session', (session) => { sessions.add(session); session.on('error', () => {}); });
  let observed;
  server.on('stream', (stream, _headers, _flags, rawHeaders) => {
    observed = rawHeaders;
    stream.respond({':status': 200});
    stream.end('ok');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => { for (const session of sessions) session.destroy(); await new Promise((resolve) => server.close(resolve)); });
  const selected = Profile.importJson(encode(custom()));
  const client = new Client({profile: selected, route: 'direct'});
  t.after(() => client.close());
  const response = await client.request(`http://127.0.0.1:${server.address().port}`, {...options, protocol: 'http2'});
  assert.equal(response.protocol, 'http2');
  assert.equal((await response.bytes(2)).toString(), 'ok');
  const index = observed.indexOf('x-custom-first');
  assert(index >= 0);
  assert.deepEqual(observed.slice(index, index + 4), ['x-custom-first', 'first', 'x-custom-last', 'last']);
  assert.equal(sessions.size, 1);
});
