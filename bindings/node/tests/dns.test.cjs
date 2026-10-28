'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const http2 = require('node:http2');
const path = require('node:path');
const tls = require('node:tls');
const {test} = require('node:test');
const {AttemptBudget, Client, PhantomError} = require('..');

const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name));
const material = {key: fixture('key.pem'), cert: fixture('certificate.pem')};
const root = fixture('certificate.der');
const profile = 'chrome-154-windows';
const request = {method: 'GET', protocol: 'http1', context: 'raw', timeoutMs: 5000};
const code = (name) => (error) => error instanceof PhantomError && error.code === name;

function answer(query, ttl) {
  assert.equal(query.readUInt16BE(2) & 0x8000, 0);
  assert.equal(query.readUInt16BE(4), 1);
  let position = 12;
  const labels = [];
  while (query[position]) {
    const length = query[position++];
    assert(length <= 63);
    labels.push(query.subarray(position, position + length).toString('ascii'));
    position += length;
  }
  position++;
  const type = query.readUInt16BE(position);
  assert.equal(query.readUInt16BE(position + 2), 1);
  assert([1, 28].includes(type));
  const name = labels.join('.');
  const question = query.subarray(12, position + 4);
  const head = Buffer.alloc(12);
  head.writeUInt16BE(query.readUInt16BE(0));
  head.writeUInt16BE(name === 'missing.invalid' ? 0x8183 : 0x8180, 2);
  head.writeUInt16BE(1, 4);
  if (name === 'missing.invalid') return {name, type, body: Buffer.concat([head, question])};

  head.writeUInt16BE(1, 6);
  const data = type === 1 ? Buffer.from([127, 0, 0, 1]) : Buffer.from('00000000000000000000000000000001', 'hex');
  const record = Buffer.alloc(12);
  record.writeUInt16BE(0xc00c);
  record.writeUInt16BE(type, 2);
  record.writeUInt16BE(1, 4);
  record.writeUInt32BE(ttl, 6);
  record.writeUInt16BE(data.length, 10);
  return {name, type, body: Buffer.concat([head, question, record, data])};
}

async function origin(t) {
  const requests = [], sockets = new Set();
  let finishLive;
  const server = http.createServer((message, response) => {
    requests.push({url: message.url, host: message.headers.host});
    if (message.url === '/live') {
      response.writeHead(200, {'content-length': '2'});
      response.write('a');
      finishLive = () => response.end('b');
    } else response.end('ok');
  });
  server.on('connection', (socket) => {sockets.add(socket); socket.on('close', () => sockets.delete(socket));});
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  return {port: server.address().port, requests, finish: () => finishLive()};
}

async function resolver(t, kind) {
  const sockets = new Set(), sessions = new Set(), failures = [], queries = [];
  let held, reset;
  const peer = {ttl: 60, status: 200, malformed: false, oversized: false,
    held: new Promise((resolve) => {held = resolve;}),
    reset: new Promise((resolve) => {reset = resolve;}), connections: 0, queries};
  const record = (query, method, headers = {}) => {
    const response = answer(query, peer.ttl);
    queries.push({...response, id: query.readUInt16BE(0), bytes: query.length, method, headers});
    if (response.name === 'held.invalid') {held(); return undefined;}
    return peer.malformed ? Buffer.alloc(1) : peer.oversized ? Buffer.alloc(65536) : response.body;
  };
  let server;
  if (kind === 'https') {
    server = http2.createSecureServer(material);
    server.on('session', (session) => {sessions.add(session); session.on('error', () => {});});
    server.on('stream', (stream, headers) => {
      const chunks = [];
      stream.on('error', () => {});
      stream.on('close', () => {if (stream.rstCode === http2.constants.NGHTTP2_CANCEL) reset();});
      stream.on('data', (chunk) => chunks.push(chunk));
      stream.on('end', () => {
        try {
          const method = headers[':method'];
          const body = method === 'GET'
            ? Buffer.from(new URL(headers[':path'], 'https://dns.invalid').searchParams.get('dns'), 'base64url')
            : Buffer.concat(chunks);
          assert(['GET', 'POST'].includes(method));
          if (method === 'POST') assert.equal(headers['content-type'], 'application/dns-message');
          const response = record(body, method, headers);
          if (response === undefined) return;
          stream.respond({':status': peer.status, 'content-type': 'application/dns-message', location: '/redirected'});
          stream.end(response);
        } catch (error) {failures.push(error); stream.destroy();}
      });
    });
  } else {
    server = tls.createServer({...material, ALPNProtocols: ['dot']}, (socket) => {
      assert.equal(socket.alpnProtocol, 'dot');
      let pending = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        try {
          while (pending.length >= 2 && pending.length >= pending.readUInt16BE(0) + 2) {
            const length = pending.readUInt16BE(0);
            const response = record(pending.subarray(2, length + 2));
            pending = pending.subarray(length + 2);
            if (response === undefined) continue;
            const prefix = Buffer.alloc(2);
            prefix.writeUInt16BE(response.length);
            socket.write(Buffer.concat([prefix, response]));
          }
        } catch (error) {failures.push(error); socket.destroy();}
      });
    });
  }
  server.on('tlsClientError', () => {});
  server.on('connection', (socket) => {
    peer.connections++;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', (error) => {
      if (!['ECONNRESET', 'ECONNABORTED', 'EPIPE'].includes(error.code)) failures.push(error);
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const session of sessions) session.destroy();
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    assert.deepEqual(failures, []);
  });
  peer.options = (changes = {}) => ({kind, timeoutMs: 2000, maxConcurrent: 8, families: 'ipv4', roots: [root],
    ...(kind === 'https' ? {endpoint: `https://localhost:${server.address().port}/query`, bootstrap: ['127.0.0.1']}
      : {serverName: 'localhost', bootstrap: [`127.0.0.1:${server.address().port}`]}), ...changes});
  return peer;
}

function client(t, dns, extra = {}) {
  const owner = new Client({profile, route: 'direct', network: {dns, dnsCache: false}, ...extra});
  t.after(() => owner.destroy());
  return owner;
}
async function send(owner, target, host = 'answer.invalid', extra = {}) {
  const response = await owner.request(`http://${host}:${target.port}/`, {...request, ...extra});
  try {assert.equal(await response.text(2), 'ok');} finally {response.close();}
  await owner.refreshConnections();
}

test('DoH GET/POST and DoT retain DNS transport, authority, roots and origin attempt budgets', {timeout: 30000}, async (t) => {
  for (const [kind, method] of [['https', 'get'], ['https', 'post'], ['tls', undefined]]) {
    const target = await origin(t), dns = await resolver(t, kind), copiedRoot = Buffer.from(root);
    const owner = client(t, dns.options({...method && {method, queryId: 42}, roots: [copiedRoot]}));
    copiedRoot.fill(0);
    const budget = new AttemptBudget(2);
    await send(owner, target, 'answer.invalid', {attemptBudget: budget});
    await send(owner, target, 'answer.invalid', {attemptBudget: budget});
    assert.equal(budget.remaining, 0);
    assert.equal(dns.connections, 1);
    assert.equal(dns.queries.length, 2);
    assert(target.requests.every((entry) => entry.host === `answer.invalid:${target.port}`));
    if (method !== undefined) assert(dns.queries.every((entry) => entry.method === method.toUpperCase() && entry.id === 42));
    await owner.destroy();
  }
});

test('DoH wire presets retain implicit padding and accept explicit overrides', {timeout: 30000}, async (t) => {
  for (const paddingBlock of [undefined, null, 64]) {
    const target = await origin(t), dns = await resolver(t, 'https');
    const owner = client(t, dns.options({wire: 'chromium154', paddingBlock, queryId: 27}));
    await send(owner, target);
    assert.equal(dns.queries[0].id, 27);
    assert.equal(dns.queries[0].headers['user-agent'], 'Chrome');
    if (paddingBlock === null) assert(dns.queries[0].bytes < 64);
    else assert.equal(dns.queries[0].bytes % (paddingBlock ?? 128), 0);
    await owner.destroy();
  }
});

test('DNS verification and malformed responses cannot send an origin request or follow redirects', {timeout: 30000}, async (t) => {
  for (const kind of ['https', 'tls']) {
    const target = await origin(t), dns = await resolver(t, kind);
    for (const changes of [{roots: []}, kind === 'https'
      ? {endpoint: dns.options().endpoint.replace('localhost', 'wrong.invalid')} : {serverName: 'wrong.invalid'}]) {
      const owner = client(t, dns.options(changes));
      await assert.rejects(send(owner, target, 'localhost'), code('Connect'));
      assert.equal(dns.queries.length, 0);
      await owner.destroy();
    }
    const owner = client(t, dns.options());
    dns.malformed = true;
    await assert.rejects(send(owner, target), code('Connect'));
    dns.malformed = false;
    if (kind === 'https') {
      dns.oversized = true;
      await assert.rejects(send(owner, target), code('Connect'));
      dns.oversized = false;
      dns.status = 302;
      const before = dns.queries.length;
      await assert.rejects(send(owner, target), code('Connect'));
      assert.equal(dns.queries.length, before + 1);
    }
    assert.deepEqual(target.requests, []);
    await owner.destroy();
  }
});

test('DNS cache sharing, hard zero TTL, host overrides and proxy-owned target resolution remain explicit', {timeout: 30000}, async (t) => {
  for (const kind of ['https', 'tls']) {
    const target = await origin(t), dns = await resolver(t, kind);
    const owner = client(t, undefined, {network: {dns: dns.options(),
      hostOverrides: [{host: 'overridden.invalid', addresses: ['127.0.0.1']}]}});
    await send(owner, target); await send(owner, target);
    assert.equal(dns.queries.length, 1);
    const shared = owner.fork({dns: true}), independent = owner.fork();
    try {
      await send(shared, target);
      assert.equal(dns.queries.length, 1);
      await send(independent, target);
      assert.equal(dns.queries.length, 2);
      await send(owner, target, 'overridden.invalid');
      assert.equal(dns.queries.length, 2);
      dns.ttl = 0; owner.clearDnsCache();
      await send(owner, target); await send(owner, target);
      assert.equal(dns.queries.length, 4);
      await assert.rejects(send(owner, target, 'missing.invalid'), code('Connect'));
    } finally {await shared.destroy(); await independent.destroy();}
    await owner.destroy();
    const proxy = client(t, dns.options(), {route: 'proxy', proxy: `http://proxy.invalid:${target.port}`});
    const response = await proxy.request('http://target.invalid/through-proxy', request);
    assert.equal(await response.text(2), 'ok');
    assert.equal(dns.queries.at(-1).name, 'proxy.invalid');
    assert.equal(target.requests.at(-1).host, 'target.invalid');
    assert.equal(target.requests.at(-1).url, 'http://target.invalid/through-proxy');
    await proxy.destroy();
  }
});

test('uncached DNS cancellation releases admission without disrupting a live response or resolver reuse', {timeout: 30000}, async (t) => {
  for (const kind of ['https', 'tls']) {
    const target = await origin(t), dns = await resolver(t, kind);
    const owner = client(t, dns.options({maxConcurrent: 1}));
    const controller = new AbortController();
    const opening = owner.request(`http://held.invalid:${target.port}/`, {...request, signal: controller.signal});
    const cancelled = assert.rejects(opening, code('Cancelled'));
    await dns.held;
    await assert.rejects(send(owner, target), code('Connect'));
    controller.abort(); await cancelled;
    if (kind === 'https') await dns.reset;
    const live = await owner.request(`http://answer.invalid:${target.port}/live`, request);
    assert.equal((await live.read(1)).toString(), 'a');
    await send(owner, target);
    target.finish();
    assert.equal(await live.text(1), 'b');
    assert.equal(dns.connections, 1);
    await owner.destroy();
  }
});

test('DNS lookup deadlines and client drain timeout preserve typed failure and explicit abort', {timeout: 30000}, async (t) => {
  for (const kind of ['https', 'tls']) {
    const target = await origin(t), bounded = await resolver(t, kind);
    const timed = client(t, bounded.options({timeoutMs: 1000}));
    const pending = timed.request(`http://held.invalid:${target.port}/`, request);
    const expired = assert.rejects(pending, code('Connect'));
    await Promise.race([bounded.held, pending]);
    await expired;
    await timed.destroy();
    const dns = await resolver(t, kind), owner = client(t, dns.options());
    let settled = false;
    const opening = owner.request(`http://held.invalid:${target.port}/`, request).finally(() => {settled = true;});
    const aborted = assert.rejects(opening, (error) => error instanceof PhantomError && ['Cancelled', 'ClientClosed'].includes(error.code));
    await dns.held;
    await assert.rejects(owner.close({timeoutMs: 0}), code('Timeout'));
    assert.equal(settled, false);
    await owner.destroy(); await aborted;
    assert.deepEqual(target.requests, []);
  }
});
