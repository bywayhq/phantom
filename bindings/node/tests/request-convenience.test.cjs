'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const http = require('node:http');
const { test } = require('node:test');

const { Client, Profile, AttemptBudget } = require('..');

const profile = process.platform === 'win32' ? 'chrome/154.0.8037.97/windows-11-26200/r1'
  : process.platform === 'darwin' ? 'chrome/154.0.8037.95/macos-15.5-arm64/r1'
  : 'chrome/154.0.8037.57/android-17-pixel7-emulator/r1';

async function peer(t) {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({method: request.method, url: request.url, headers: request.rawHeaders,
      body: Buffer.concat(chunks), port: request.socket.remotePort});
    if (request.url === '/redirect') response.writeHead(307, {location: '/final'}).end();
    else response.end('ok');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  return {url: `http://127.0.0.1:${server.address().port}`, requests};
}

test('request conveniences preserve real bytes, headers, query spelling and connection reuse', {timeout: 30000}, async (t) => {
  const {url, requests} = await peer(t);
  const value = Buffer.from('first');
  const client = new Client({profile, route: 'direct', protocol: 'http1', context: 'raw', baseUrl: url,
    headers: [{name: 'X-First', value}, {name: 'X-Replace', value: Buffer.from('old')}]});
  t.after(() => client.close());
  value.fill(0);

  const response = await client.post('/?raw=%20', {json: {word: 'café'}, query: [['tag', 'a b'], ['tag', '+']],
    headers: [{name: 'x-replace', value: Buffer.from('new')}, {name: 'x-replace', value: Buffer.from('last')}]});
  assert.equal(await response.text(2), 'ok');
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].url, '/?raw=%20&tag=a+b&tag=%2B');
  assert.equal(requests[0].body.toString(), '{"word":"café"}');
  const head = requests[0].headers;
  assert.equal(head[head.indexOf('X-First') + 1], 'first');
  assert.ok(head.indexOf('X-First') < head.indexOf('x-replace'));
  assert.equal(head[head.indexOf('x-replace') + 1], 'new');
  assert.equal(head[head.lastIndexOf('x-replace') + 1], 'last');
  assert.equal(head[head.indexOf('content-type') + 1], 'application/json');

  assert.equal(await (await client.put(new URL(url), {body: 'π'})).text(2), 'ok');
  assert.equal(requests[1].body.toString('hex'), 'cf80');
  assert.equal(await (await client.patch('/form', {form: [['x', 'one'], ['x', 'a b']]})).text(2), 'ok');
  assert.equal(requests[2].body.toString(), 'x=one&x=a+b');
  assert.equal(requests[0].port, requests[1].port);
  assert.equal(requests[1].port, requests[2].port);
});

test('encoded helpers retain redirect replay, exact shared budgets and content-type validation', {timeout: 30000}, async (t) => {
  const {url, requests} = await peer(t);
  const client = new Client({profile, route: 'direct', protocol: 'http1', context: 'raw',
    redirectPolicy: {mode: 'limited', maximumHops: 1}});
  t.after(() => client.close());
  const budget = new AttemptBudget(2);
  const response = await client.post(url + '/redirect', {json: {replay: true}, attemptBudget: budget});
  assert.equal(await response.text(2), 'ok');
  assert.equal(budget.remaining, 0);
  assert.deepEqual(requests.map(({method, body}) => [method, body.toString()]), [
    ['POST', '{"replay":true}'], ['POST', '{"replay":true}'],
  ]);
  await assert.rejects(client.get(url, {attemptBudget: budget}), {code: 'AttemptBudgetExhausted'});
  const unspent = new AttemptBudget(1);
  for (const headers of [
    [{name: 'content-type', value: Buffer.from('text/plain')}],
    [{name: 'content-type', value: Buffer.from('application/json')}, {name: 'Content-Type', value: Buffer.from('application/json')}],
  ]) {
    await assert.rejects(client.post(url, {json: {}, headers, attemptBudget: unspent}), {code: 'InvalidHeader'});
  }
  assert.equal(unspent.remaining, 1);
  assert.equal(requests.length, 2);
});

for (const template of ['chrome-154-windows', 'chrome-154-macos', 'chrome-154-android']) {
  test(`attached ${template} template supplies context and generated body fields in their slots`, {timeout: 30000}, async (t) => {
    const {url, requests} = await peer(t);
    const document = Profile.fromCatalog(profile, 'navigation').describe();
    // Templates are portable; the transport still belongs to the current host.
    document.profile.request_template = Profile.fromCatalog(template, 'navigation').describe().profile.request_template;
    const fields = document.profile.request_template.http1_fields;
    fields.unshift({variant: 'Literal', name: 'X-Before-Length', value: 'before'},
      {variant: 'Caller', name: 'Content-Length', required: false},
      {variant: 'Literal', name: 'X-After-Length', value: 'after'});
    const client = new Client({profile: Profile.fromDescription(document), route: 'direct', protocol: 'http1'});
    t.after(() => client.close());
    if (template === 'chrome-154-macos') {
      const budget = new AttemptBudget(1);
      await assert.rejects(client.post(url, {json: {x: 1}, attemptBudget: budget}), {code: 'RequestTemplate'});
      assert.equal(budget.remaining, 1);
      assert.equal(requests.length, 0);
    }
    const response = await client.post(url, {json: {x: 1}, headers: [{name: 'User-Agent', value: Buffer.from('template-fixture')}]});
    assert.equal(await response.text(2), 'ok');
    const head = requests[0].headers;
    const names = head.filter((_value, index) => index % 2 === 0).map((name) => name.toLowerCase());
    const index = names.indexOf('content-length');
    assert.ok(index > names.indexOf('x-before-length'));
    assert.ok(index < names.indexOf('x-after-length'));
    assert.equal(head[names.indexOf('user-agent') * 2 + 1], 'template-fixture');
    assert.equal(requests[0].body.toString(), '{"x":1}');
  });
}
