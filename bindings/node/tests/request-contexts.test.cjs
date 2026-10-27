'use strict';

const assert = require('node:assert/strict');
const { once } = require('node:events');
const http2 = require('node:http2');
const { test } = require('node:test');

const { AttemptBudget, Client, Profile } = require('..');

const selector = process.platform === 'win32' ? 'chrome-156-windows'
  : process.platform === 'darwin' ? 'chrome-156-macos' : 'chrome-156-linux';

test('concurrent resource contexts share one HTTP/2 session without changing the default', {timeout: 30000}, async (t) => {
  const sessions = new Set();
  const observed = new Map();
  const server = http2.createServer();
  server.on('session', (session) => {
    sessions.add(session);
    session.on('error', () => {});
  });
  server.on('stream', (stream, headers) => {
    observed.set(headers[':path'], headers);
    stream.respond({':status': 200});
    stream.end('ok');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const session of sessions) session.destroy();
    await new Promise((resolve) => server.close(resolve));
  });

  const profile = Profile.fromCatalog(selector);
  for (const context of ['navigation', 'script', 'stylesheet', 'image', 'font']) {
    assert(profile.contexts.includes(context));
  }
  const client = new Client({profile, route: 'direct', protocol: 'http2', context: 'navigation'});
  t.after(() => client.close());
  const url = `http://127.0.0.1:${server.address().port}`;
  const headers = [
    {name: 'referer', value: Buffer.from(url + '/page')},
    {name: 'origin', value: Buffer.from(url)},
  ];
  assert.equal(await (await client.get(url + '/default')).text(2), 'ok');

  const destinations = new Map([
    ['navigation', 'document'], ['script', 'script'], ['stylesheet', 'style'],
    ['image', 'image'], ['font', 'font'],
  ]);
  await Promise.all([...destinations].map(async ([context, destination]) => {
    const response = await client.get(url + '/' + context, {context, headers});
    assert.equal(await response.text(2), 'ok');
    assert.equal(observed.get('/' + context)['sec-fetch-dest'], destination);
    assert.equal(observed.get('/' + context).referer, url + '/page');
    assert.equal(observed.get('/' + context).origin, url);
  }));
  assert.equal(await (await client.get(url + '/default-again')).text(2), 'ok');
  assert.equal(observed.get('/default')['sec-fetch-dest'], 'document');
  assert.equal(observed.get('/default-again')['sec-fetch-dest'], 'document');
  assert.equal(await (await client.get(url + '/raw', {context: 'raw'})).text(2), 'ok');
  assert.equal(observed.get('/raw')['sec-fetch-dest'], undefined);
  assert.equal(sessions.size, 1);

  const budget = new AttemptBudget(1);
  await assert.rejects(client.get(url + '/unavailable', {context: 'fetchUpload', attemptBudget: budget}),
    {code: 'UnavailableContext'});
  assert.equal(budget.remaining, 1);
  assert.equal(observed.has('/unavailable'), false);
});
