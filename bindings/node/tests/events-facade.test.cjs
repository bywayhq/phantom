'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');

const {loadFacade} = require('./load-facade.cjs');

function response() {
  const {Response, EventStream} = loadFacade(path.resolve(__dirname, '../index.cjs'), {NativeEnvironment: class {}});
  let closed = 0, finished = 0;
  const calls = [];
  const events = {lastEventId: '', retryMs: null, async read() {return null;}, close() {closed++;}};
  const native = {
    status: 200, protocol: 'http2', url: 'https://peer/events', redirects: 0,
    headers: [], decodedContentCodings: [], redirectHistory: null,
    events(...limits) {calls.push(limits); return events;},
    async read() {return Buffer.from('body');}, async collect() {return Buffer.from('body');},
    close() {closed++;},
  };
  return {response: new Response(native, () => {finished++;}, {}), native, events, EventStream, calls,
    counts: () => ({closed, finished})};
}

test('SSE limits default exactly and invalid options leave the response untouched', () => {
  for (const options of [null, {maximumLineBytes: null}, {maximumEventBytes: -1}, {maximumLineBytes: 1n},
    {maximumEventBytes: 0x100000000}, {other: 1}, new Proxy({}, {}),
    Object.defineProperty({}, 'maximumLineBytes', {get() {throw Error('accessed');}})]) {
    const item = response();
    assert.throws(() => item.response.events(options), {code: 'InvalidArgument'});
    assert.deepEqual(item.calls, []); assert.deepEqual(item.counts(), {closed: 0, finished: 0});
    item.response.close();
  }
  const defaults = response(); defaults.response.events().close();
  assert.deepEqual(defaults.calls, [[65536, 1048576]]);
  const zero = response(); zero.response.events({maximumLineBytes: 0, maximumEventBytes: 0}).close();
  assert.deepEqual(zero.calls, [[0, 0]]);
});

test('SSE conversion exclusively transfers an unread body without cancelling it', async () => {
  const item = response(); const stream = item.response.events();
  assert(stream instanceof item.EventStream);
  assert.throws(() => item.response.events(), {code: 'BodyUsed'});
  await assert.rejects(item.response.read(), {code: 'BodyUsed'});
  await assert.rejects(item.response.bytes(10), {code: 'BodyUsed'});
  assert.deepEqual(item.counts(), {closed: 0, finished: 0});
  stream.close(); stream.close();
  assert.deepEqual(item.counts(), {closed: 1, finished: 1});

  const failed = response();
  failed.native.events = () => {throw Error('PHANTOM_SSE:UnexpectedStatus:SSE requires status 200');};
  assert.throws(() => failed.response.events(), {code: 'Sse', kind: 'UnexpectedStatus'});
  assert.equal((await failed.response.bytes(10)).toString(), 'body');
  assert.equal(failed.counts().closed, 0);
});

test('pending and partially consumed raw reads prevent conversion without disturbing their owner', async () => {
  const item = response(); let release;
  item.native.read = () => new Promise((resolve) => {release = resolve;});
  const reading = item.response.read();
  assert.throws(() => item.response.events(), {code: 'ConcurrentRead'});
  await assert.rejects(item.response.bytes(10), {code: 'ConcurrentRead'});
  assert.equal(item.counts().closed, 0);
  release(Buffer.from('part')); assert.equal((await reading).toString(), 'part');
  assert.throws(() => item.response.events(), {code: 'BodyUsed'});
  assert.equal(item.counts().closed, 0); item.response.close();
});

test('SSE events retain exact retry values and iterator cleanup without prefetching', async () => {
  const item = response(); let reads = 0;
  const expected = [{data: 'one', event: 'message', id: 'first', retryMs: 0n},
    {data: 'two', event: 'update', id: '', retryMs: 18446744073709551615n}];
  item.events.read = async () => {
    const event = expected[reads++] ?? null;
    if (event) {item.events.lastEventId = event.id; item.events.retryMs = event.retryMs;}
    return event;
  };
  const stream = item.response.events();
  assert.equal(reads, 0); assert.equal(stream.retryMs, null);
  const first = await stream.read(); assert.deepEqual(first, expected[0]); assert(Object.isFrozen(first));
  assert.equal(stream.lastEventId, 'first'); assert.equal(stream.retryMs, 0n);
  const rest = []; for await (const event of stream) rest.push(event);
  assert.deepEqual(rest, expected.slice(1)); assert.equal(stream.lastEventId, '');
  assert.equal(stream.retryMs, 18446744073709551615n);
  assert.equal(await stream.read(), null); assert.equal(reads, 3);
  assert.deepEqual(item.counts(), {closed: 0, finished: 1});

  const stopped = response(); stopped.events.read = async () => expected[0];
  for await (const event of stopped.response.events()) {assert.equal(event.data, 'one'); break;}
  assert.deepEqual(stopped.counts(), {closed: 1, finished: 1});
});

test('duplicate SSE reads preserve the first read and close wakes it with a typed cancellation', async () => {
  const item = response(); let reject;
  item.events.read = () => new Promise((_resolve, rejected) => {reject = rejected;});
  item.events.close = () => {reject(Error('PHANTOM:Cancelled:request was cancelled'));};
  const stream = item.response.events(); const reading = stream.read();
  const cancelled = assert.rejects(reading, {code: 'Cancelled'});
  await assert.rejects(stream.read(), {code: 'ConcurrentRead'});
  assert.equal(item.counts().finished, 0);
  stream.close(); await cancelled;
  assert.equal(item.counts().finished, 1); assert.equal(await stream.read(), null);
});

test('SSE decoder errors preserve kind and ordinary request failures preserve timeout details', async () => {
  const item = response(); item.events.read = async () => {throw Error('PHANTOM_SSE:LineTooLong:SSE line exceeds limit');};
  await assert.rejects(item.response.events().read(), {code: 'Sse', kind: 'LineTooLong'});
  assert.deepEqual(item.counts(), {closed: 1, finished: 1});
  const timeout = response();
  timeout.events.read = async () => {throw Error('PHANTOM_REQUEST:Timeout:http2:total:request deadline expired');};
  await assert.rejects(timeout.response.events().read(), {code: 'Timeout', protocol: 'http2', timeoutPhase: 'total'});
});
