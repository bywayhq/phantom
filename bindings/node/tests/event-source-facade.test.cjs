'use strict';

const assert = require('node:assert/strict');
const { getEventListeners } = require('node:events');
const path = require('node:path');
const { test } = require('node:test');
const { inspect } = require('node:util');

const { loadFacade } = require('./load-facade.cjs');

function facade() {
  const calls = [];
  const sources = [];
  let opening;
  class Source {
    closed = false;
    lastEventId = '';
    retryMs = 3000n;
    reconnects = 0;
    reads = 0;
    next = async () => null;
    constructor() { sources.push(this); }
    read() { this.reads++; return this.next(); }
    close() { this.closed = true; this.cancel?.(); }
  }
  const owner = {
    async close() {},
    async eventSource(options, source) {
      calls.push(options);
      if (opening) return opening(source);
      return {status: 200, protocol: options.protocol, url: options.url,
        headers: [{name: 'content-type', value: Buffer.from('text/event-stream'), sensitive: false}]};
    },
  };
  const native = {NativeEventSource: Source, NativeEnvironment: class {client() {return owner;}}};
  return {...loadFacade(path.resolve(__dirname, '../index.cjs'), native), calls, sources,
    setOpening(value) { opening = value; }};
}

const field = (name, value) => ({name, value: Buffer.from(value)});

test('EventSource merges client headers and explicit ordered ID slots without dropping defaults', async () => {
  const {Client, calls, sources} = facade();
  const client = new Client({profile: 'exact', route: 'direct', context: 'navigation', headers: [
    field('Authorization', 'secret'), field('Accept', 'custom'), field('X-Default', 'kept'),
  ]});
  const source = await client.eventSource('https://example.test/stream', {protocol: 'http1'});
  assert.deepEqual(calls[0].headers.map((header) => [header.kind, header.name, header.value?.toString()]), [
    ['field', 'Cache-Control', 'no-cache'], ['field', 'Authorization', 'secret'],
    ['field', 'Accept', 'custom'], ['field', 'X-Default', 'kept'],
  ]);
  assert.equal(calls[0].maximumLineBytes, 65536);
  assert.equal(calls[0].maximumEventBytes, 1048576);
  assert.equal(calls[0].initialRetryMs, 3000);
  assert.equal(calls[0].maximumReconnects, 3);
  assert.equal(calls[0].timeouts, undefined);
  assert.equal(calls[0].route, undefined);
  assert.equal(sources[0].reads, 0);
  source.close();

  const selected = await client.eventSource(new URL('https://example.test/stream'), {
    protocol: 'http2', headers: [field('authorization', 'replacement'), {lastEventId: 'last-event-id'}, field('x-tail', 'end')],
    maximumReconnects: 0, initialRetryMs: 0, minimumRetryMs: 1.25, idleTimeoutMs: 0,
    limits: {maximumLineBytes: 0, maximumEventBytes: 0},
    timeouts: {connectMs: 25, totalMs: null}, route: {route: 'direct'},
  });
  assert.deepEqual(calls[1].headers.map((header) => [header.kind, header.name]), [
    ['field', 'Accept'], ['field', 'X-Default'], ['field', 'authorization'], ['lastEventId', 'last-event-id'], ['field', 'x-tail'],
  ]);
  assert.equal(calls[1].headers[3].value, undefined);
  assert.equal(calls[1].headers[3].sensitive, undefined);
  assert.equal(calls[1].minimumRetryMs, 1.25);
  assert.equal(calls[1].maximumReconnects, 0);
  assert.equal(calls[1].maximumLineBytes, 0);
  assert.deepEqual(calls[1].timeouts, {connect: {disabled: false, milliseconds: 25}, total: {disabled: true, milliseconds: 0}});
  assert.deepEqual({...calls[1].route}, {route: 'direct'});
  selected.close();
});

test('unsupported EventSource options and executable inputs fail before native admission', async () => {
  const {Client, calls, sources} = facade();
  const client = new Client({profile: 'exact', route: 'direct', context: 'raw'});
  for (const options of [undefined, {}, {protocol: 'negotiated'}, {protocol: 'profile'},
    {protocol: 'http1', context: 'raw'}, {protocol: 'http1', attemptBudget: {}},
    {protocol: 'http1', body: Buffer.alloc(0)}, {protocol: 'http1', maximumReconnects: -1},
    {protocol: 'http1', initialRetryMs: Infinity}, {protocol: 'http1', minimumRetryMs: NaN},
    {protocol: 'http1', idleTimeoutMs: null}, {protocol: 'http1', timeouts: {readIdleMs: 1}},
    {protocol: 'http1', timeouts: {readIdleMs: null}}, {protocol: 'http1', timeouts: {readIdleMs: undefined}},
    {protocol: 'http1', headers: [{lastEventId: 'Last-Event-ID', value: Buffer.alloc(0)}]}]) {
    await assert.rejects(client.eventSource('https://example.test/private', options));
  }
  let reads = 0;
  await assert.rejects(client.eventSource('https://example.test/', {
    protocol: 'http1', headers: [{get lastEventId() {reads++; return 'Last-Event-ID';}}],
  }), {code: 'InvalidArgument'});
  assert.equal(reads, 0);
  assert.equal(calls.length, 0);
  assert.equal(sources.length, 0);
});

test('EventSource pulls one event at a time and concurrent reads preserve the admitted reader', async () => {
  const {Client, sources} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const source = await client.eventSource('https://example.test/', {protocol: 'http1'});
  const native = sources[0];
  let release;
  native.next = () => new Promise((resolve) => {release = resolve;});
  const pending = source.read();
  await assert.rejects(source.read(), {code: 'ConcurrentRead'});
  assert.equal(native.closed, false);
  assert.equal(native.reads, 1);
  const value = {data: 'first', event: 'message', id: 'saved'};
  native.lastEventId = value.id;
  native.retryMs = 18446744073709551615n;
  release(value);
  const event = await pending;
  assert.deepEqual(event, value);
  assert(Object.isFrozen(event));
  assert.equal(source.retryMs, 18446744073709551615n);
  assert.equal(source.lastEventId, 'saved');
  assert.equal(native.reads, 1);
  source.close();
  assert.equal(await source.read(), null);
});

test('EventSource close and AbortSignal interrupt pending work and detach listeners', async () => {
  const {Client, sources} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const controller = new AbortController();
  const source = await client.eventSource('https://example.test/', {protocol: 'http1', signal: controller.signal});
  sources[0].next = () => new Promise((_, reject) => {
    sources[0].cancel = () => reject(new Error('PHANTOM:Cancelled:event source was closed'));
  });
  const pending = source.read();
  assert.equal(getEventListeners(controller.signal, 'abort').length, 1);
  controller.abort();
  await assert.rejects(pending, {code: 'Cancelled'});
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  assert.equal(await source.read(), null);
  assert.equal(source.closed, true);

  const other = await client.eventSource('https://example.test/', {protocol: 'http1'});
  sources[1].next = () => new Promise((_, reject) => {
    sources[1].cancel = () => reject(new Error('PHANTOM:Cancelled:event source was closed'));
  });
  const waiting = other.read();
  other.close();
  await assert.rejects(waiting, {code: 'Cancelled'});
  other.close();
});

test('opening cancellation owns setup and terminal 204 retains only its initial metadata', async () => {
  const {Client, sources, setOpening} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const controller = new AbortController();
  setOpening((source) => new Promise((_, reject) => {
    source.cancel = () => reject(new Error('PHANTOM:Cancelled:event source was closed'));
  }));
  const opening = client.eventSource('https://example.test/', {protocol: 'http1', signal: controller.signal});
  controller.abort();
  await assert.rejects(opening, {code: 'Cancelled'});
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  assert.equal(sources[0].closed, true);

  setOpening((source) => {
    source.closed = true;
    return {status: 204, protocol: 'http2', url: 'https://example.test/final', headers: []};
  });
  const source = await client.eventSource('https://example.test/', {protocol: 'http2'});
  assert.equal(source.status, 204);
  assert.equal(source.protocol, 'http2');
  assert.equal(source.url, 'https://example.test/final');
  assert(Object.isFrozen(source.headers));
  assert.equal(source.closed, true);
  assert.equal(await source.read(), null);
  assert.equal(sources[1].reads, 0);
});

test('reconnect exhaustion keeps its SSE category and typed transport cause without leaking inspection', async () => {
  const {Client, sources} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const source = await client.eventSource('https://example.test/', {protocol: 'http3'});
  sources[0].next = async () => { throw new Error('PHANTOM_EVENT_SOURCE:ReconnectLimit:reconnect limit exhausted\nPHANTOM_REQUEST:Timeout:http3:connect:connection timed out'); };
  await assert.rejects(source.read(), (error) => {
    assert.equal(error.code, 'Sse');
    assert.equal(error.kind, 'ReconnectLimit');
    assert.equal(error.cause.code, 'Timeout');
    assert.equal(error.cause.protocol, 'http3');
    assert.equal(error.cause.timeoutPhase, 'connect');
    assert(!inspect(error).includes('connection timed out'));
    return true;
  });
  assert.equal(await source.read(), null);
});

test('breaking EventSource iteration stops its native owner without prefetching', async () => {
  const {Client, sources} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const source = await client.eventSource('https://example.test/', {protocol: 'http1'});
  sources[0].next = async () => ({data: 'one', event: 'message', id: '', retryMs: 3000n});
  for await (const event of source) {
    assert.equal(event.data, 'one');
    break;
  }
  assert.equal(sources[0].reads, 1);
  assert.equal(sources[0].closed, true);
});
