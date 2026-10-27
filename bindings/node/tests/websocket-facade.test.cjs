'use strict';

const assert = require('node:assert/strict');
const {getEventListeners} = require('node:events');
const path = require('node:path');
const {test} = require('node:test');

const {loadFacade} = require('./load-facade.cjs');

function facade(connect) {
  const sockets = [], calls = [];
  class Socket {
    constructor() {this.events = []; this.sent = []; sockets.push(this);}
    receive() {return this.read ? this.read() : Promise.resolve(this.events.shift() ?? null);}
    send(...args) {this.sent.push(args); return this.write ? this.write() : Promise.resolve();}
    abort() {this.aborted = true; this.reject?.(Error('PHANTOM:Cancelled:WebSocket was aborted'));}
  }
  const owner = {
    async websocket(options, socket) {
      calls.push(options);
      if (connect) return connect(options, socket);
      return {status: 101, protocol: 'http1', selectedProtocol: null, headers: [{name: 'X-Order', value: Buffer.from('one'), sensitive: false}]};
    },
    async close() {for (const socket of sockets) socket.abort();},
  };
  const native = {NativeWebSocket: Socket, NativeEnvironment: class {client() {return owner;}}};
  return {...loadFacade(path.resolve(__dirname, '../index.cjs'), native), sockets, calls};
}

test('WebSocket preparation inherits only ordered headers and forwards explicit native policies', async () => {
  const {Client, WebSocketConnection, calls, sockets} = facade();
  const headers = [{name: 'X-First', value: Buffer.from('first')}, {name: 'X-Replace', value: Buffer.from('old')}];
  const client = new Client({profile: 'exact', route: 'direct', headers, protocol: 'http3', context: 'fetch'});
  headers[0].value.fill(0);
  const socket = await client.websocket(new URL('ws://example.test/chat'), {
    protocol: 'profile', headers: [{name: 'x-replace', value: Buffer.from('one')}, {name: 'x-replace', value: Buffer.from('two')}],
    handshakeTimeoutMs: null, maximumFrameBytes: 128, maximumMessageBytes: 512, maximumMessageFragments: 4,
    maximumConnectionFailures: 2, retryDelayMs: 10,
  });
  assert(socket instanceof WebSocketConnection);
  assert.equal(calls[0].protocol, 'profile'); assert.equal(calls[0].context, undefined);
  assert.equal(calls[0].handshakeTimeoutMs, 0);
  assert.deepEqual(calls[0].headers.map(({name, value}) => [name, value.toString()]), [['X-First', 'first'], ['x-replace', 'one'], ['x-replace', 'two']]);
  assert(Object.isFrozen(socket.handshake)); assert(Object.isFrozen(socket.handshake.headers));
  assert.equal(socket.handshake.selectedProtocol, null);
  socket.abort(); assert(sockets[0].aborted);
  const ordinary = await client.websocket('ws://example.test/default');
  assert.equal(calls[1].protocol, 'http1'); ordinary.abort(); await client.close();
});

test('WebSocket message projection preserves strings, bytes and control events without prefetching', async () => {
  const {Client, sockets} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const socket = await client.websocket('ws://example.test/');
  const native = sockets[0];
  native.events.push({kind: 'text', text: 'hello'}, {kind: 'binary', data: Buffer.from([0, 255])}, {kind: 'ping', data: Buffer.from('p')}, {kind: 'pong', data: Buffer.alloc(0)}, {kind: 'close', code: 1000, reason: 'done'});
  assert.equal(native.events.length, 5);
  const events = [];
  for await (const message of socket) events.push(message);
  assert.deepEqual(events, [{type: 'text', data: 'hello'}, {type: 'binary', data: Buffer.from([0, 255])}, {type: 'ping', data: Buffer.from('p')}, {type: 'pong', data: Buffer.alloc(0)}, {type: 'close', code: 1000, reason: 'done'}]);
  assert.equal(await socket.receive(), null); assert(native.aborted);
  await client.close();
});

test('one pending receive and send progress independently while duplicate operations fail', async () => {
  const {Client, sockets} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const socket = await client.websocket('ws://example.test/');
  const native = sockets[0];
  let receive, send;
  native.read = () => new Promise((resolve) => {receive = resolve;});
  native.write = () => new Promise((resolve) => {send = resolve;});
  const reading = socket.receive();
  const writing = socket.send('hello');
  await assert.rejects(socket.receive(), {code: 'InvalidOperation'});
  await assert.rejects(socket.send('again'), {code: 'InvalidOperation'});
  assert.equal(native.sent.length, 1);
  send(); await writing;
  receive({kind: 'text', text: 'received'});
  assert.deepEqual(await reading, {type: 'text', data: 'received'});
  native.write = undefined;
  await socket.send(Buffer.from([0, 255])); await socket.ping(); await socket.pong(Buffer.from('p')); await socket.close(1000, 'done');
  assert.deepEqual(native.sent.map((message) => message[0]), ['text', 'binary', 'ping', 'pong', 'close']);
  await assert.rejects(socket.ping(Buffer.alloc(126)), {code: 'InputLimit'});
  await assert.rejects(socket.close(1000, 'é'.repeat(62)), {code: 'InputLimit'});
  socket.abort(); await client.close();
});

test('WebSocket AbortSignal covers setup and reads, detaches listeners, and iteration break aborts', async () => {
  const controller = new AbortController();
  const {Client, sockets} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  const socket = await client.websocket('ws://example.test/', {signal: controller.signal});
  assert.equal(getEventListeners(controller.signal, 'abort').length, 1);
  sockets[0].read = () => new Promise((_resolve, reject) => {sockets[0].reject = reject;});
  const reading = socket.receive(); const rejected = assert.rejects(reading, {code: 'Cancelled'});
  controller.abort(); await rejected;
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  const second = await client.websocket('ws://example.test/');
  sockets[1].events.push({kind: 'text', text: 'one'});
  for await (const message of second) {assert.equal(message.data, 'one'); break;}
  assert(sockets[1].aborted);
  await client.close();
  const unopened = new AbortController(); unopened.abort();
  await assert.rejects(client.websocket('ws://example.test/', {signal: unopened.signal}), {code: 'Cancelled'});
});

test('invalid WebSocket inputs fail before opening and native handshake failures retain category', async () => {
  const {Client, calls} = facade();
  const client = new Client({profile: 'exact', route: 'direct'});
  for (const options of [{protocol: null}, {protocol: 'negotiated'}, {signal: {}}, {maximumFrameBytes: 0}, {maximumMessageBytes: 67108865}, {handshakeTimeoutMs: 0}, {maximumMessageFragments: 1.5}, {retryDelayMs: -1}]) {
    await assert.rejects(client.websocket('ws://example.test/', options), (error) => ['InvalidProtocol', 'InvalidArgument'].includes(error.code));
  }
  assert.equal(calls.length, 0);
  await client.close();
  const failed = facade(() => {throw Error('PHANTOM_WEBSOCKET:HandshakeRejected::403:WebSocket opening was rejected');});
  await assert.rejects(new failed.Client({profile: 'exact', route: 'direct'}).websocket('ws://example.test/'), {code: 'WebSocket', kind: 'HandshakeRejected', status: 403});
  assert(failed.sockets[0].aborted);
});
