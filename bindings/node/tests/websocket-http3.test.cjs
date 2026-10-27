'use strict';

const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const {test} = require('node:test');
const {Client, Profile} = require('..');

async function bounded(promise, label, milliseconds = 10000) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

for (const reject of [false, true]) test(`HTTP/3 WebSocket ${reject ? 'rejection survives graceful shutdown timeout' : 'frames and cancellation preserve a pooled sibling'}`, {timeout: 40000}, async () => {
  const python = process.env.PHANTOM_H3_PEER_PYTHON;
  const script = process.env.PHANTOM_WEBSOCKET_H3_PEER_SCRIPT;
  assert.ok(python && script, 'independent HTTP/3 WebSocket peer paths are required');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-node-ws-h3-'));
  const peer = spawn(python, [script, '--directory', directory, ...(reject ? ['--reject'] : [])], {stdio: ['pipe', 'pipe', 'pipe']});
  const lines = readline.createInterface({input: peer.stdout, terminal: false})[Symbol.asyncIterator]();
  let stderr = '', overflow = false;
  peer.stderr.on('data', (data) => {
    if (stderr.length + data.length > 65536) overflow = true;
    else stderr += data.toString();
  });
  const exit = new Promise((resolve) => {
    peer.once('error', (error) => resolve({error}));
    peer.once('close', (code, signal) => resolve({code, signal}));
  });
  async function event(expected) {
    const line = await bounded(lines.next(), `missing peer event ${expected}`);
    assert.equal(line.done, false);
    assert.ok(Buffer.byteLength(line.value) <= 1024);
    assert.deepEqual(JSON.parse(line.value), {event: expected});
  }
  async function receipt(name) {
    const data = await fs.readFile(path.join(directory, name));
    assert.ok(data.length <= 65536);
    return JSON.parse(data.toString());
  }
  let client, socket, healthy, rejected;
  try {
    await event('ready');
    const ready = await receipt('ready.json');
    // Chrome's recipe leaves HTTP/3 WebSockets disabled.
    const document = Profile.fromCatalog('chrome-154-windows').describe();
    document.profile.http3.request.extended_connect_pseudo_header_order =
      ['Method', 'Protocol', 'Scheme', 'Authority', 'Path'];
    const profile = Profile.fromDescription(document);
    client = new Client({profile, route: 'direct',
      additionalRoots: [Buffer.from(ready.root_der)], timeouts: {totalMs: 10000}});
    const options = {method: 'GET', protocol: 'http3', context: 'raw'};
    const warm = await client.request(ready.url + '/warm', options);
    assert.equal(await warm.text(2), 'ok');
    const url = ready.url.replace('https:', 'wss:');
    if (reject) {
      await assert.rejects(client.websocket(url + '/reject', {protocol: 'http3'}), (error) => {
        rejected = error.response;
        return error.code === 'WebSocket' && error.kind === 'HandshakeRejected' && error.status === 403;
      });
      await event('rejected');
      assert.equal(rejected.protocol, 'http3');
      assert.deepEqual(rejected.headers.filter(({name}) => name === 'x-duplicate').map(({value}) => value.toString()), ['one', 'two']);
      await assert.rejects(client.close({timeoutMs: 0}), {code: 'Timeout'});
      assert.equal((await rejected.read(2)).toString(), 'de');
      peer.stdin.write('release\n');
      await event('complete');
      assert.equal(await rejected.text(4), 'nied');
      await client.close();
    } else {
      socket = await client.websocket(url + '/echo', {protocol: 'http3', headers: [{name: 'sec-websocket-protocol', value: Buffer.from('chat')}]});
      assert.equal(socket.handshake.status, 200);
      assert.equal(socket.handshake.protocol, 'http3');
      assert.equal(socket.handshake.selectedProtocol, 'chat');
      await socket.send('hello'); assert.deepEqual(await socket.receive(), {type: 'text', data: 'hello'});
      await socket.send(Buffer.from([0, 255])); assert.deepEqual(await socket.receive(), {type: 'binary', data: Buffer.from([0, 255])});
      await socket.close(1000, 'done'); assert.deepEqual(await socket.receive(), {type: 'close', code: 1000, reason: 'done'});
      const controller = new AbortController();
      socket = await client.websocket(url + '/cancel', {protocol: 'http3', signal: controller.signal});
      // Keep the receive pending before opening the independent HTTP sibling.
      const pending = assert.rejects(socket.receive(), {code: 'Cancelled'});
      healthy = await client.request(ready.url + '/healthy', options);
      await event('live');
      controller.abort();
      await bounded(pending, 'WebSocket receive did not cancel');
      await event('cancelled');
      assert.equal(await healthy.text(7), 'healthy');
      const reuse = await client.request(ready.url + '/reuse', options);
      assert.equal(await reuse.text(2), 'ok');
      await event('complete');
    }
    const result = await receipt('result.json');
    assert.equal(result.connections, 1);
    assert.equal(result.rejected, reject);
    assert.equal(new Set(Object.values(result.streams)).size, reject ? 2 : 5);
    if (!reject) {
      assert.equal(result.frames, 3);
      assert.equal(result.healthy_released, true);
      assert.deepEqual(result.cancellations, {reset_stream: 0x10c, stop_sending: 0x10c});
    }
    peer.stdin.end('stop\n');
    assert.deepEqual(await bounded(exit, 'HTTP/3 peer did not settle', 8000), {code: 0, signal: null}, stderr);
    await client.close();
  } finally {
    socket?.abort(); healthy?.close(); rejected?.close();
    if (!peer.stdin.destroyed) peer.stdin.end();
    try {
      assert.deepEqual(await bounded(exit, 'HTTP/3 peer did not settle', 8000), {code: 0, signal: null}, stderr);
      assert.equal(overflow, false);
    } catch (error) {peer.kill(); await exit; throw error;}
    finally {
      try {if (client) await client.destroy();}
      finally {await fs.rm(directory, {recursive: true, force: true});}
    }
  }
});
