'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const adapter = require('./phantom_node_client.cjs');

test('known-length producer retains bounded chunks and exact payload', async () => {
  for (const size of [0, 1, 65536, 65537, 16 * 1024 * 1024]) {
    let count = 0;
    for await (const part of adapter.upload(size)) {
      assert.ok(part.length <= 65536);
      assert.ok(part.every((byte) => byte === 85));
      count += part.length;
    }
    assert.equal(count, size);
  }
});

function cancellation(extra = {}) {
  return adapter.configuration({warmup: 1, concurrency: 2, requests: 2,
    cancel_after_bytes: 2, bytes: 8, chunk_delay_ms: 1, ...extra});
}

test('strict config retains uploads and rejects unsupported cancellation modes', () => {
  assert.equal(adapter.configuration({method: 'POST', upload_bytes: 65537}).upload_bytes, 65537);
  assert.equal(cancellation().cancel_after_bytes, 2);
  for (const change of [{cancel_stage: 'upload'}, {upload_bytes: 1}, {method: 'PUT'},
    {method: 'POST', upload_bytes: 16 * 1024 * 1024 + 1}]) {
    assert.throws(() => adapter.configuration(change));
  }
  for (const change of [{consume: 'collect'}, {cold: true}, {warmup: 0}, {requests: 3},
    {chunk_delay_ms: 0}, {cancel_after_bytes: 8}, {origins: 2}, {method: 'POST'}]) {
    assert.throws(() => cancellation(change));
  }
});

function response(url, cleanupError = false) {
  let remaining = 8;
  return {
    status: 200, protocol: 'http2', redirects: 0, connectionRetries: 0, url,
    closed: false, reads: [],
    async read(maximum) {
      this.reads.push(maximum);
      if (!remaining) return null;
      remaining--;
      return Buffer.from('Z');
    },
    close() {
      this.closed = true;
      if (cleanupError) throw new Error('cleanup failed');
    },
  };
}

test('prefix closes only selected response and healthy operation completes', async () => {
  const seen = [];
  const client = {async request(url) {
    const reply = response(url);
    seen.push(reply);
    return reply;
  }};
  for (const id of [0, 1]) {
    const record = adapter.sample(id);
    await adapter.execute(cancellation(), ['https://127.0.0.1:12345/'], client, null, record);
    assert.equal(record.error, null);
    assert.equal(record.cancelled, id === 0);
    assert.equal(record.bytes, id === 0 ? 2 : 8);
    assert.ok(record.first_byte_ns > 0);
  }
  assert.equal(seen[0].url, 'https://127.0.0.1:12345/?cancel=1');
  assert.equal(seen[1].url, 'https://127.0.0.1:12345/');
  assert.equal(seen[0].reads[0], 2);
  assert.ok(seen.every((reply) => reply.closed));
});

test('POST sends exact length; cleanup failure never becomes successful cancellation', async () => {
  let payload = 0;
  const client = {async request(url, options) {
    assert.equal(options.method, 'POST');
    assert.equal(options.bodyLength, 65537);
    for await (const part of options.body) payload += part.length;
    const reply = response(url);
    reply.bytes = async () => Buffer.from('Z');
    return reply;
  }};
  const record = adapter.sample(0);
  await adapter.execute(adapter.configuration({method: 'POST', upload_bytes: 65537,
    consume: 'collect', bytes: 1}), ['https://127.0.0.1:12345/'], client, null, record);
  assert.equal(record.error, null);
  assert.equal(payload, 65537);
  const failed = adapter.sample(0);
  await adapter.execute(cancellation(), ['https://127.0.0.1:12345/'], {
    async request(url) { return response(url, true); },
  }, null, failed);
  assert.match(failed.error, /cleanup failed/);
  assert.equal(failed.cancelled, false);
});
