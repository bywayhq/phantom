'use strict';

// Public Node binding adapter for the existing controlled-peer protocol.
const fs = require('node:fs/promises');
const path = require('node:path');
const readline = require('node:readline');
const { setTimeout: sleep } = require('node:timers/promises');

// Keep these effective fields aligned with workload_config.py and native Config.
const DEFAULTS = Object.freeze({
  name: 'warm-h2', protocol: 'h2', profile: 'chrome', route: 'direct',
  concurrency: 1, requests: 2000, warmup: 100, bytes: 1024, method: 'GET',
  upload_bytes: 0, redirects: 0, cancel_after_bytes: 0, cancel_stage: 'body',
  consume: 'stream', cold: false, origins: 1, server_delay_ms: 0,
  chunk_bytes: 16384, chunk_delay_ms: 0, gzip: false, template: false,
  arrival_interval_us: 0, workers: 2, peer_workers: null,
  speculative_tls: false, proxy_delay_ms: 0, proxy_auth: false,
  diagnostic_events: 0, diagnostic_snapshot: true,
});
const PROTOCOLS = Object.freeze({h1: 'http1', h2: 'http2', h3: 'http3'});
const PROFILE = 'chrome/154.0.8037.97/windows-11-26200/r1';

function configuration(supplied) {
  if (supplied === null || typeof supplied !== 'object' || Array.isArray(supplied)
    || Object.keys(supplied).some((key) => !Object.hasOwn(DEFAULTS, key))) {
    throw new Error('unknown benchmark configuration fields');
  }
  const config = {...DEFAULTS, ...supplied};
  for (const [key, value] of Object.entries(DEFAULTS)) {
    if (key !== 'peer_workers' && typeof config[key] !== typeof value) {
      throw new Error(`invalid configuration type: ${key}`);
    }
  }
  const bounds = {
    concurrency: [1, 256], requests: [1, 1000000], warmup: [0, 100000],
    bytes: [0, 16 * 1024 * 1024], origins: [1, 128], chunk_bytes: [1, 65536],
    server_delay_ms: [0, 1000], chunk_delay_ms: [0, 1000],
    arrival_interval_us: [0, 1000000],
  };
  const variable = new Set([...Object.keys(bounds), 'name', 'protocol', 'consume', 'cold', 'peer_workers']);
  for (const [key, value] of Object.entries(DEFAULTS)) {
    if (!variable.has(key) && config[key] !== value) {
      throw new Error(`adapter requires ${key}=${JSON.stringify(value)}`);
    }
  }
  for (const [key, [lower, upper]] of Object.entries(bounds)) {
    if (!Number.isSafeInteger(config[key]) || config[key] < lower || config[key] > upper) {
      throw new Error(`unbounded benchmark configuration: ${key}`);
    }
  }
  if (!Object.hasOwn(PROTOCOLS, config.protocol) || !['collect', 'stream'].includes(config.consume)) {
    throw new Error('adapter requires exact H1/H2/H3 and collect or stream');
  }
  if (config.peer_workers !== null && (!Number.isInteger(config.peer_workers)
    || config.peer_workers < 1 || config.peer_workers > 16)) {
    throw new Error('invalid peer_workers');
  }
  // The shared client stays alive; the binding permits 128 retained clients/Env.
  if (config.cold && config.concurrency > 127) {
    throw new Error('cold concurrency exceeds the native environment client bound');
  }
  return config;
}

function peerInputs(ready, count) {
  if (!Array.isArray(ready.urls) || ready.urls.length !== count) {
    throw new Error('peer origin count differs from configuration');
  }
  for (const value of ready.urls) {
    if (typeof value !== 'string') throw new Error('invalid peer URL');
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.hostname !== '127.0.0.1' || !url.port
      || url.username || url.password || url.hash) {
      throw new Error('adapter requires HTTPS peers on IPv4 loopback');
    }
  }
  if (!Array.isArray(ready.root_der) || !ready.root_der.length
    || ready.root_der.length > 1024 * 1024
    || ready.root_der.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error('invalid peer DER root');
  }
  return {urls: ready.urls, root: Buffer.from(ready.root_der)};
}

function sample(id) {
  return {
    id, scheduled_ns: 0, started_ns: 0, application_wait_ns: 0, build_ns: 0,
    head_ns: null, first_byte_ns: null, complete_ns: 0, bytes: 0,
    cancelled: false, error: null,
  };
}

function errorText(error) {
  return `${error?.name ?? 'Error'}${error?.code ? ` (${error.code})` : ''}: ${error?.message ?? 'operation failed'}`;
}

async function execute(config, urls, shared, create, record) {
  const start = process.hrtime.bigint();
  const elapsed = () => Number(process.hrtime.bigint() - start);
  let owned;
  let response;
  try {
    const selected = config.cold ? (owned = create()) : shared;
    if (owned) record.build_ns = elapsed();
    const url = urls[record.id % urls.length];
    response = await selected.request(url, {
      method: 'GET', protocol: PROTOCOLS[config.protocol], context: 'raw',
    });
    record.head_ns = elapsed();
    if (response.status !== 200 || response.protocol !== PROTOCOLS[config.protocol]
      || response.connectionRetries !== 0 || response.redirects !== 0 || response.url !== url) {
      throw new Error('unexpected status, protocol, URL or replay');
    }
    const verify = (data) => {
      record.bytes += data.length;
      if (record.bytes > config.bytes) throw new Error('incorrect response length');
      for (const byte of data) {
        if (byte !== 90) throw new Error('incorrect response content');
      }
    };
    if (config.consume === 'collect') {
      verify(await response.bytes(config.bytes));
      // The public collector does not expose first data arrival.
    } else {
      for await (const data of response) {
        if (data.length && record.first_byte_ns === null) record.first_byte_ns = elapsed();
        verify(data);
      }
    }
    if (record.bytes !== config.bytes) throw new Error('incorrect response length');
  } catch (error) {
    record.error = errorText(error);
  } finally {
    record.complete_ns = elapsed();
    try {
      response?.close();
    } catch (error) {
      record.error = [record.error, errorText(error)].filter(Boolean).join('; ');
    }
    try {
      if (owned) await owned.close({timeoutMs: 5000});
    } catch (error) {
      record.error = [record.error, errorText(error)].filter(Boolean).join('; ');
    }
  }
}

async function runWorkers(config, urls, shared, create, records, start) {
  async function worker(index) {
    for (let id = index; id < records.length; id += config.concurrency) {
      const record = records[id];
      if (start !== undefined) {
        const planned = id * config.arrival_interval_us * 1000;
        if (config.arrival_interval_us) {
          for (;;) {
            const remaining = planned - Number(process.hrtime.bigint() - start);
            if (remaining <= 0) break;
            await sleep(Math.min(remaining / 1000000, 2147483647));
          }
        }
        const now = Number(process.hrtime.bigint() - start);
        record.scheduled_ns = config.arrival_interval_us ? planned : now;
        record.started_ns = now;
        record.application_wait_ns = Math.max(0, now - record.scheduled_ns);
      }
      await execute(config, urls, shared, create, record);
    }
  }
  await Promise.all(Array.from({length: config.concurrency}, (_, i) => worker(i)));
}

function signal(event) {
  return new Promise((resolve, reject) => {
    process.stdout.write(`${JSON.stringify({event})}\n`, (error) => error ? reject(error) : resolve());
  });
}

async function control(lines, expected) {
  const command = await lines.next();
  if (command.done || command.value.trim() !== expected) {
    throw new Error('controller disconnected or sent an invalid command');
  }
}

async function run(supplied, ready, output) {
  const config = configuration(supplied);
  const {urls, root} = peerInputs(ready, config.origins);
  const packagePath = process.env.PHANTOM_NODE_PACKAGE;
  if (!packagePath || !path.isAbsolute(packagePath) || !(await fs.stat(packagePath)).isDirectory()) {
    throw new Error('PHANTOM_NODE_PACKAGE must name the explicit absolute package directory');
  }
  if (process.env.TOKIO_WORKER_THREADS !== undefined && process.env.TOKIO_WORKER_THREADS !== '2') {
    throw new Error('adapter requires TOKIO_WORKER_THREADS=2');
  }
  // Pinned napi uses Tokio's default multi-thread builder, which reads this.
  process.env.TOKIO_WORKER_THREADS = '2';
  const {Client} = require(packagePath);
  const metadata = JSON.parse(await fs.readFile(path.join(packagePath, 'package.json'), 'utf8'));
  const create = () => new Client({
    profile: PROFILE, route: 'direct', cookies: false, additionalRoots: [root],
    maximumActiveRequests: config.concurrency,
    timeouts: {connectMs: 5000, totalMs: 15000},
  });
  const shared = create();
  const input = readline.createInterface({input: process.stdin, crlfDelay: Infinity, terminal: false});
  const lines = input[Symbol.asyncIterator]();
  try {
    let warmup = Array.from({length: config.warmup}, (_, i) => sample(i));
    await runWorkers(config, urls, shared, create, warmup);
    if (warmup.some((record) => record.error !== null)) throw new Error('warmup failed; no measurement accepted');
    warmup = null;
    const records = Array.from({length: config.requests}, (_, i) => sample(i));
    // Serialized size is reproducible, but is not V8's in-memory object size.
    const observerBytes = Buffer.byteLength(JSON.stringify(records));
    await signal('ready');
    await control(lines, 'go');
    const start = process.hrtime.bigint();
    await runWorkers(config, urls, shared, create, records, start);
    const elapsed = Number(process.hrtime.bigint() - start);
    await signal('phase_end');
    await control(lines, 'save');
    const result = {
      config, samples: records, elapsed_ns: elapsed, heap_instrumented: false,
      observer_storage_bytes: observerBytes,
      observer_storage_kind: 'prephase JSON-encoded observation size; not V8 heap size',
      adapter_settings: {
        library: `${metadata.name}@${metadata.version}`, runtime: process.version,
        recipe: PROFILE, native_workers: 2, native_workers_source: 'TOKIO_WORKER_THREADS before addon load',
        maximum_active_requests: config.concurrency, stream_chunk_bytes: 65536,
        cookies: false, connect_timeout_s: 5, total_timeout_s: 15, route: 'direct',
      },
    };
    await fs.writeFile(output, `${JSON.stringify(result)}\n`, {flag: 'wx'});
    await signal('saved');
  } finally {
    input.close();
    await shared.close({timeoutMs: 5000});
  }
}

if (require.main === module) {
  if (process.argv.length !== 6 || process.argv[2] !== 'run') {
    process.stderr.write('usage: phantom_node_client.cjs run CONFIG READY RESULT\n');
    process.exitCode = 1;
  } else {
    Promise.all(process.argv.slice(3, 5).map(async (file) => JSON.parse(await fs.readFile(file, 'utf8'))))
      .then(([config, ready]) => run(config, ready, process.argv[5]))
      .catch((error) => { process.stderr.write(`${errorText(error)}\n`); process.exitCode = 1; });
  }
}

module.exports = {DEFAULTS, configuration, peerInputs, control};
