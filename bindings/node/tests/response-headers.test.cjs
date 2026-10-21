'use strict';

const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');
const {Client} = require('..');

test('HTTP/3 head fields retain raw QPACK order, bytes and markers after close', {timeout: 30000}, async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'phantom-header-h3-'));
  const peer = spawn(process.env.PHANTOM_H3_PEER_PYTHON,
    [process.env.PHANTOM_HEADER_H3_PEER_SCRIPT, '--directory', directory], {stdio: ['pipe', 'pipe', 'pipe']});
  let stderr = '', output = '';
  peer.stderr.setEncoding('utf8').on('data', (value) => { stderr += value; });
  const exited = new Promise((resolve, reject) => { peer.once('error', reject); peer.once('exit', resolve); });
  let timer;
  try {
    await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('missing header peer ready')), 10000);
      peer.stdout.setEncoding('utf8').on('data', (value) => {
        output += value;
        if (output.length > 1024) { reject(new Error('oversized header peer event')); return; }
        if (output.includes('\n')) {
          try { assert.deepEqual(JSON.parse(output.trim()), {event: 'ready'}); resolve(); }
          catch (error) { reject(error); }
        }
      });
      exited.then((code) => reject(new Error(`header peer exited ${code}: ${stderr}`)), reject);
    });
    clearTimeout(timer);
    const data = await fs.readFile(path.join(directory, 'ready.json'));
    assert.ok(data.length <= 65536);
    const ready = JSON.parse(data);
    const client = new Client({profile: 'chrome/154.0.8037.97/windows-11-26200/r1',
      route: 'direct', additionalRoots: [Buffer.from(ready.root_der)]});
    try {
      const expected = [{name: 'x-a', value: Buffer.from('first'), sensitive: false},
        {name: 'x-b', value: Buffer.from([0x80, 0x42]), sensitive: true},
        {name: 'x-a', value: Buffer.from('last'), sensitive: false}];
      for (const target of ['/one', '/two']) {
        const response = await client.request(ready.url + target,
          {method: 'GET', protocol: 'http3', context: 'raw', timeoutMs: 10000});
        try {
          assert.deepEqual(response.headers, expected);
          assert.equal((await response.bytes(2)).toString(), 'ok');
        } finally { response.close(); }
        assert.deepEqual(response.headers, expected);
      }
      peer.stdin.end('stop\n');
      const code = await Promise.race([exited, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('header peer did not settle')), 10000);
      })]);
      assert.equal(code, 0, stderr);
    } finally { await client.close(); }
  } finally {
    clearTimeout(timer);
    if (peer.exitCode === null) peer.kill();
    await exited;
    await fs.rm(directory, {recursive: true, force: true});
  }
});
