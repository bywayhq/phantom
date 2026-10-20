'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../index.cjs'), 'utf8');

function fixture(options = {}) {
  const calls = [];
  const addon = {NativeEnvironment: class {}};
  const name = options.name ?? '@byway/phantom-linux-x64-gnu';
  const cause = options.cause ?? Object.assign(new Error('original loader failure'), {code: 'ERR_DLOPEN_FAILED'});
  const requireMock = (id) => {
    calls.push(id);
    if (id === 'node:fs') return {existsSync: () => options.local ?? false};
    if (id === './package.json') return {version: '0.3.0'};
    if (id === '/native/package.json') return {name, version: options.version ?? '0.3.0'};
    if (id === './phantom.node' || id === name) {
      if (options.broken) throw cause;
      return addon;
    }
    return require(id);
  };
  requireMock.resolve = (id) => {
    calls.push(id);
    if (options.missing) throw Object.assign(new Error('missing native package'), {code: 'MODULE_NOT_FOUND'});
    if (options.resolveError) throw cause;
    return '/native/package.json';
  };
  const run = () => vm.runInNewContext(source, {
    require: requireMock, module: {exports: {}}, __dirname: '/facade', Buffer,
    process: {platform: options.platform ?? 'linux', arch: options.arch ?? 'x64',
      report: {getReport: () => ({header: {glibcVersionRuntime: options.musl ? undefined : '2.39'}})}},
  });
  return {run, calls, cause};
}

test('adjacent developer addon loads without registry lookup or version guessing', () => {
  const f = fixture({local: true, platform: 'other'});
  f.run();
  assert.ok(f.calls.includes('./phantom.node'));
  assert.ok(!f.calls.some(id => id.startsWith('@byway/')));
});

test('supported hosts select one exact-version native package', () => {
  for (const options of [
    {platform: 'linux', arch: 'x64', name: '@byway/phantom-linux-x64-gnu'},
    {platform: 'win32', arch: 'x64', name: '@byway/phantom-win32-x64-msvc'},
    {platform: 'darwin', arch: 'arm64', name: '@byway/phantom-darwin-arm64'},
  ]) {
    const f = fixture(options);
    f.run();
    assert.deepEqual(f.calls.filter(id => id.startsWith('@byway/')), [options.name + '/package.json', options.name]);
  }
});

test('musl and unsupported architectures fail without another native package', () => {
  for (const options of [{musl: true}, {arch: 'arm64'}, {platform: 'darwin', arch: 'x64'}]) {
    const f = fixture(options);
    assert.throws(f.run, {code: 'NativePlatformUnsupported'});
    assert.ok(!f.calls.some(id => id.startsWith('@byway/')));
  }
});

test('missing package and mismatched version are distinguishable', () => {
  assert.throws(fixture({missing: true}).run, {code: 'NativePackageMissing'});
  const f = fixture({version: '0.2.0'});
  assert.throws(f.run, {code: 'NativePackageVersion'});
  assert.ok(!f.calls.includes('@byway/phantom-linux-x64-gnu'));
});

test('local and registry loader failures preserve their original cause without fallback', () => {
  for (const options of [{local: true, broken: true}, {broken: true}, {resolveError: true}]) {
    const f = fixture(options);
    assert.throws(f.run, error => error.code === 'NativeLoad' && error.cause === f.cause);
    if (options.local) assert.ok(!f.calls.some(id => id.startsWith('@byway/')));
  }
});
