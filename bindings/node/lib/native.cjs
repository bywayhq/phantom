'use strict';

const { PhantomError } = require('./errors.cjs');

function loadNative() {
  const failure = (code, message, cause) => {
    const error = new PhantomError(code, message);
    if (cause !== undefined) Object.defineProperty(error, 'cause', {value: cause});
    return error;
  };
  const load = (name) => {
    try { return require(name); }
    catch (cause) { throw failure('NativeLoad', 'Phantom native library could not be loaded', cause); }
  };
  if (require('node:fs').existsSync(require('node:path').join(__dirname, '..', 'phantom.node'))) {
    return load('../phantom.node');
  }
  let packageName;
  if (process.platform === 'win32' && process.arch === 'x64') packageName = '@byway/phantom-win32-x64-msvc';
  else if (process.platform === 'darwin' && process.arch === 'arm64') packageName = '@byway/phantom-darwin-arm64';
  else if (process.platform === 'linux' && process.arch === 'x64') {
    let glibc;
    try { glibc = process.report.getReport().header.glibcVersionRuntime; }
    catch (cause) { throw failure('NativePlatformUnsupported', 'Phantom requires a supported native host', cause); }
    if (typeof glibc === 'string' && glibc.length > 0) packageName = '@byway/phantom-linux-x64-gnu';
  }
  if (packageName === undefined) {
    throw failure('NativePlatformUnsupported', 'Phantom has no native package for this host');
  }
  let metadataPath;
  try { metadataPath = require.resolve(`${packageName}/package.json`); }
  catch (cause) {
    throw failure(cause?.code === 'MODULE_NOT_FOUND' ? 'NativePackageMissing' : 'NativeLoad',
      'Phantom requires its matching optional native package; install with optional dependencies enabled', cause);
  }
  const metadata = load(metadataPath);
  if (metadata.name !== packageName || metadata.version !== require('../package.json').version) {
    throw failure('NativePackageVersion', 'Phantom facade and native package versions must match exactly');
  }
  return load(packageName);
}

module.exports = loadNative();
