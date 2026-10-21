'use strict';

const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');

// Give each native double its own actual facade graph and private class handles.
function loadFacade(filename, native) {
  const cache = new Map();
  const directory = path.dirname(filename);
  const library = path.join(directory, 'lib') + path.sep;
  function load(file) {
    if (cache.has(file)) return cache.get(file).exports;
    const loaded = new Module(file, module);
    cache.set(file, loaded);
    loaded.filename = file;
    loaded.paths = Module._nodeModulePaths(path.dirname(file));
    const realRequire = Module.createRequire(file);
    loaded.require = (id) => {
      if (id === '../phantom.node' && file === path.join(directory, 'lib', 'native.cjs')) return native;
      if (id === 'node:fs') return {...fs, existsSync: (candidate) => candidate === path.join(directory, 'phantom.node') || fs.existsSync(candidate)};
      if (id.startsWith('.')) {
        const resolved = realRequire.resolve(id);
        if (resolved.startsWith(library) && resolved.endsWith('.cjs')) return load(resolved);
      }
      return realRequire(id);
    };
    loaded._compile(fs.readFileSync(file, 'utf8'), file);
    return loaded.exports;
  }
  return load(filename);
}

module.exports = { loadFacade };
