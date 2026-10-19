'use strict';
const { copyFileSync } = require('node:fs');
const path = require('node:path');
const repository = path.resolve(__dirname, '../../..');
const target = process.env.CARGO_TARGET_DIR
  ? path.resolve(repository, process.env.CARGO_TARGET_DIR) : path.join(repository, 'target');
const name = process.platform === 'win32' ? 'phantom_node.dll'
  : process.platform === 'darwin' ? 'libphantom_node.dylib' : 'libphantom_node.so';
copyFileSync(path.join(target, 'debug', name), path.resolve(__dirname, '../phantom.node'));
