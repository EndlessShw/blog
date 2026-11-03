'use strict';

// Use the parsers declared by the existing Hexo packages, without patching them.
const { createRequire } = require('node:module');
const hexoRequire = createRequire(require.resolve('hexo'));
const rendererRequire = createRequire(require.resolve('hexo-renderer-marked'));
const utilRequire = createRequire(hexoRequire.resolve('hexo-util'));

module.exports = {
  yaml: hexoRequire('js-yaml'),
  moment: hexoRequire('moment-timezone'),
  marked: rendererRequire('marked'),
  html: utilRequire('htmlparser2')
};
