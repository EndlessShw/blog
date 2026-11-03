'use strict';

const path = require('node:path');
const { prepareHistory } = require('../lib/article-timestamps/git');

prepareHistory(path.resolve(__dirname, '..')).then(head => {
  console.log(`[article-timestamps] Git 历史已就绪：${head.slice(0, 7)}`);
}).catch(error => {
  console.error(`[article-timestamps] ${error.message}`);
  process.exitCode = 1;
});
