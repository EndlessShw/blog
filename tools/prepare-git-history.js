'use strict';

const path = require('node:path');
const { prepareHistory } = require('../lib/article-timestamps/git');
const { repository } = require('../package.json');
const repositoryUrl = (typeof repository === 'string' ? repository : repository?.url)?.replace(/^git\+/, '');

prepareHistory(path.resolve(__dirname, '..'), { repositoryUrl }).then(head => {
  console.log(`[article-timestamps] Git 历史已就绪：${head.slice(0, 7)}`);
}).catch(error => {
  console.error(`[article-timestamps] ${error.message}`);
  process.exitCode = 1;
});
