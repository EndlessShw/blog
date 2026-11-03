'use strict';

// Hexo catches script-load errors. Requiring inside the registered filter lets
// runtime failures stop generation instead of silently falling back to dates.
// Run before Fluid's priority-10 filter snapshots the article collections.
hexo.extend.filter.register('before_generate', async function () {
  await require('../lib/article-timestamps').applyToHexo(hexo);
}, 5);
