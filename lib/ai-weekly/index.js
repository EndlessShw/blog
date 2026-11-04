'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
// Resolve through the packages that declare these dependencies. This also works
// with pnpm's isolated layout before unrelated root dependency upgrades ship.
const moment = createRequire(require.resolve('hexo'))('moment');
const pagination = createRequire(require.resolve('hexo-generator-archive'))('hexo-pagination');

const PREFIX = 'ai-weekly/';

function collectReports(pages) {
  const reports = [];
  for (const page of pages) {
    if (!page.source.startsWith(PREFIX) && page.layout !== 'ai-weekly') continue;
    const fail = message => { throw new Error(`AI 周报 ${page.source}：${message}`); };
    if (!/^ai-weekly\/[a-z0-9]+(?:-[a-z0-9]+)*\/index\.md$/.test(page.source)) {
      fail('请使用 source/ai-weekly/<英文数字或连字符 slug>/index.md');
    }
    if (page.path !== page.source.replace(/\.md$/, '.html')) fail('请保留目录决定的永久链接，不设置 permalink');
    if (page.layout !== 'ai-weekly') fail('layout 必须为 ai-weekly');
    if (typeof page.title !== 'string' || !page.title.trim()) fail('title 必须为非空文本');
    if (page.summary != null && typeof page.summary !== 'string') fail('summary 必须为纯文本');
    const published = page.published_at;
    if (typeof published !== 'string' || !/T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(published)) {
      fail('published_at 必须为带时区的 ISO 8601 字符串，例如 "2026-11-04T12:00:00+08:00"（请加引号）');
    }
    const date = moment.parseZone(published, moment.ISO_8601, true);
    if (!date.isValid()) fail('published_at 不是有效日期');
    // Hexo otherwise defaults Page dates to filesystem timestamps. All consumers,
    // including search and Open Graph, must use the explicit publication time.
    page.date = date.toDate();
    page.updated = date.toDate();
    reports.push(page);
  }
  return reports.sort((a, b) => b.date.valueOf() - a.date.valueOf() || a.source.localeCompare(b.source, 'en'));
}

function register(hexo) {
  let searchWrapped = false;
  hexo.extend.filter.register('before_generate', function () {
    for (const [view, file] of [['ai-weekly-list', 'list'], ['ai-weekly', 'report']]) {
      hexo.theme.setView(`${view}.ejs`, fs.readFileSync(path.join(__dirname, 'views', `${file}.ejs`), 'utf8'));
    }
    collectReports(hexo.locals.get('pages').toArray());
    if (!searchWrapped) {
      // Theme/site scripts load concurrently. Wrap only after all scripts load,
      // and only once, including under `hexo server` and repeated generation.
      const original = hexo.extend.generator.get('_hexo_generator_search');
      if (typeof original !== 'function') throw new Error('AI 周报：未找到 Fluid 搜索生成器');
      hexo.extend.generator.register('_hexo_generator_search', function (locals) {
        const reports = collectReports(locals.pages.toArray());
        // Pass only search fields. Page metadata may contain plain categories/
        // tags arrays, while Fluid's Post branch expects Warehouse queries.
        const entries = reports.map(report => ({
          title: report.title, path: report.path, date: report.date,
          content: report.content, indexing: report.indexing
        }));
        const posts = new locals.posts.constructor([...locals.posts.toArray(), ...entries]);
        return original.call(this, { ...locals, posts });
      });
      searchWrapped = true;
    }
  }, 20);

  hexo.extend.generator.register('ai-weekly', function (locals) {
    const reports = collectReports(locals.pages.toArray());
    return pagination(PREFIX, reports, {
      perPage: reports.length ? 10 : 0,
      layout: 'ai-weekly-list',
      format: `${hexo.config.pagination_dir}/%d/`,
      data: { title: 'AI 周报', layout: 'ai-weekly-list', report_total: reports.length }
    });
  });
}

module.exports = { collectReports, register };
