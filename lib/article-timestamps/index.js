'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { git, GitHistory, newer } = require('./git');
const { frontMatter, parseDate, insertDate } = require('./content');
const { resolveAssets } = require('./assets');
const { moment } = require('./dependencies');

async function inspect(root, { fetch = false, sourceDir = 'source', zone = 'Asia/Shanghai', files } = {}) {
  const history = await GitHistory.open(root, { fetch });
  try {
    const prefix = sourceDir.replace(/\\/g, '/').replace(/\/$/, '') + '/_posts/';
    const withoutHistory = [...new Set((await git(root, ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', prefix])).split('\0'))].filter(file => /\.md$/i.test(file) && !history.tree.has(file));
    if (withoutHistory.length) throw new Error(`新文章尚无 Git 历史，请先提交：${withoutHistory.join(', ')}`);
    let articles = [...history.tree.keys()].filter(file => file.startsWith(prefix) && /\.md$/i.test(file));
    if (files) {
      const selected = new Set(files.map(file => path.relative(root, path.resolve(root, file)).replace(/\\/g, '/')));
      for (const file of selected) if (!articles.includes(file)) throw new Error(`${file}: 不在根仓库已跟踪的 ${prefix} Markdown 范围内；新文章请先 git add 并 commit`);
      articles = articles.filter(file => selected.has(file));
    }
    const results = [], diagnostics = [];
    for (const file of articles.sort()) {
      try {
        const committed = frontMatter(await history.content(file));
        const working = await fs.readFile(path.join(root, file));
        const current = frontMatter(working);
        const article = await history.history(file, 'article');
        if (!article.first || !article.latest) throw new Error('没有可推导的文章历史，请先提交');
        const assets = resolveAssets(history, file, committed.body, committed.data, sourceDir);
        let latest = article.latest;
        const dependencies = [];
        for (const dependency of assets.dependencies) {
          const event = article.lineage.has(dependency.path) ? null : dependency.directory ? await history.directory(dependency.path, article.lineage) : (await history.history(dependency.path)).latest;
          latest = newer(latest, event);
          dependencies.push({ ...dependency, source: event });
        }
        const missingDate = !Object.hasOwn(current.data, 'date');
        const published = missingDate ? moment.tz(article.first.time, zone) : parseDate(current.data.date, zone);
        const updated = moment.tz(latest.time, zone);
        if (published.valueOf() > updated.valueOf()) diagnostics.push({ file, code: 'date-after-updated', message: `date ${published.format()} 晚于 Git 更新时间 ${updated.format()}；保留原值` });
        diagnostics.push(...assets.diagnostics);
        results.push({ file, title: current.data.title, date: published.format(), updated: updated.format(), missingDate,
          first: article.first, source: latest, articleSource: article.latest, dependencies, candidates: assets.candidates });
      } catch (error) { throw new Error(`${file}: ${error.message}`, { cause: error }); }
    }
    diagnostics.push(...history.diagnostics);
    return { head: history.head, zone, articles: results, diagnostics };
  } finally { await history.close(); }
}

async function writeMissingDates(root, report) {
  const edits = [];
  for (const article of report.articles.filter(article => article.missingDate)) {
    const file = path.join(root, article.file), before = await fs.readFile(file);
    const after = insertDate(before, moment.parseZone(article.date).format('YYYY-MM-DD HH:mm:ss'));
    if (!before.equals(after)) edits.push({ file, before, after });
  }
  for (const edit of edits) if (!(await fs.readFile(edit.file)).equals(edit.before)) throw new Error(`预检后文件已被修改，停止写入：${edit.file}`);
  for (const edit of edits) await fs.writeFile(edit.file, edit.after);
  return edits.length;
}

async function applyToHexo(hexo) {
  const sourceDir = path.relative(hexo.base_dir, hexo.source_dir).replace(/\\/g, '/').replace(/\/$/, '');
  const report = await inspect(hexo.base_dir, { fetch: false, sourceDir, zone: hexo.config.timezone || 'Asia/Shanghai' });
  const byFile = new Map(report.articles.map(article => [article.file, article]));
  let skipped = 0;
  for (const post of hexo.model('Post').toArray()) {
    const file = path.relative(hexo.base_dir, post.full_source || path.join(hexo.source_dir, post.source)).replace(/\\/g, '/');
    const article = byFile.get(file);
    if (!article) { skipped++; continue; }
    // Warehouse returns document copies. Use its public update API and Date
    // instants, so Hexo's Moment schema performs exactly one conversion.
    await post.update({ date: new Date(article.date), updated: new Date(article.updated) });
  }
  hexo.locals.invalidate();
  for (const item of report.diagnostics) hexo.log.warn(`[article-timestamps] ${item.file}: ${item.message}${item.ref ? ` (引用 ${item.ref})` : ''}`);
  hexo.log.info(`[article-timestamps] ${report.articles.length} 篇文章使用 Git 时间；${skipped} 个范围外记录保持原处理；HEAD ${report.head.slice(0, 7)}`);
  return report;
}

module.exports = { inspect, writeMissingDates, applyToHexo };
