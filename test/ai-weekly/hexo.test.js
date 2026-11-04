'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const Hexo = require('hexo');
const { collectReports } = require('../../lib/ai-weekly');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blog-weekly-'));
  const cleanups = [];
  t.after(async () => {
    for (const cleanup of cleanups) await cleanup();
    const resolved = path.resolve(root);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep) || !path.basename(resolved).startsWith('blog-weekly-')) {
      throw new Error('拒绝清理临时目录外的路径');
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  return {
    root,
    write(file, content) {
      const target = path.join(root, file);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content);
    },
    beforeCleanup: callback => cleanups.push(callback)
  };
}

test('周报元数据：明确日期、合法路径与布局，不使用文件时间兜底', () => {
  const valid = {
    source: 'ai-weekly/2026-11-02/index.md', path: 'ai-weekly/2026-11-02/index.html',
    layout: 'ai-weekly', title: '第一期', published_at: '2026-11-04T12:00:00+08:00'
  };
  assert.equal(collectReports([valid]).length, 1);
  assert.equal(valid.date.toISOString(), '2026-11-04T04:00:00.000Z');
  for (const change of [
    { title: ' ' }, { published_at: undefined }, { published_at: '2026-02-30T12:00:00+08:00' },
    { published_at: '2026-11-04 12:00:00' }, { layout: 'post' },
    { path: 'other/index.html' }, { source: 'ai-weekly/page/2/index.md' }, { summary: ['不是文本'] }
  ]) {
    assert.throws(() => collectReports([{ ...valid, ...change }]), /AI 周报.*ai-weekly\//);
  }
});

test('真实 Hexo/Fluid：空栏目、倒序分页、独立详情、搜索及缓存重载', async t => {
  const f = fixture(t);
  f.write('package.json', JSON.stringify({ name: 'weekly-fixture', version: '1.0.0', hexo: { version: '8.1.2' } }));
  f.write('_config.yml', 'title: Weekly test\nurl: https://example.invalid/blog\nroot: /blog/\npermalink: :title/\ntimezone: Asia/Shanghai\nlanguage: zh-CN\ntheme: fluid\nupdated_option: date\n');
  const themeConfig = fs.readFileSync(path.resolve('_config.fluid.yml'), 'utf8');
  f.write('_config.fluid.yml', themeConfig);
  f.write('scripts/ai-weekly.js', `require(${JSON.stringify(path.resolve('lib/ai-weekly'))}).register(hexo);\n`);
  for (const [link, target] of [
    ['themes/fluid', path.dirname(require.resolve('hexo-theme-fluid/package.json'))],
    ['node_modules', path.resolve('node_modules')]
  ]) {
    const full = path.join(f.root, link);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.symlinkSync(target, full, 'junction');
    f.beforeCleanup(() => fs.unlinkSync(full));
  }
  f.write('source/_posts/older.md', '---\ntitle: Ordinary older\ndate: 2020-01-01\ncategories: [OriginalCategory]\ntags: [OriginalTag]\n---\n普通文章旧文\n');
  f.write('source/_posts/newer.md', '---\ntitle: Ordinary newer\ndate: 2020-01-02\ncategories: [OriginalCategory]\ntags: [OriginalTag]\n---\n普通文章新文\n');
  let hexo;
  const init = async () => {
    hexo = new Hexo(f.root, { silent: true });
    await hexo.init();
    for (const name of ['hexo-renderer-marked', 'hexo-renderer-ejs', 'hexo-renderer-stylus', 'hexo-generator-index', 'hexo-generator-archive', 'hexo-generator-category', 'hexo-generator-tag']) {
      await hexo.loadPlugin(require.resolve(name));
    }
  };
  f.beforeCleanup(() => hexo.exit());
  await init();
  const read = file => fs.readFileSync(path.join(f.root, 'public', file), 'utf8');
  await hexo.call('generate', { force: true });
  assert.match(read('ai-weekly/index.html'), /暂无周报/);
  assert.match(read('index.html'), /href="\/blog\/ai-weekly\/"/);
  const ordinaryPages = ['index.html', 'archives/index.html', 'categories/OriginalCategory/index.html', 'tags/OriginalTag/index.html', 'older/index.html', 'newer/index.html'];
  const before = ordinaryPages.map(read);
  const report = day => `---\nlayout: ai-weekly\ntitle: WeeklyIssue${day}\npublished_at: "2026-11-${String(day).padStart(2, '0')}T12:00:00+08:00"\nsummary: "本期摘要 <纯文本>"\ncategories: [WeeklyCategory]\ntags: [WeeklyTag]\n---\n## 本期要点\n\n正文关键词WeeklySearch${day}\n\n![配图](./cover.svg)\n`;
  for (let day = 1; day <= 11; day++) {
    const content = day === 1 ? report(day).replace('summary:', 'indexing: false\nsummary:') : report(day);
    f.write(`source/ai-weekly/issue-${day}/index.md`, content);
  }
  f.write('source/ai-weekly/issue-11/cover.svg', '<svg xmlns="http://www.w3.org/2000/svg"/>');
  await hexo.call('generate', { force: true });
  const list = read('ai-weekly/index.html');
  assert.ok(list.indexOf('WeeklyIssue11') < list.indexOf('WeeklyIssue10'));
  assert.doesNotMatch(list, />WeeklyIssue1</);
  assert.match(list, /href="\/blog\/ai-weekly\/page\/2\//);
  assert.match(list, /&lt;纯文本&gt;/);
  assert.match(read('ai-weekly/page/2/index.html'), />WeeklyIssue1</);
  assert.doesNotMatch(read('ai-weekly/page/2/index.html'), />WeeklyIssue2</);
  const detail = read('ai-weekly/issue-11/index.html');
  assert.match(detail, /本期内容由 AI 生成/);
  assert.match(detail, /2026-11-11 12:00/);
  assert.match(detail, /正文关键词WeeklySearch11/);
  assert.match(detail, /class="markdown-body"/);
  assert.match(detail, /返回 AI 周报/);
  assert.equal((detail.match(/id="board"/g) || []).length, 1);
  assert.doesNotMatch(detail, /post-prevnext/);
  assert.equal(fs.existsSync(path.join(f.root, 'public/ai-weekly/issue-11/cover.svg')), true);
  for (let i = 0; i < ordinaryPages.length; i++) assert.equal(read(ordinaryPages[i]), before[i], ordinaryPages[i]);
  assert.equal(hexo.model('Post').length, 2);
  assert.equal(fs.existsSync(path.join(f.root, 'public/categories/WeeklyCategory/index.html')), false);
  assert.equal(fs.existsSync(path.join(f.root, 'public/tags/WeeklyTag/index.html')), false);
  const verifySearch = () => {
    const xml = read('local-search.xml');
    assert.equal((xml.match(/<title>WeeklyIssue11<\/title>/g) || []).length, 1);
    assert.match(xml, /<url>\/blog\/ai-weekly\/issue-11\/index.html<\/url>/);
    assert.match(xml, /WeeklySearch11|RevisedWeeklySearch/);
    assert.match(xml, /Ordinary newer/);
    assert.doesNotMatch(xml, /<title>WeeklyIssue1<\/title>/);
  };
  verifySearch();
  f.write('source/ai-weekly/issue-11/index.md', report(11).replace('WeeklySearch11', 'RevisedWeeklySearch'));
  await hexo.call('generate', { force: true });
  verifySearch();
  assert.match(read('local-search.xml'), /RevisedWeeklySearch/);
  await hexo.exit();
  await init();
  await hexo.call('generate', { force: true });
  verifySearch();
  assert.match(read('ai-weekly/index.html'), /WeeklyIssue11/);
  f.write('source/ai-weekly/broken/index.md', '---\nlayout: ai-weekly\ntitle: Broken\n---\n缺少发布时间\n');
  await assert.rejects(hexo.call('generate', { force: true }), /AI 周报.*broken/);
});
