'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { GitHistory, prepareHistory } = require('../../lib/article-timestamps/git');
const { inspect, writeMissingDates } = require('../../lib/article-timestamps');
const { fixture } = require('./fixtures');

test('真实历史：时间/标题维护、CRLF 和移动不更新；已有标题、正文及标签修改更新', async t => {
  const f = fixture(t), original = 'source/_posts/中文 空格/旧名.md', renamed = 'source/_posts/中文 空格/新名.md';
  const body = '# 标题\n\n正文  \n';
  f.write(original, body); const first = f.commit(1);
  f.write(original, '---\ndate: 2020-01-01 12:00:00\n---\n' + body); f.commit(2);
  f.write(original, '---\ndate: 2020-01-01 12:00:00\ntitle: 标题 TODO\n---\n' + body); f.commit(3);
  f.write(original, fs.readFileSync(path.join(f.root, original), 'utf8').replace(/\n/g, '\r\n')); f.commit(4);
  f.git(['mv', original, renamed]); f.commit(5);
  let h = await GitHistory.open(f.root);
  try { const r = await h.history(renamed, 'article'); assert.equal(r.first.sha, first); assert.equal(r.latest.sha, first); } finally { await h.close(); }
  f.write(renamed, '---\ndate: 2020-01-01 12:00:00\ntitle: 正式标题\n---\n' + body); const title = f.commit(6);
  let r = await inspect(f.root); assert.equal(r.articles[0].source.sha, title);
  f.write(renamed, '---\ndate: 2020-01-01 12:00:00\ntitle: 正式标题\ntags: [java]\n---\n' + body); const tag = f.commit(7);
  r = await inspect(f.root); assert.equal(r.articles[0].source.sha, tag);
  f.write(renamed, fs.readFileSync(path.join(f.root, renamed), 'utf8').replace('正文  ', '正文 ')); const layout = f.commit(8);
  r = await inspect(f.root); assert.equal(r.articles[0].source.sha, layout);
  assert.equal(r.articles[0].date, '2020-01-01T12:00:00+08:00');
});

test('附件：共享图片、显式工程的修改/删除；不计同级无归属文件和未提交编辑', async t => {
  const f = fixture(t), article = 'source/_posts/文章.md', other = 'source/_posts/另一篇.md';
  f.write(article, '---\ndate: 2020-01-01 12:00:00\nupdated: 2099-01-01\nupdated_assets: [code/project/]\n---\n![图片](/img/shared.png)\n');
  f.write(other, '---\ndate: 2020-01-01 12:00:00\n---\n<img src="/img/shared.png">\n');
  f.write('source/img/shared.png', Buffer.from([0, 1])); f.write('source/_posts/code/project/Main.java', 'class A {}\n');
  f.write('source/_posts/code/project/Main.class', Buffer.from([0, 1])); const first = f.commit(1);
  f.write('source/_posts/unrelated.txt', '无归属'); f.commit(2);
  let r = await inspect(f.root); assert.ok(r.articles.every(a => a.source.sha === first));
  f.write('source/img/shared.png', Buffer.from([0, 2])); const image = f.commit(3);
  r = await inspect(f.root); assert.ok(r.articles.every(a => a.source.sha === image));
  f.remove('source/_posts/code/project/Main.java'); const deletion = f.commit(4);
  r = await inspect(f.root); assert.equal(r.articles.find(a => a.file === article).source.sha, deletion);
  assert.equal(r.articles.find(a => a.file === other).source.sha, image);
  f.write('source/_posts/code/project/Main.class', Buffer.from([0, 3])); const binary = f.commit(5);
  r = await inspect(f.root); assert.equal(r.articles.find(a => a.file === article).source.sha, binary);
  f.remove('source/_posts/code/project/Main.class'); const empty = f.commit(6);
  f.write(article, fs.readFileSync(path.join(f.root, article), 'utf8') + '未提交正文\n');
  f.write('source/img/shared.png', Buffer.from([0, 9]));
  r = await inspect(f.root); assert.equal(r.articles.find(a => a.file === article).source.sha, empty);
  assert.ok(r.diagnostics.some(d => d.code === 'missing-directory'));
});

test('被删除引用保留删除提交；纯附件重命名和目录移动不更新', async t => {
  const f = fixture(t), article = 'source/_posts/a.md';
  f.write(article, '---\ndate: 2020-01-01 12:00:00\nupdated_assets: [code/old/]\n---\n![图片](/img/a.png)\n');
  f.write('source/img/a.png', Buffer.from([0, 1])); f.write('source/_posts/code/old/A.java', 'abc\n'); const first = f.commit(1);
  f.git(['mv', 'source/_posts/code/old', 'source/_posts/code/new']); f.commit(2);
  let r = await inspect(f.root); assert.equal(r.articles[0].source.sha, first);
  f.remove('source/img/a.png'); const deletion = f.commit(3);
  r = await inspect(f.root); assert.equal(r.articles[0].source.sha, deletion);
  assert.ok(r.diagnostics.some(d => d.code === 'missing-file'));
});

test('合并已有分支内容不刷新时间，冲突解决的新内容刷新时间', async t => {
  const f = fixture(t), article = 'source/_posts/a.md';
  f.write(article, '# 最初\n'); f.commit(1);
  f.git(['checkout', '-b', 'topic']); f.write(article, '# 分支修订\n'); const branch = f.commit(2);
  f.git(['checkout', 'main']); f.write('other.txt', 'other'); f.commit(3);
  f.git(['merge', '--no-ff', 'topic', '-m', 'merge'], { GIT_AUTHOR_DATE: '2020-01-04T12:00:00+08:00', GIT_COMMITTER_DATE: '2020-01-04T12:00:00+08:00' });
  let r = await inspect(f.root); assert.equal(r.articles[0].source.sha, branch);
  f.git(['checkout', '-b', 'conflict']); f.write(article, '# 左边\n'); f.commit(5);
  f.git(['checkout', 'main']); f.write(article, '# 右边\n'); f.commit(6);
  assert.throws(() => f.git(['merge', 'conflict', '-m', 'conflict']));
  f.write(article, '# 解决后的新内容\n'); const resolved = f.commit(7);
  r = await inspect(f.root); assert.equal(r.articles[0].source.sha, resolved);
});

test('缺失 date 沿移动补齐，写入不碰 ignored HELP 或其他目录，幂等且不刷新 updated', async t => {
  const f = fixture(t), old = 'source/_posts/旧.md', current = 'source/_posts/新.md';
  f.write(old, '\uFEFF# 正文\r\n'); f.write('.gitignore', '**/HELP.md\n'); f.write('README.md', '# other'); const first = f.commit(1);
  f.git(['mv', old, current]); f.commit(2);
  f.write('source/_posts/project/HELP.md', 'ignored');
  const report = await inspect(f.root); assert.equal(report.articles.length, 1); assert.equal(report.articles[0].first.sha, first);
  assert.equal(await writeMissingDates(f.root, report), 1);
  const buffer = fs.readFileSync(path.join(f.root, current)); assert.ok(buffer.toString().startsWith('\uFEFF---\r\n'));
  const second = await inspect(f.root); assert.equal(await writeMissingDates(f.root, second), 0);
  assert.deepEqual(fs.readFileSync(path.join(f.root, current)), buffer);
  assert.equal(fs.readFileSync(path.join(f.root, 'source/_posts/project/HELP.md'), 'utf8'), 'ignored');
  f.commit(3); assert.equal((await inspect(f.root)).articles[0].source.sha, first);
  f.write('source/_posts/new.md', '# 新文章');
  await assert.rejects(inspect(f.root), /新文章尚无 Git 历史/);
  f.git(['add', 'source/_posts/new.md']);
  await assert.rejects(inspect(f.root), /新文章尚无 Git 历史/);
});

test('浅克隆补全不改 HEAD；离线失败或无 .git 明确报错', async t => {
  const source = fixture(t), clone = fixture(t);
  source.write('source/_posts/a.md', '# a'); source.commit(1); source.write('other.txt', 'b'); const head = source.commit(2);
  const remote = new URL('file:///' + source.root.replace(/\\/g, '/')).href;
  clone.git(['fetch', '--depth=1', remote, 'main']); clone.git(['checkout', '--detach', 'FETCH_HEAD']);
  clone.git(['remote', 'add', 'origin', remote]);
  await assert.rejects(prepareHistory(clone.root, { fetch: false }), /历史不完整/);
  assert.equal(await prepareHistory(clone.root), head); assert.equal(clone.git(['rev-parse', '--is-shallow-repository']), 'false');
  const withoutOrigin = fixture(t);
  withoutOrigin.git(['fetch', '--depth=1', remote, 'main']); withoutOrigin.git(['checkout', '--detach', 'FETCH_HEAD']);
  await assert.rejects(prepareHistory(withoutOrigin.root), /浅克隆缺少 origin/);
  assert.equal(await prepareHistory(withoutOrigin.root, { repositoryUrl: remote }), head);
  assert.equal(withoutOrigin.git(['rev-parse', '--is-shallow-repository']), 'false');
  assert.equal(withoutOrigin.git(['remote']), '');
  clone.git(['remote', 'set-url', 'origin', 'file:///unavailable/blog.git']);
  assert.equal(await prepareHistory(clone.root, { fetch: false }), head); // full history works offline
  const offline = fixture(t);
  offline.git(['fetch', '--depth=1', remote, 'main']); offline.git(['checkout', '--detach', 'FETCH_HEAD']);
  offline.git(['remote', 'add', 'origin', 'file:///unavailable/blog.git']);
  await assert.rejects(prepareHistory(offline.root), /无法补齐 Git 历史/);
  await assert.rejects(prepareHistory(path.dirname(source.root)), /Git rev-parse/);
});

test('移动同时转换 CRLF 时恢复内容身份，移动后的附件历史继续跟踪', async t => {
  const f = fixture(t), old = 'source/_posts/old.md', current = 'source/_posts/new.md';
  const text = '# 内容\n' + Array.from({ length: 30 }, (_, i) => `line ${i}`).join('\n') + '\n';
  f.write(old, text); const first = f.commit(1);
  f.remove(old); f.write(current, text.replace(/\n/g, '\r\n')); f.commit(2);
  let report = await inspect(f.root); assert.equal(report.articles[0].source.sha, first); assert.equal(report.articles[0].first.sha, first);
  f.write(current, text.replace('line 0', '修改内容')); const changed = f.commit(3);
  report = await inspect(f.root); assert.equal(report.articles[0].source.sha, changed);
});

test('gitlink 只比较父仓库版本；无效 date 报路径，date 晚于 updated 只报告不改写', async t => {
  const f = fixture(t), article = 'source/_posts/a.md', link = 'source/_posts/project';
  f.write(article, '---\ndate: 2020-01-05 12:00:00\nupdated_assets: [project/]\n---\n# a\n[源码](project/A.java)\n'); const first = f.commit(1);
  f.git(['update-index', '--add', '--cacheinfo', `160000,${first},${link}`]); const linked = f.commit(2, 'gitlink', false);
  let report = await inspect(f.root); assert.equal(report.articles[0].source.sha, linked);
  assert.ok(report.diagnostics.some(d => d.code === 'date-after-updated'));
  f.git(['update-index', '--cacheinfo', `160000,${linked},${link}`]); const version = f.commit(3, 'gitlink update', false);
  report = await inspect(f.root); assert.equal(report.articles[0].source.sha, version);
  f.git(['update-index', '--force-remove', link]); const deleted = f.commit(4, 'gitlink delete', false);
  report = await inspect(f.root); assert.equal(report.articles[0].source.sha, deleted);
  assert.ok(report.articles[0].dependencies.some(d => d.path === link && !d.directory));
  f.write(article, '---\ndate: invalid\n---\n# a\n');
  await assert.rejects(inspect(f.root), /source\/_posts\/a.md.*无法解析 date/);
});

test('文章资源目录、站点根、中文编码、Windows 路径和仓库边界', async t => {
  const f = fixture(t), article = 'source/_posts/中文.md';
  f.write(article, '# 正文\n![a](中文/空%20格.png?size=2#x)\n<img src="图\\图片.png">\n[代码](code/Main.java)\n![root](/images/shared.png)\n[外链](https://example.invalid/file.zip)\n![越界](../../../../private.png)\n![失效](lost.png)\n');
  f.write('source/_posts/中文/空 格.png', Buffer.from([0, 1])); f.write('source/_posts/中文/图/图片.png', Buffer.from([0, 1]));
  f.write('source/_posts/code/Main.java', 'abc'); f.write('source/images/shared.png', Buffer.from([0, 1])); f.commit(1);
  const report = await inspect(f.root), deps = report.articles[0].dependencies;
  for (const expected of ['source/_posts/中文/空 格.png', 'source/_posts/中文/图/图片.png', 'source/_posts/code/Main.java', 'source/images/shared.png']) assert.ok(deps.some(d => d.path === expected), expected);
  assert.equal(deps.some(d => /example.invalid/.test(d.path)), false);
  assert.ok(report.diagnostics.some(d => d.code === 'outside-repository'));
  assert.ok(report.diagnostics.some(d => d.code === 'untracked-file'));
});

test('文章自引用或声明自身所在目录，仍不能使补 date/title 算成更新', async t => {
  const f = fixture(t), file = 'source/_posts/a.md';
  const before = '---\nupdated_assets: [./]\n---\n[本文](./a.md#正文)\n# 正文\n';
  f.write(file, before); const first = f.commit(1);
  f.write(file, before.replace('updated_assets:', 'date: 2020-01-01 12:00:00\ntitle: 补齐标题\nupdated_assets:')); f.commit(2);
  let report = await inspect(f.root); assert.equal(report.articles[0].source.sha, first);
  f.git(['mv', file, 'source/_posts/b.md']); f.commit(3);
  report = await inspect(f.root); assert.equal(report.articles[0].source.sha, first);
});
