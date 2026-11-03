'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { sameArticle, sameAsset, insertDate, parseDate, frontMatter } = require('../../lib/article-timestamps/content');
const { references } = require('../../lib/article-timestamps/assets');

test('只排除时间维护、缺失标题补齐和 CRLF，不排除正文空白或既有标题变更', () => {
  const body = '# 标题\n\n正文  \n下一行\n';
  const a = '---\ntags: [java]\n---\n' + body;
  const b = '---\ntags: [java]\ndate: 2020-01-01\nupdated: 2025-01-01\ntitle: 标题\n---\n' + body;
  assert.equal(sameArticle(a, b.replace(/\n/g, '\r\n')), true);
  assert.equal(sameArticle(b, b.replace('title: 标题', 'title: 标题 TODO')), false);
  assert.equal(sameArticle(a, b.replace('正文  ', '正文 ')), false);
  assert.equal(sameArticle(a, b.replace('[java]', '[go]')), false);
  assert.equal(sameArticle(body, '---\ndate: 2020-01-01\n---\n' + body), true);
  assert.equal(sameArticle('---\ntitle: null\n---\n' + body, '---\ntitle: 标题\n---\n' + body), true);
  assert.equal(sameArticle(b.replace('title: 标题', 'title: 标题 TODO'), b), false);
  assert.equal(sameArticle(a, b.replace('下一行', '改错字')), false);
});

test('文本附件统一换行，二进制附件不转换', () => {
  assert.equal(sameAsset(Buffer.from('a\r\nb'), Buffer.from('a\nb'), 'hello.java'), true);
  assert.equal(sameAsset(Buffer.from('a\r\nb'), Buffer.from('a\nb'), 'hello.jar'), false);
  assert.equal(sameAsset(Buffer.from([0, 13, 10]), Buffer.from([0, 10]), 'unknown'), false);
  assert.equal(sameAsset(Buffer.from([0xd6, 0xd0, 13, 10]), Buffer.from([0xd6, 0xd0, 10]), 'Legacy.java'), true);
});

test('date 写入保留 BOM、CRLF、原正文及元数据，重复执行不变', () => {
  for (const original of ['正文\r\n', '\uFEFF---\r\ntitle: 名称\r\n---\r\n正文\r\n', '---\ntags: [java]\n---\n正文\n', '']) {
    const input = Buffer.from(original), output = insertDate(input, '2020-01-01 12:00:00');
    assert.equal(frontMatter(output).data.date, '2020-01-01 12:00:00');
    assert.equal(sameArticle(input, output), true);
    assert.deepEqual(insertDate(output, '2025-01-01 00:00:00'), output);
    assert.equal(output.toString().replace(/date: 2020-01-01 12:00:00\r?\n/, '').includes('title: 名称'), original.includes('title: 名称'));
  }
});

test('显式时区与无时区 date 的含义一致，拒绝无效日期', () => {
  assert.equal(parseDate('2020-01-01 12:00:00').format(), '2020-01-01T12:00:00+08:00');
  assert.equal(parseDate('2020-01-01T04:00:00Z').format(), '2020-01-01T12:00:00+08:00');
  assert.throws(() => parseDate('2020-02-31'), /无法解析/);
  assert.throws(() => parseDate(null), /date/);
});

test('按 Markdown/HTML 语法识别附件，跳过代码块、行内代码和 pre/code 内容', () => {
  const text = [
    '![图片](文章名/图.png)', '[文件](code/Main.java)', '![引用][img]', '[img]: /images/shared.png',
    '<img src="hello%20world.png?x=1&amp;y=2"><a href="file.zip">下载</a>',
    '`![假图片](fake.png)`', '```html\n<img src="fake2.png">\n```',
    '<pre><img src="fake3.png"></pre>', '<code><img src="fake4.png"></code>',
    '<img srcset="a.png 1x, b.png 2x">'
  ].join('\n\n');
  const refs = references(text).map(item => item.ref);
  for (const expected of ['文章名/图.png', 'code/Main.java', '/images/shared.png', 'hello%20world.png?x=1&y=2', 'file.zip', 'a.png', 'b.png']) assert.ok(refs.includes(expected), expected);
  assert.equal(refs.some(ref => /fake/.test(ref)), false);
});
