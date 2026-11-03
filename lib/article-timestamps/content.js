'use strict';

const { yaml, moment } = require('./dependencies');
const BINARY = /\.(?:png|jpe?g|gif|webp|ico|avif|bmp|pdf|zip|7z|rar|gz|jar|class|exe|dll|so|woff2?|ttf|mp[34]|wav|ogg|bin)$/i;
const TEXT = /\.(?:txt|md|java|kt|kts|c|cpp|h|hpp|cs|go|rs|py|rb|php|js|jsx|ts|tsx|json|xml|html?|css|scss|less|ya?ml|toml|ini|properties|sql|sh|bat|cmd|ps1|gradle|vue)$/i;

function frontMatter(input) {
  const text = (Buffer.isBuffer(input) ? input.toString('utf8') : input).replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  const match = /^---[^\S\n]*\n([\s\S]*?)^---[^\S\n]*(?:\n|$)/m.exec(text);
  if (!match || match.index !== 0) return { data: {}, body: text, text, header: null };
  const data = yaml.load(match[1], { schema: yaml.JSON_SCHEMA }) ?? {};
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error('文章 YAML 头必须是字段映射');
  return { data, body: text.slice(match[0].length), text, header: match[0] };
}

function emptyTitle(value) {
  return value == null || (typeof value === 'string' && !value.trim());
}

function effectiveData(data, omitTitle) {
  return Object.fromEntries(Object.entries(data).filter(([key]) => !['date', 'updated'].includes(key) && !(omitTitle && key === 'title')));
}

function sameArticle(before, after) {
  const a = frontMatter(before), b = frontMatter(after);
  const titleFill = emptyTitle(a.data.title) && !emptyTitle(b.data.title);
  // Empty/null title and no title have the same meaning for title maintenance.
  const omitTitle = titleFill || (emptyTitle(a.data.title) && emptyTitle(b.data.title));
  return a.body === b.body && JSON.stringify(effectiveData(a.data, omitTitle)) === JSON.stringify(effectiveData(b.data, omitTitle));
}

function sameAsset(before, after, file) {
  if (before.equals(after)) return true;
  if (BINARY.test(file) || before.includes(0) || after.includes(0)) return false;
  // Legacy Windows code attachments may be GBK, rather than UTF-8. For known
  // text formats compare bytes after CRLF normalization, without transcoding.
  if (TEXT.test(file)) return before.toString('latin1').replace(/\r\n/g, '\n') === after.toString('latin1').replace(/\r\n/g, '\n');
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    return decoder.decode(before).replace(/\r\n/g, '\n') === decoder.decode(after).replace(/\r\n/g, '\n');
  } catch { return false; }
}

function parseDate(value, zone = 'Asia/Shanghai') {
  if (typeof value !== 'string') throw new Error(`date 必须是有效日期字符串，实际为 ${JSON.stringify(value)}`);
  const hasZone = /(?:Z|[+-]\d\d:?\d\d)$/i.test(value);
  const date = hasZone
    ? moment.parseZone(value, moment.ISO_8601, true)
    : moment.tz(value, ['YYYY-MM-DD HH:mm:ss', 'YYYY-MM-DD HH:mm', 'YYYY-MM-DD', 'YYYY-MM-DDTHH:mm:ss', 'YYYY-MM-DDTHH:mm:ss.SSS'], true, zone);
  if (!date.isValid()) throw new Error(`无法解析 date: ${value}`);
  return date.tz(zone);
}

function insertDate(input, value) {
  const text = input.toString('utf8');
  const fm = frontMatter(text);
  if (Object.hasOwn(fm.data, 'date')) return input;
  const bom = text.startsWith('\uFEFF') ? '\uFEFF' : '';
  const source = text.slice(bom.length);
  const eol = source.includes('\r\n') ? '\r\n' : '\n';
  const head = /^---[^\S\r\n]*\r?\n[\s\S]*?^---[^\S\r\n]*(?:\r?\n|$)/m.exec(source);
  if (head?.index === 0) {
    const close = head[0].lastIndexOf('---');
    return Buffer.from(bom + source.slice(0, close) + `date: ${value}${eol}` + source.slice(close));
  }
  return Buffer.from(bom + `---${eol}date: ${value}${eol}---${eol}` + source);
}

module.exports = { frontMatter, sameArticle, sameAsset, parseDate, insertDate };
