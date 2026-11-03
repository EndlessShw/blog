'use strict';

const path = require('node:path').posix;
const fs = require('node:fs');
const { marked, html } = require('./dependencies');

function references(body) {
  const result = [], lexer = new marked.Lexer({ ...marked.getDefaults(), gfm: true, pedantic: false });
  let ignored = 0;
  const reader = new html.Parser({
      onopentag(tag, attributes) {
        if (['pre', 'code', 'script', 'style'].includes(tag)) ignored++;
        if (ignored) return;
        const keys = tag === 'a' ? ['href'] : ['img', 'source', 'audio', 'video', 'track', 'iframe', 'embed', 'input'].includes(tag) ? ['src', 'poster'] : tag === 'object' ? ['data'] : [];
        for (const key of keys) if (attributes[key]) result.push({ ref: attributes[key], image: tag === 'img' });
        if (['img', 'source'].includes(tag) && attributes.srcset) {
          for (const item of attributes.srcset.split(',')) result.push({ ref: item.trim().split(/\s+/)[0], image: true });
        }
      },
      onclosetag(tag) { if (['pre', 'code', 'script', 'style'].includes(tag)) ignored = Math.max(0, ignored - 1); }
    }, { decodeEntities: true });
  marked.walkTokens(lexer.lex(body), token => {
    if (!ignored && (token.type === 'image' || token.type === 'link')) result.push({ ref: token.href, image: token.type === 'image' });
    if (token.type === 'html') reader.write(token.text);
  });
  reader.end();
  return result;
}

function safePath(base, ref) {
  const target = path.normalize(path.join(base, ref));
  return target === '..' || target.startsWith('../') || path.isAbsolute(target) ? null : target.replace(/\/$/, '');
}

function resolveAssets(history, article, body, data, sourceDir = 'source') {
  const dependencies = new Map(), diagnostics = [], candidates = [];
  const addDiagnostic = (ref, code, message) => diagnostics.push({ file: article, ref, code, message });
  const directory = path.dirname(article), assetDir = article.replace(/\.[^.]+$/, '');
  const submodules = [...history.gitlinks];
  const known = file => history.paths.has(file) || submodules.some(prefix => file.startsWith(prefix + '/'));
  function add(ref, { explicit = false, image = false } = {}) {
    if (typeof ref !== 'string' || !ref.trim()) { addDiagnostic(String(ref), 'invalid-reference', '附件路径必须是非空字符串'); return; }
    const original = ref;
    if (/^[a-z]:[\\/]/i.test(ref)) { addDiagnostic(ref, 'outside-repository', '本机绝对路径不属于仓库附件'); return; }
    if (/^(?:[a-z][a-z\d+.-]*:|\/\/|#)/i.test(ref)) {
      if (explicit) addDiagnostic(ref, 'invalid-declaration', 'updated_assets 只允许仓库内相对路径');
      return;
    }
    ref = ref.split(/[?#]/)[0];
    if (!ref) return;
    try { ref = decodeURIComponent(ref); } catch { addDiagnostic(original, 'invalid-url', '路径包含无效 URL 编码'); return; }
    ref = ref.replace(/\\/g, '/');
    const isDirectory = explicit && ref.endsWith('/');
    let choices;
    if (explicit) {
      if (ref.startsWith('/')) { addDiagnostic(original, 'invalid-declaration', '声明路径必须相对于文章所在目录'); return; }
      choices = [safePath(directory, ref)];
    } else if (ref.startsWith('/')) choices = [safePath(sourceDir, ref.replace(/^\/+/, ''))];
    else {
      const relative = safePath(directory, ref), asset = safePath(assetDir, ref);
      const prefixed = ref.startsWith(path.basename(assetDir) + '/') || ref.startsWith(path.basename(assetDir) + '.assets/');
      choices = image && !ref.startsWith('.') && !prefixed ? [asset, relative] : [relative, asset];
    }
    choices = [...new Set(choices.filter(Boolean))];
    if (!choices.length) { addDiagnostic(original, 'outside-repository', '解析后的路径越出仓库'); return; }
    const exists = file => history.tree.has(file) || (isDirectory && [...history.tree.keys()].some(item => item.startsWith(file + '/')));
    let resolved = choices.find(exists) || choices.find(file => known(file) || (isDirectory && [...history.paths].some(item => item.startsWith(file + '/'))));
    resolved ||= choices.find(file => fs.existsSync(path.join(history.root.replace(/\\/g, '/'), file))) || choices[0];
    const submodule = submodules.find(prefix => resolved === prefix || resolved.startsWith(prefix + '/'));
    if (submodule) resolved = submodule;
    if (resolved === article && !isDirectory) return;
    const key = resolved + (isDirectory && !submodule ? '/' : '');
    dependencies.set(key, { path: key, directory: isDirectory && !submodule, ref: original, explicit });
    if (isDirectory && !submodule) {
      if (![...history.tree.keys()].some(item => item.startsWith(key))) addDiagnostic(original, 'missing-directory', `当前目录没有受 Git 管理的文件：${key}`);
    } else if (!history.tree.has(resolved)) {
      addDiagnostic(original, known(resolved) ? 'missing-file' : 'untracked-file', `${known(resolved) ? '附件已删除或移动，仍追踪其历史' : '没有可用的根仓库 Git 历史'}：${resolved}`);
    }
  }
  for (const reference of references(body)) add(reference.ref, reference);
  if (data.updated_assets != null && !Array.isArray(data.updated_assets)) throw new Error(`${article}: updated_assets 必须是路径数组`);
  for (const ref of data.updated_assets || []) add(ref, { explicit: true });
  const prefixes = new Set([...history.tree.keys()].filter(file => file.startsWith(directory + '/')).map(file => {
    const relative = file.slice(directory.length + 1);
    const match = /^(?:code|代码)\/[^/]+\//i.exec(relative);
    return match ? directory + '/' + match[0] : null;
  }).filter(Boolean));
  for (const prefix of prefixes) if (![...dependencies.keys()].some(dep => prefix.startsWith(dep) && dep.endsWith('/'))) candidates.push(path.relative(directory, prefix) + '/');
  return { dependencies: [...dependencies.values()], diagnostics, candidates };
}

module.exports = { references, resolveAssets };
