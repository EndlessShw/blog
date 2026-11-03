'use strict';

const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const { sameArticle, sameAsset } = require('./content');
const exec = promisify(execFile);

async function git(root, args, options = {}) {
  try {
    const { stdout } = await exec('git', ['-c', 'core.quotepath=false', ...args], {
      cwd: root, windowsHide: true, maxBuffer: 64 * 1024 * 1024, encoding: 'utf8',
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_NO_REPLACE_OBJECTS: '1' }, ...options
    });
    return stdout;
  } catch (error) {
    throw new Error(`Git ${args[0]} 失败：${String(error.stderr || error.message).trim()}`, { cause: error });
  }
}

async function prepareHistory(root, { fetch = true } = {}) {
  await git(root, ['rev-parse', '--show-toplevel']);
  const head = (await git(root, ['rev-parse', 'HEAD'])).trim();
  if ((await git(root, ['rev-parse', '--is-shallow-repository'])).trim() === 'true') {
    if (!fetch) throw new Error('Git 历史不完整：请联网执行 git fetch --unshallow origin，再重新构建');
    try {
      await git(root, ['-c', 'http.sslVerify=true', 'fetch', '--unshallow', '--no-tags', 'origin'], { timeout: 120000 });
    } catch (error) {
      throw new Error('无法补齐 Git 历史；请检查 origin 访问权限，执行 git fetch --unshallow origin 后重试。' + error.message, { cause: error });
    }
    if ((await git(root, ['rev-parse', '--is-shallow-repository'])).trim() !== 'false') throw new Error('补齐后 Git 历史仍不完整，停止生成日期');
  }
  if ((await git(root, ['rev-parse', 'HEAD'])).trim() !== head) throw new Error('历史准备期间 HEAD 发生变化，请重新构建');
  return head;
}

// A single batch process reads all requested blobs, including binary files.
class BlobReader {
  constructor(root) {
    this.process = spawn('git', ['cat-file', '--batch'], { cwd: root, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, GIT_NO_REPLACE_OBJECTS: '1' } });
    this.closed = new Promise(resolve => this.process.once('close', resolve));
    this.pending = []; this.buffer = Buffer.alloc(0); this.cache = new Map(); this.failure = null;
    this.process.stdout.on('data', chunk => { this.buffer = Buffer.concat([this.buffer, chunk]); this.drain(); });
    this.process.on('error', error => this.fail(error));
    this.process.on('close', code => { if (code || this.pending.length) this.fail(new Error(`git cat-file 异常退出 (${code})`)); });
    this.process.stderr.resume();
  }
  fail(error) { this.failure = error; for (const request of this.pending.splice(0)) request.reject(error); }
  drain() {
    while (this.pending.length) {
      const newline = this.buffer.indexOf(10);
      if (newline < 0) return;
      const header = this.buffer.subarray(0, newline).toString('ascii');
      const match = /^[a-f0-9]+ blob (\d+)$/.exec(header);
      if (!match) { this.fail(new Error(`无法读取 Git blob：${header}`)); return; }
      const size = Number(match[1]), end = newline + 1 + size;
      if (this.buffer.length < end + 1) return;
      const data = Buffer.from(this.buffer.subarray(newline + 1, end));
      this.buffer = this.buffer.subarray(end + 1);
      this.pending.shift().resolve(data);
    }
  }
  get(oid) {
    if (this.failure) return Promise.reject(this.failure);
    if (!this.cache.has(oid)) this.cache.set(oid, new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject }); this.process.stdin.write(`${oid}\n`);
    }));
    return this.cache.get(oid);
  }
  close() { this.process.stdin.end(); return this.closed; }
}

function parseRaw(raw) {
  const parts = raw.split('\0'), changes = [];
  for (let i = 0; i < parts.length;) {
    const header = parts[i++];
    if (!header) continue;
    const match = /^:(\d+) (\d+) ([a-f0-9]+) ([a-f0-9]+) ([A-Z])\d*$/.exec(header);
    if (!match) throw new Error(`无法解析 Git diff 元数据：${header.slice(0, 120)}`);
    const [, oldMode, mode, oldOid, oid, status] = match;
    const oldPath = parts[i++], file = ['R', 'C'].includes(status) ? parts[i++] : oldPath;
    changes.push({ oldMode, mode, oldOid, oid, status, oldPath, path: file });
  }
  return changes;
}

function newer(a, b) { return !a ? b : !b ? a : a.time >= b.time ? a : b; }
function older(a, b) { return !a ? b : !b ? a : a.time <= b.time ? a : b; }

class GitHistory {
  static async open(root, options) {
    const head = await prepareHistory(root, options);
    const history = new GitHistory(root, head);
    try { await history.load(); return history; } catch (error) { await history.close(); throw error; }
  }
  constructor(root, head) {
    this.root = root; this.head = head; this.commits = new Map(); this.paths = new Set();
    this.gitlinks = new Set();
    this.memo = new Map(); this.equality = new Map(); this.blobs = new BlobReader(root); this.diagnostics = [];
  }
  async load() {
    const log = await git(this.root, ['log', '--reverse', '--topo-order', '--format=%H%x00%P%x00%cI', this.head]);
    for (const line of log.trim().split('\n')) {
      const [sha, parents, iso] = line.split('\0');
      const commit = { sha, parents: parents ? parents.split(' ') : [], iso, time: Date.parse(iso), edges: [], tree: new Map() };
      if (!Number.isFinite(commit.time)) throw new Error(`无效提交时间：${sha}`);
      if (commit.parents.length) commit.tree = new Map(this.commits.get(commit.parents[0]).tree);
      // Diff every parent, so pure merges inherit the source branch's dates.
      for (const parent of commit.parents.length ? commit.parents : [null]) {
        const args = ['diff-tree', '--no-commit-id', '--raw', '--no-abbrev', '-r', '-z', '-M', '-l0'];
        args.push(...(parent ? [parent, sha] : ['--root', sha]));
        const changes = parseRaw(await git(this.root, args));
        const edge = { parent, changes, incoming: new Map(), outgoing: new Map() };
        for (const change of changes) {
          edge.incoming.set(change.path, change); edge.outgoing.set(change.oldPath, change);
          this.paths.add(change.oldPath); this.paths.add(change.path);
          if (change.oldMode === '160000') this.gitlinks.add(change.oldPath);
          if (change.mode === '160000') this.gitlinks.add(change.path);
        }
        commit.edges.push(edge);
      }
      for (const change of commit.edges[0].changes) {
        if (change.status === 'R' || change.status === 'D') commit.tree.delete(change.oldPath);
        if (change.status !== 'D') commit.tree.set(change.path, { oid: change.oid, mode: change.mode });
      }
      this.commits.set(sha, commit);
    }
    this.tree = this.commits.get(this.head).tree;
  }
  close() { return this.blobs.close(); }
  async content(file, sha = this.head) {
    const entry = this.commits.get(sha).tree.get(file);
    if (!entry || entry.mode === '160000') return null;
    return this.blobs.get(entry.oid);
  }
  async equal(before, after, kind, file) {
    if (!before || !after) return before === after;
    if (before.oid === after.oid) return true;
    if (before.mode === '160000' || after.mode === '160000') return false;
    const key = `${kind}:${file}:${before.oid}:${after.oid}`;
    if (!this.equality.has(key)) this.equality.set(key, (async () => {
      const [a, b] = await Promise.all([this.blobs.get(before.oid), this.blobs.get(after.oid)]);
      return kind === 'article' ? sameArticle(a, b) : sameAsset(a, b, file);
    })());
    return this.equality.get(key);
  }
  history(file, kind = 'asset', sha = this.head) {
    const key = `${sha}:${kind}:${file}`;
    if (!this.memo.has(key)) this.memo.set(key, this.trace(file, kind, sha));
    return this.memo.get(key);
  }
  async trace(file, kind, sha) {
    const commit = this.commits.get(sha), current = commit.tree.get(file);
    const inherited = [];
    for (const edge of commit.edges) {
      if (!edge.parent) continue;
      const parent = this.commits.get(edge.parent);
      const change = edge.incoming.get(file), outgoing = edge.outgoing.get(file);
      let previousPath = change?.status === 'R' ? change.oldPath : file;
      let previous = parent.tree.get(previousPath), compared = current;
      // A rename out of a dependency path is not itself a deletion of content.
      if (!current && outgoing?.status === 'R') compared = commit.tree.get(outgoing.path);
      // Git's similarity detection may miss an exact/CRLF-only move. Recover only
      // an unambiguous deleted source; never guess an identity by its filename.
      if (!previous && current && change?.status === 'A') {
        const candidates = [];
        for (const deleted of edge.changes.filter(item => item.status === 'D')) {
          if (await this.equal(parent.tree.get(deleted.oldPath), current, kind, file)) candidates.push(deleted.oldPath);
        }
        if (candidates.length === 1) { previousPath = candidates[0]; previous = parent.tree.get(previousPath); }
        else if (candidates.length > 1) this.diagnostics.push({ file, code: 'ambiguous-rename', message: `提交 ${sha.slice(0, 7)} 有多个内容相同的删除源，无法确认重命名身份` });
      }
      const equal = await this.equal(previous, compared, kind, file);
      inherited.push({ equal, previous, result: await this.history(previousPath, kind, edge.parent) });
    }
    // If the merge result is already present in a parent, the merge did not
    // introduce content. Follow matching parents instead of dating the merge.
    const matching = inherited.filter(item => item.equal);
    const sources = matching.length ? matching : inherited;
    let latest = null, first = null;
    for (const source of sources) { latest = newer(latest, source.result.latest); first = older(first, source.result.first); }
    const changed = !matching.length && (current || inherited.some(item => item.previous));
    if (changed) {
      const event = { sha, time: commit.time, iso: commit.iso, path: file };
      latest = newer(latest, event); first ??= event;
    }
    if (kind === 'article') {
      const lineage = new Set([file]);
      for (const source of sources) for (const alias of source.result.lineage) lineage.add(alias);
      return { latest, first, lineage };
    }
    return { latest, first };
  }
  async directory(prefix, excludedPaths = new Set()) {
    const results = await Promise.all([...this.paths].filter(file => file.startsWith(prefix) && !excludedPaths.has(file)).map(file => this.history(file)));
    return results.reduce((latest, result) => newer(latest, result.latest), null);
  }
}

module.exports = { git, prepareHistory, GitHistory, newer };
