'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'blog-timestamps-'));
  const cleanups = [];
  t.after(async () => {
    for (const cleanup of cleanups) await cleanup();
    const resolved = path.resolve(root), base = path.resolve(os.tmpdir()) + path.sep;
    if (!resolved.startsWith(base) || !path.basename(resolved).startsWith('blog-timestamps-')) throw new Error('拒绝清理临时目录外的路径');
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const git = (args, env = {}) => execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'commit.gpgSign=false', ...args], {
    cwd: root, windowsHide: true, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', ...env }
  }).trim();
  git(['init', '--initial-branch=main']);
  git(['config', 'user.name', 'Timestamp Test']); git(['config', 'user.email', 'timestamp-test@example.invalid']);
  git(['config', 'core.hooksPath', path.join(root, '.no-hooks')]);
  const write = (file, content) => { fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true }); fs.writeFileSync(path.join(root, file), content); };
  const commit = (day, message = 'content', stage = true) => {
    if (stage) git(['add', '-A']);
    const date = `2020-01-${String(day).padStart(2, '0')}T12:00:00+08:00`;
    git(['commit', '--allow-empty', '-m', message], { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date });
    return git(['rev-parse', 'HEAD']);
  };
  return { root, git, write, commit, beforeCleanup: callback => cleanups.push(callback), remove: file => fs.unlinkSync(path.join(root, file)) };
}

module.exports = { fixture };
