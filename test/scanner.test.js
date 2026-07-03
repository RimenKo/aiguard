'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { scan } = require('../src/scanner');

// A well-formed but fake AWS Access Key ID — matches SECRET_PATTERNS with no
// validate() step, so it's a reliable trigger for these throwaway temp repos.
const FAKE_SECRET = 'AKIAABCDEFGHIJKLMNOP'; // gitleaks:allow — fake fixture, not a real key

function makeTempProject() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aiguard-scanner-test-'));
}

function writeFile(dir, relPath, content) {
  const full = path.join(dir, relPath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

// Isolates git from the host machine's real ~/.gitconfig and
// ~/.gitignore_global — without this, a personal global excludes file (e.g.
// one that blacklists *secrets*.json for safety) can silently change which
// fixture files are "ignored" and make these tests flaky depending on whose
// machine (or CI image) runs them.
function git(dir, args) {
  execFileSync('git', args, {
    cwd: dir,
    stdio: 'pipe',
    env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' },
  });
}

function initGitRepo(dir) {
  git(dir, ['init', '--quiet']);
}

function findingsFor(findings, relFile) {
  return findings.filter((f) => f.file === relFile && f.type === 'secret_pattern');
}

// scan() spawns its own `git ls-files` internally (scanner.js's
// getGitTrackedFiles), inheriting process.env as-is — so it would otherwise
// pick up the host's real ~/.gitconfig / ~/.gitignore_global too. Same
// isolation as the git() helper above, applied around the call under test.
function scanIsolated(dir) {
  const prevGlobal = process.env.GIT_CONFIG_GLOBAL;
  const prevSystem = process.env.GIT_CONFIG_SYSTEM;
  process.env.GIT_CONFIG_GLOBAL = '/dev/null';
  process.env.GIT_CONFIG_SYSTEM = '/dev/null';
  try {
    return scan(dir);
  } finally {
    if (prevGlobal === undefined) delete process.env.GIT_CONFIG_GLOBAL; else process.env.GIT_CONFIG_GLOBAL = prevGlobal;
    if (prevSystem === undefined) delete process.env.GIT_CONFIG_SYSTEM; else process.env.GIT_CONFIG_SYSTEM = prevSystem;
  }
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok — ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL — ${name}`);
    console.error(`    ${err.message}`);
  }
}

// ── Bug 1: file tracked by git before it was added to .gitignore ───────
test('git-tracked file matched by a later .gitignore rule — secret still caught', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  // Deliberately not named like a secrets/creds file — some machines carry a
  // global core.excludesFile that blocks `git add` on such names outright,
  // which would mask what this test is actually about (a project-local
  // .gitignore rule added AFTER the file was already tracked).
  writeFile(dir, 'config/data.json', `{"key": "${FAKE_SECRET}"}`);
  git(dir, ['add', 'config/data.json']);
  // Added to .gitignore AFTER the file was already tracked — the hand-rolled
  // parser has no notion of "already tracked", so it would drop the whole
  // config/ directory from the scan.
  writeFile(dir, '.gitignore', 'config/\n');

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'config/data.json').length, 1,
    'expected the AWS key inside the git-tracked file to be reported'
  );
});

// ── Bug 2: "!pattern" negation in .gitignore ────────────────────────────
test('negated .gitignore pattern (!keep.json) — file is scanned like real git would', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, '.gitignore', '*.json\n!keep.json\n');
  // Left untracked on purpose — negation is meant to un-ignore it for
  // `git add`/`git status` before it's ever committed.
  writeFile(dir, 'keep.json', `{"key": "${FAKE_SECRET}"}`);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'keep.json').length, 1,
    'expected the AWS key inside the negated file to be reported'
  );
});

// ── Non-git project must not crash, and must fall back to old behavior ──
test('non-git directory — scan() does not throw and still finds secrets', () => {
  const dir = makeTempProject(); // no `git init` at all
  writeFile(dir, 'index.js', `const key = "${FAKE_SECRET}";`);

  let findings;
  assert.doesNotThrow(() => { findings = scanIsolated(dir); });
  assert.strictEqual(findingsFor(findings, 'index.js').length, 1);
});

// ── Normal project, no .gitignore tricks — behavior unchanged ──────────
test('ordinary project (gitignored node_modules) — ignored files stay ignored', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, '.gitignore', 'node_modules/\n');
  writeFile(dir, 'index.js', `const key = "${FAKE_SECRET}";`);
  // Never `git add`-ed and matches .gitignore — must stay out of the scan,
  // exactly like before this change.
  writeFile(dir, 'node_modules/pkg/index.js', `const key = "${FAKE_SECRET}";`);

  const findings = scanIsolated(dir);
  assert.strictEqual(findingsFor(findings, 'index.js').length, 1, 'normal source file still scanned');
  assert.strictEqual(
    findingsFor(findings, 'node_modules/pkg/index.js').length, 0,
    'gitignored, untracked node_modules must stay excluded'
  );
});

// ── npm publish semantics: node_modules is never publishable ───────────
test('npm project: unignored untracked node_modules is never reported as "will be published"', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg', version: '1.0.0' }));
  writeFile(dir, 'index.js', `const key = "${FAKE_SECRET}";`);
  // No .gitignore at all — node_modules is untracked AND unignored, so
  // `git ls-files --others` would surface it if getPublishFiles() didn't
  // filter it back out (npm's own packer never includes node_modules,
  // regardless of git status).
  writeFile(dir, 'node_modules/pkg/index.js', `const key = "${FAKE_SECRET}";`);

  const findings = scanIsolated(dir);
  assert.strictEqual(findingsFor(findings, 'index.js').length, 1, 'normal source file still scanned');
  assert.strictEqual(
    findingsFor(findings, 'node_modules/pkg/index.js').length, 0,
    'npm never publishes node_modules regardless of git tracking — must not be reported as publishable'
  );
});

test('npm project: nested node_modules (not at project root) is also never reported', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg', version: '1.0.0' }));
  // No .gitignore — untracked and unignored at any depth, exactly like the
  // top-level case, but nested under src/. npm excludes node_modules
  // regardless of depth, so this must stay unreported too.
  writeFile(dir, 'src/node_modules/dep/index.js', `const key = "${FAKE_SECRET}";`);
  // A directory that merely LOOKS like node_modules must NOT be swept up by
  // the same filter — it's a real, publishable path.
  writeFile(dir, 'my-node_modules-backup/index.js', `const key = "${FAKE_SECRET}";`);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'src/node_modules/dep/index.js').length, 0,
    'nested node_modules must not be reported as publishable, npm excludes it at any depth'
  );
  assert.strictEqual(
    findingsFor(findings, 'my-node_modules-backup/index.js').length, 1,
    'a directory that only resembles node_modules by name must still be scanned normally'
  );
});

// ── git repo present, but `git ls-files` itself fails ───────────────────
test('git repo with a corrupted index — ls-files fails but scan does not crash, and warns', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'index.js', `const key = "${FAKE_SECRET}";`);
  git(dir, ['add', 'index.js']);
  // Corrupt the index after staging. `git rev-parse --is-inside-work-tree`
  // doesn't touch the index and still succeeds; `git ls-files` reads it and
  // fails — the one case where getAllFilesGitAware() should emit a warning
  // instead of silently looking as thorough as a clean run.
  fs.writeFileSync(path.join(dir, '.git', 'index'), 'not-a-real-index');

  let findings;
  assert.doesNotThrow(() => { findings = scanIsolated(dir); });
  assert.strictEqual(
    findingsFor(findings, 'index.js').length, 1,
    'ignore-based fallback still finds the secret even though git ls-files failed'
  );
  const degraded = findings.filter((f) => f.type === 'git_awareness_degraded');
  assert.strictEqual(degraded.length, 1, 'expected a warning that git ls-files failed inside a real git repo');
});

// ── Unicode normalization mismatch between git and fs.readdirSync ──────
test('non-ASCII filename (NFD/NFC mismatch) — same file not reported twice', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  // "café.js" spelled with a combining acute accent (NFD form) — git
  // reports tracked names as NFC (core.precomposeunicode), while a plain fs
  // walk can see the NFD bytes the file was actually created with.
  const nfdName = 'café.js';
  writeFile(dir, nfdName, `const key = "${FAKE_SECRET}";`);
  git(dir, ['add', '.']);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findings.filter((f) => f.type === 'secret_pattern').length, 1,
    'the same file must not be reported twice under two Unicode-normalization forms of its name'
  );
});

// ── git-tracked symlink to another tracked file ─────────────────────────
test('git-tracked symlink to another tracked file — secret not double-counted', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'real.js', `const key = "${FAKE_SECRET}";`);
  fs.symlinkSync('real.js', path.join(dir, 'link.js'));
  git(dir, ['add', 'real.js', 'link.js']);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findings.filter((f) => f.type === 'secret_pattern').length, 1,
    'a git-tracked symlink to an already-scanned file must not double the finding'
  );
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
