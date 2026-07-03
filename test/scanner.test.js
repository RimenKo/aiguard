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

// npm only excludes node_modules at the project ROOT, not at any depth —
// verified directly against npm's own source (npm-packlist's default ignore
// rules use '/node_modules', anchored with a leading slash, unlike e.g.
// '.npmrc' which is intentionally left unanchored). A nested node_modules-
// named directory elsewhere in the tree is real, publishable content as far
// as npm is concerned (e.g. a module-resolution test fixture some package
// ships on purpose) — getPublishFiles()'s npm-pack union now reflects that
// real behavior directly, superseding this test's previous (incorrect)
// "excluded at any depth" assumption, which getNpmPackFiles() was added to
// stop relying on hand-rolled guesses for.
test('npm project: nested node_modules (not at project root) IS published — must be reported, not excluded', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg', version: '1.0.0' }));
  writeFile(dir, 'src/node_modules/dep/index.js', `const key = "${FAKE_SECRET}";`);
  // A directory that only resembles node_modules by name was never excluded
  // by any filter in the first place — kept as a control case.
  writeFile(dir, 'my-node_modules-backup/index.js', `const key = "${FAKE_SECRET}";`);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'src/node_modules/dep/index.js').length, 1,
    'npm only excludes node_modules at project root ("/node_modules", anchored) — a nested one is real published content and must be reported'
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

// ── getNpmPackFiles(): npm truth catches what our own emulation misses ─
// dyra #5: buildIgnoreList()'s defaultIgnore hardcodes 'dist' as excluded
// unconditionally — but real npm has no such rule and publishes dist/ like
// any other directory unless "files" or .npmignore/.gitignore says otherwise.
test('npm project, no "files" field: secret in dist/ IS published by real npm — must be reported', () => {
  const dir = makeTempProject(); // no git needed — npm pack doesn't require it
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg-dist', version: '1.0.0' }));
  writeFile(dir, 'dist/bundle.js', `const key = "${FAKE_SECRET}";`);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'dist/bundle.js').length, 1,
    'real npm publishes dist/ by default (verified via npm pack --dry-run) — our old hand-rolled defaultIgnore wrongly hardcodes it as excluded, so only the npm-pack union catches this'
  );
});

// dyra #6: when "files" is set, expandGlobs() only resolves exactly what's
// listed — but npm always publishes package.json/README/LICENSE regardless
// of whether "files" lists them. A secret sitting in one of those slips past
// the old emulation entirely.
test('npm project, "files" field set without README.md: secret in README.md IS published — must be reported', () => {
  const dir = makeTempProject();
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg-readme', version: '1.0.0', files: ['src/'] }));
  writeFile(dir, 'src/index.js', 'module.exports = 1;');
  // README.md is deliberately NOT listed in "files" — npm ships it anyway.
  // Phrased like the other tests' fixtures (`const key = "..."`), not
  // "secret: ..." — that label alone independently matches the unrelated
  // "generic secret in env" pattern too, which would make this test about
  // pattern-matching nuance instead of about file inclusion.
  writeFile(dir, 'README.md', `# tmp-pkg-readme\n\nconst key = "${FAKE_SECRET}";\n`);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'README.md').length, 1,
    'npm always publishes README.md even when "files" doesn\'t list it — expandGlobs() alone would miss this, only the npm-pack union catches it'
  );
});

// ── npm pack itself unavailable — graceful fallback, not a crash or a gap ──
test('npm unavailable (stripped PATH): scan() falls back to emulation and warns, does not crash', () => {
  const dir = makeTempProject(); // no git — isGitRepo() will just report false
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg-nonpm', version: '1.0.0' }));
  writeFile(dir, 'index.js', `const key = "${FAKE_SECRET}";`);

  const prevPath = process.env.PATH;
  process.env.PATH = '';
  let findings;
  try {
    assert.doesNotThrow(() => { findings = scan(dir); });
  } finally {
    process.env.PATH = prevPath;
  }

  assert.strictEqual(
    findingsFor(findings, 'index.js').length, 1,
    'ignore-based emulation alone (no git, no npm reachable) must still catch the secret'
  );
  const degraded = findings.filter((f) => f.type === 'npm_pack_degraded');
  assert.strictEqual(degraded.length, 1, 'expected a warning that npm pack --dry-run could not run');
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
