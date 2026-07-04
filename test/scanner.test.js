'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { scan, scanGitHistory } = require('../src/scanner');

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
  // fails — the one case where getGitFileList() should emit a warning
  // instead of silently looking as thorough as a clean run.
  fs.writeFileSync(path.join(dir, '.git', 'index'), 'not-a-real-index');

  let findings;
  assert.doesNotThrow(() => { findings = scanIsolated(dir); });
  assert.strictEqual(
    findingsFor(findings, 'index.js').length, 1,
    'full-directory walk fallback still finds the secret even though git ls-files failed'
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
// dyra #5: the old hand-rolled default-ignore list hardcoded 'dist' as
// excluded unconditionally — but real npm has no such rule and publishes
// dist/ like any other directory unless "files" or .npmignore/.gitignore
// says otherwise.
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

// dyra #6: when "files" is set, the old hand-rolled glob-expansion only
// resolved exactly what's listed — but npm always publishes
// package.json/README/LICENSE regardless of whether "files" lists them. A
// secret sitting in one of those slips past the old emulation entirely.
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
    'npm always publishes README.md even when "files" doesn\'t list it — the old hand-rolled glob-expansion alone would have missed this, only the npm-pack union catches it'
  );
});

// ── npm-confirmed vs git-only: message must name the real leak channel ──
// A file caught ONLY via the git-tracked-then-later-ignored emulation path
// (getGitTrackedFiles) really will leak — but through `git push`, since real
// npm treats .gitignore as pure pattern exclusion and doesn't consult git
// tracking (verified separately against npm-packlist's own source). Saying
// "will be published to npm" about a file npm itself excludes is wrong about
// the channel, even though flagging it at all is correct.
test('AI secret file (CLAUDE.md) caught only via git-tracking, not confirmed by npm: message names git, not npm', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg-git-only', version: '1.0.0' }));
  writeFile(dir, 'CLAUDE.md', `API key: ${FAKE_SECRET}\n`);
  git(dir, ['add', 'package.json', 'CLAUDE.md']);
  // Added to .gitignore AFTER CLAUDE.md was already tracked — real npm pack
  // excludes it (pure .gitignore pattern match, no tracked-file exception),
  // but git still carries it in history and will expose it on push.
  writeFile(dir, '.gitignore', 'CLAUDE.md\n');

  const findings = scanIsolated(dir);
  const published = findings.filter((f) => f.type === 'ai_secret_file_published' && f.file === 'CLAUDE.md');
  assert.strictEqual(published.length, 1, 'must still flag CLAUDE.md — it really does leak, just via git, not npm');
  assert.match(
    published[0].detail, /git push/,
    'message must name the actual leak channel (git push), not "уйдёт в npm-пакет" — real npm excludes this file'
  );
  assert.doesNotMatch(
    published[0].detail, /уйдёт в npm-пакет/,
    'must not claim npm will publish a file npm pack itself confirmed it excludes'
  );
});

// ── mixed AI folder: part npm-confirmed, part git-only ──────────────────
// A folder where SOME files are really published by npm and others are only
// exposed via git tracking must report both counts/channels separately — an
// any()-based check would let one npm-confirmed file make the whole folder
// look npm-only, silently dropping the "remove from git history" advice the
// git-only files actually need.
test('mixed AI folder (.claude/): one file npm-confirmed, one git-only — message reports both channels', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg-mixed-folder', version: '1.0.0' }));
  writeFile(dir, '.claude/keep.json', '{}');
  writeFile(dir, '.claude/hidden.json', '{}');
  git(dir, ['add', 'package.json', '.claude/keep.json', '.claude/hidden.json']);
  // Only hidden.json gets excluded from real npm — it's already git-tracked
  // (staged before this rule existed), so git still carries it regardless.
  // keep.json matches no ignore pattern, so npm confirms it too.
  writeFile(dir, '.gitignore', '.claude/hidden.json\n');

  const findings = scanIsolated(dir);
  const folderFinding = findings.find((f) => f.type === 'ai_folder_in_publish' && f.file === '.claude/');
  assert.ok(folderFinding, 'expected a finding for the .claude/ folder');
  assert.match(
    folderFinding.detail, /1 файлов попадёт в npm-пакет/,
    'must report the npm-confirmed count separately, not fold it into "everything is git-only"'
  );
  assert.match(
    folderFinding.detail, /ещё 1 npm publish не включит/,
    'must report the npm-excluded count separately, not fold it into "everything ships via npm"'
  );
});

// ── npm pack itself unavailable — graceful fallback, not a crash or a gap ──
test('npm unavailable (stripped PATH): scan() falls back to full-directory walk and warns, does not crash', () => {
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
    'full-directory walk fallback alone (no git, no npm reachable) must still catch the secret'
  );
  const degraded = findings.filter((f) => f.type === 'npm_pack_degraded');
  assert.strictEqual(degraded.length, 1, 'expected a warning that npm pack --dry-run could not run');
});

// Creates a fake `npm` executable that unconditionally prints `stdout` and
// exits 0, then prepends its directory to PATH for the duration of `fn` —
// so getNpmPackFiles() (which spawns `npm` via the inherited process env)
// calls this stub instead of the real npm pack. Used to force npm pack to
// "succeed" with output that isn't the manifest shape getNpmPackFiles()
// expects, without needing a real broken npm install.
function withFakeNpm(stdout, fn) {
  const fakeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aiguard-fake-npm-'));
  const fakeNpm = path.join(fakeDir, 'npm');
  fs.writeFileSync(fakeNpm, `#!/bin/sh\necho '${stdout}'\n`);
  fs.chmodSync(fakeNpm, 0o755);
  const prevPath = process.env.PATH;
  process.env.PATH = `${fakeDir}${path.delimiter}${prevPath}`;
  try {
    fn();
  } finally {
    process.env.PATH = prevPath;
    fs.rmSync(fakeDir, { recursive: true, force: true });
  }
}

// ── getNpmPackFiles(): npm ran but its output couldn't be parsed ───────
test('npm pack returns invalid JSON: npm_pack_degraded names the real reason', () => {
  const dir = makeTempProject();
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg-badjson', version: '1.0.0' }));
  writeFile(dir, 'index.js', `const key = "${FAKE_SECRET}";`);

  let findings;
  withFakeNpm('not valid json at all', () => {
    findings = scan(dir);
  });

  assert.strictEqual(
    findingsFor(findings, 'index.js').length, 1,
    'full-directory walk fallback still catches the secret even though npm pack "succeeded" with garbage output'
  );
  const degraded = findings.filter((f) => f.type === 'npm_pack_degraded');
  assert.strictEqual(degraded.length, 1, 'expected exactly one npm_pack_degraded warning');
  assert.match(degraded[0].detail, /невалидный JSON/, 'must name the actual reason (invalid JSON), not a generic message');
});

// ── getNpmPackFiles(): npm ran, output parsed, but isn't a publish manifest ─
test('npm pack returns well-formed JSON of the wrong shape: npm_pack_degraded names the real reason', () => {
  const dir = makeTempProject();
  writeFile(dir, 'package.json', JSON.stringify({ name: 'tmp-pkg-badshape', version: '1.0.0' }));
  writeFile(dir, 'index.js', `const key = "${FAKE_SECRET}";`);

  let findings;
  withFakeNpm('{}', () => {
    findings = scan(dir);
  });

  assert.strictEqual(
    findingsFor(findings, 'index.js').length, 1,
    'full-directory walk fallback still catches the secret even though npm pack "succeeded" with the wrong JSON shape'
  );
  const degraded = findings.filter((f) => f.type === 'npm_pack_degraded');
  assert.strictEqual(degraded.length, 1, 'expected exactly one npm_pack_degraded warning');
  assert.match(degraded[0].detail, /неожиданной формы/, 'must name the actual reason (unexpected shape), not a generic message');
});

// ── walkAllFiles() fallback: a directory it can't even list ─────────────
test('walkAllFiles fallback: unreadable subdirectory is warned about, not silently dropped', () => {
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    return; // root bypasses chmod 000 — nothing to test under this account
  }
  const dir = makeTempProject(); // no git, no package.json — forces the walkAllFiles fallback path
  writeFile(dir, 'index.js', `const key = "${FAKE_SECRET}";`);
  const blockedDir = path.join(dir, 'blocked');
  fs.mkdirSync(blockedDir);
  writeFile(dir, 'blocked/secret.js', `const key = "${FAKE_SECRET}";`);
  fs.chmodSync(blockedDir, 0o000);

  let findings;
  try {
    findings = scanIsolated(dir);
  } finally {
    fs.chmodSync(blockedDir, 0o755);
  }

  assert.strictEqual(findingsFor(findings, 'index.js').length, 1, 'readable sibling file is still scanned');
  const unreadable = findings.filter((f) => f.type === 'directory_unreadable');
  assert.strictEqual(unreadable.length, 1, 'expected a warning naming the unreadable directory');
  assert.strictEqual(unreadable[0].file, 'blocked', 'warning must name the actual directory that failed to list');
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

// ── scanGitHistory: dyra #4 — --diff-filter=A only saw brand-new files ─
test('scanGitHistory: secret added by editing an already-tracked file is caught, not just secrets in new files', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'config.js', 'module.exports = {};\n');
  git(dir, ['add', 'config.js']);
  git(dir, ['commit', '--quiet', '-m', 'add config']);
  // config.js already exists and is tracked — this commit's file status is
  // "modified", not "added". The old --diff-filter=A dropped this commit
  // from `git log` entirely, so the secret below was never scanned.
  writeFile(dir, 'config.js', `module.exports = { key: '${FAKE_SECRET}' };\n`);
  git(dir, ['add', 'config.js']);
  git(dir, ['commit', '--quiet', '-m', 'edit config, add secret']);

  const hits = scanGitHistory(dir).filter((f) => f.type === 'secret_pattern');
  assert.strictEqual(
    hits.length, 1,
    'a secret added via an edit to an already-tracked file must be caught in history scanning'
  );
});

// Exact scenario named in the task: added by an edit, then removed by a
// later edit — must still surface from history even though the working
// tree (and a scan() of the current tree) no longer contains it.
test('scanGitHistory: secret added by an edit, then removed by a later edit — still caught in history', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'config.js', 'module.exports = {};\n');
  git(dir, ['add', 'config.js']);
  git(dir, ['commit', '--quiet', '-m', 'add config']);
  writeFile(dir, 'config.js', `module.exports = { key: '${FAKE_SECRET}' };\n`);
  git(dir, ['add', 'config.js']);
  git(dir, ['commit', '--quiet', '-m', 'edit config, add secret']);
  writeFile(dir, 'config.js', 'module.exports = {};\n');
  git(dir, ['add', 'config.js']);
  git(dir, ['commit', '--quiet', '-m', 'remove secret']);

  const hits = scanGitHistory(dir).filter((f) => f.type === 'secret_pattern');
  assert.strictEqual(
    hits.length, 1,
    'the secret must still be found in a past commit even though a later commit removed it from the working tree'
  );
});

// ── scanGitHistory: dyra #9 — a failed `git log` silently returned [] ──
test('scanGitHistory: git log itself fails (corrupted branch ref) — visible warning, not a silent empty result', () => {
  const dir = makeTempProject();
  initGitRepo(dir);
  writeFile(dir, 'file.js', 'const a = 1;\n');
  git(dir, ['add', 'file.js']);
  git(dir, ['commit', '--quiet', '-m', 'add file']);

  // Corrupt every branch ref to a SHA that doesn't exist in the object
  // database. `git rev-parse --is-inside-work-tree` (scanGitHistory's own
  // "is this a git repo" check) doesn't need to resolve any ref and still
  // succeeds, but `git log --all` fails with "fatal: bad object" trying to
  // walk history from it — exactly the failure this catch block covers.
  const headsDir = path.join(dir, '.git', 'refs', 'heads');
  for (const ref of fs.readdirSync(headsDir)) {
    fs.writeFileSync(path.join(headsDir, ref), 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n');
  }

  const findings = scanGitHistory(dir);
  assert.notStrictEqual(
    findings.length, 0,
    'a failed "git log" must produce a visible warning, not silently look like "history is clean"'
  );
  const failed = findings.filter((f) => f.type === 'git_history_scan_failed');
  assert.strictEqual(failed.length, 1, 'expected exactly one git_history_scan_failed warning');
  assert.strictEqual(failed[0].severity, 'WARN');
});

// ── File size limit: a huge file must be skipped, fast, with a visible warning ─
test('file over the size limit is skipped without scanning (fast, and a WARN names why)', () => {
  const dir = makeTempProject();
  // 6 MB of filler plus an embedded AWS key — the key must NOT be found:
  // the file is skipped by size before it's ever read.
  const bigContent = 'a'.repeat(6 * 1024 * 1024) + `\nconst key = "${FAKE_SECRET}";\n`;
  writeFile(dir, 'huge.js', bigContent);

  const start = Date.now();
  const findings = scanIsolated(dir);
  const elapsedMs = Date.now() - start;

  assert.strictEqual(findingsFor(findings, 'huge.js').length, 0, 'oversized file must not be scanned for secrets');
  assert.ok(elapsedMs < 500, `expected the skip to be fast (<500ms), took ${elapsedMs}ms`);
  const tooLarge = findings.filter((f) => f.type === 'file_too_large' && f.file === 'huge.js');
  assert.strictEqual(tooLarge.length, 1, 'expected a visible warning naming the skipped oversized file');
  assert.strictEqual(tooLarge[0].severity, 'WARN');
});

// ── UTF-16: BOM'd text must be decoded and scanned, not treated as binary ──
test('UTF-16 LE file (with BOM) is scanned as text, not skipped as binary', () => {
  const dir = makeTempProject();
  const content = `const key = "${FAKE_SECRET}";\n`;
  const utf16Buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(content, 'utf16le')]);
  fs.writeFileSync(path.join(dir, 'utf16le.js'), utf16Buf);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'utf16le.js').length, 1,
    'a UTF-16 LE file with a BOM must be decoded and scanned, not silently treated as binary'
  );
});

test('UTF-16 BE file (with BOM) is scanned as text, not skipped as binary', () => {
  const dir = makeTempProject();
  const content = `const key = "${FAKE_SECRET}";\n`;
  const leBuf = Buffer.from(content, 'utf16le');
  const beBuf = Buffer.alloc(leBuf.length);
  for (let i = 0; i + 1 < leBuf.length; i += 2) {
    beBuf[i] = leBuf[i + 1];
    beBuf[i + 1] = leBuf[i];
  }
  const utf16Buf = Buffer.concat([Buffer.from([0xfe, 0xff]), beBuf]);
  fs.writeFileSync(path.join(dir, 'utf16be.js'), utf16Buf);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'utf16be.js').length, 1,
    'a UTF-16 BE file with a BOM must be decoded and scanned, not silently treated as binary'
  );
});

test('a real binary file (null byte, no BOM) is still skipped — unaffected by the UTF-16 fix', () => {
  const dir = makeTempProject();
  const binBuf = Buffer.concat([Buffer.from([0x00, 0x01, 0x02, 0x03]), Buffer.from(`key=${FAKE_SECRET}`)]);
  fs.writeFileSync(path.join(dir, 'blob.dat'), binBuf);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'blob.dat').length, 0,
    'a genuine binary blob (no UTF-16 BOM) must still be skipped, not scanned as garbled text'
  );
});

// ── Round-2 /validate fix: UTF-32 LE BOM must not be mis-read as UTF-16 ─
// Found by an independent reviewer: a UTF-32 LE BOM (FF FE 00 00) shares its
// first two bytes with UTF-16 LE's BOM (FF FE) — without checking the next
// two bytes, a UTF-32 file got silently mis-decoded as garbled UTF-16 text.
test('UTF-32 LE file (BOM FF FE 00 00) is not mis-decoded as UTF-16 — treated as binary like before', () => {
  const dir = makeTempProject();
  const content = `const key = "${FAKE_SECRET}";\n`;
  const codepoints = Array.from(content).map((ch) => ch.codePointAt(0));
  const utf32Buf = Buffer.alloc(4 + codepoints.length * 4);
  utf32Buf.writeUInt8(0xff, 0);
  utf32Buf.writeUInt8(0xfe, 1);
  utf32Buf.writeUInt8(0x00, 2);
  utf32Buf.writeUInt8(0x00, 3);
  codepoints.forEach((cp, i) => utf32Buf.writeUInt32LE(cp, 4 + i * 4));
  fs.writeFileSync(path.join(dir, 'utf32le.js'), utf32Buf);

  const findings = scanIsolated(dir);
  assert.strictEqual(
    findingsFor(findings, 'utf32le.js').length, 0,
    'UTF-32 is out of scope (same as before this fix) — it must not be garbled into a false or missed match, just skipped as binary'
  );
});

// ── Round-2 /validate fix: fail closed when size can't be confirmed ────
// Found by an independent reviewer: if statSync() fails (returns null from
// getFileSize) but readFileSync() would have succeeded, the old code fell
// through to an unbounded read — defeating the whole point of the size
// limit. safeRead() must now treat "size unknown" the same as "too big".
test('safeRead fails closed when stat() cannot confirm size, even though the file is small and readable', () => {
  const dir = makeTempProject();
  writeFile(dir, 'stat-flaky.js', `const key = "${FAKE_SECRET}";`);
  // scan() resolves paths through fs.realpathSync (resolveWithinRoot) before
  // ever calling safeRead — on macOS the tmp dir itself is a symlink
  // (/var/folders/... -> /private/var/folders/...), so the path safeRead
  // actually stats is the REALPATH, not the raw path handed to writeFile().
  const target = fs.realpathSync(path.join(dir, 'stat-flaky.js'));

  const originalStatSync = fs.statSync;
  fs.statSync = function (p, ...rest) {
    if (p === target) {
      const err = new Error('simulated stat failure');
      err.code = 'EIO';
      throw err;
    }
    return originalStatSync.call(fs, p, ...rest);
  };

  let findings;
  try {
    findings = scanIsolated(dir);
  } finally {
    fs.statSync = originalStatSync;
  }

  assert.strictEqual(
    findingsFor(findings, 'stat-flaky.js').length, 0,
    'when size cannot be confirmed, the file must be skipped rather than read unbounded'
  );
});

// ── file_unreadable: chmod 000 file must warn, not silently skip ─────────
// Acceptance test for the "предупреждение о нечитаемом файле" fix.
// stat() succeeds on a chmod-000 file (directory execute-bit is what matters,
// not the file's own read-bit), so getFileSize() returns a real size —
// the permission failure only surfaces in readFileSync(), which throws EACCES.
// Before this fix: safeRead() silently swallowed EACCES and returned null,
// the caller's `if (!content) continue` dropped the file without any warning.
test('permission-denied file (chmod 000) emits file_unreadable WARN, does not crash, is not silently skipped', () => {
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    return; // root bypasses chmod 000 — nothing to test under this account
  }
  const dir = makeTempProject();
  writeFile(dir, 'locked.js', `const key = "${FAKE_SECRET}";`);
  const lockedFile = path.join(dir, 'locked.js');
  fs.chmodSync(lockedFile, 0o000);

  let findings;
  try {
    assert.doesNotThrow(() => { findings = scanIsolated(dir); });
  } finally {
    fs.chmodSync(lockedFile, 0o644);
  }

  const unreadable = findings.filter((f) => f.type === 'file_unreadable' && f.file === 'locked.js');
  assert.strictEqual(unreadable.length, 1, 'expected exactly one file_unreadable warning naming the permission-denied file');
  assert.strictEqual(unreadable[0].severity, 'WARN', 'file_unreadable must have WARN severity');
  // Secret itself must NOT be reported — we never read the contents
  assert.strictEqual(findingsFor(findings, 'locked.js').length, 0, 'no secret_pattern finding expected for an unreadable file');
});

// ── file_unreadable: race condition (file disappears mid-scan) must stay silent ─
// When a file listed by git/npm/walk disappears between listing and scanning,
// getFileSize() returns null (ENOENT) AND existsSync() returns false — no
// warning should be emitted (it is a normal race, not a coverage gap).
test('file removed between listing and scanning (race) — no spurious file_unreadable warning', () => {
  const dir = makeTempProject();
  writeFile(dir, 'vanishing.js', `const key = "${FAKE_SECRET}";`);
  // Resolve the real path: on macOS /tmp is a symlink, so resolveWithinRoot
  // inside scan() will produce the realpath, which is what getFileSize sees.
  const realVanishing = fs.realpathSync(path.join(dir, 'vanishing.js'));

  const originalStatSync = fs.statSync;
  const originalExistsSync = fs.existsSync;
  // Simulate the file disappearing: both stat and existsSync see it as gone.
  fs.statSync = function (p, ...rest) {
    if (p === realVanishing) {
      const err = new Error('simulated ENOENT (race)');
      err.code = 'ENOENT';
      throw err;
    }
    return originalStatSync.call(fs, p, ...rest);
  };
  fs.existsSync = function (p, ...rest) {
    if (p === realVanishing) return false;
    return originalExistsSync.call(fs, p, ...rest);
  };

  let findings;
  try {
    findings = scanIsolated(dir);
  } finally {
    fs.statSync = originalStatSync;
    fs.existsSync = originalExistsSync;
  }

  const unreadable = findings.filter((f) => f.type === 'file_unreadable' && f.file === 'vanishing.js');
  assert.strictEqual(unreadable.length, 0, 'a file that disappeared between listing and scanning is a normal race — must not emit file_unreadable');
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
