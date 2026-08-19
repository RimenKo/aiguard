'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const HOOK = path.join(__dirname, '..', 'claude-hook', 'aiguard-hook.js');

function runHook(toolInput, extra) {
  return spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ tool_input: toolInput }),
    encoding: 'utf8',
    cwd: extra && extra.cwd,
  });
}

let passed = 0;

function check(label, toolInput, expectedExit) {
  const r = runHook(toolInput);
  assert.strictEqual(r.status, expectedExit, `[${label}] expected exit ${expectedExit}, got ${r.status}\nstderr: ${r.stderr}`);
  console.log(`✓ ${label}`);
  passed++;
}

// ── MultiEdit: secret hidden in edits[] is blocked ────────────────────────────
check(
  'MultiEdit: secret in edits[1].new_string → blocked',
  {
    file_path: 'config.js',
    edits: [
      { old_string: 'A', new_string: 'safe text here' },
      { old_string: 'B', new_string: 'key = AKIAABCDEFGHIJKLMNOP' }, // gitleaks:allow — fake fixture
    ],
  },
  2,
);

check(
  'MultiEdit: all edits clean → allowed',
  {
    file_path: 'config.js',
    edits: [
      { old_string: 'A', new_string: 'hello world' },
      { old_string: 'B', new_string: 'no secrets here' },
    ],
  },
  0,
);

check(
  'MultiEdit: empty edits array → allowed',
  { file_path: 'config.js', edits: [] },
  0,
);

// ── Regression: null element in edits[] must not crash the process ─────────────
// Before the fix, `if (e.new_string)` threw a TypeError reading `.new_string`
// off `null`, crashing the process with exit 1 (uncaught exception) *before*
// the pattern-search loop ever ran — so a real secret sitting in another
// edits[] element (e.g. edits[0]) went completely unchecked. Fail-closed now
// requires exit 2, not 0 and not 1.
check(
  'MultiEdit: secret in edits[0] + null in edits[1] → blocked (exit 2, not crash)',
  {
    file_path: 'config.js',
    edits: [
      { old_string: 'A', new_string: 'key = AKIAABCDEFGHIJKLMNOP' }, // gitleaks:allow — fake fixture
      null,
    ],
  },
  2,
);

// ── OpenAI sk-proj- (was missed by old regex) ──────────────────────────────
check(
  'Write: sk-proj- OpenAI key → blocked',
  {
    file_path: 'env.js',
    content: 'const KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz12"', // gitleaks:allow — fake fixture
  },
  2,
);

check(
  'Edit: sk-proj- in new_string → blocked',
  {
    file_path: 'env.js',
    old_string: 'placeholder',
    new_string: 'OPENAI_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz12', // gitleaks:allow — fake fixture
  },
  2,
);

// ── Other providers still caught ──────────────────────────────────────────────
check(
  'Write: Anthropic sk-ant- key → blocked',
  {
    file_path: 'env.js',
    content: 'KEY=sk-ant-api03-fakekeytest1234567890abcde', // gitleaks:allow — fake fixture
  },
  2,
);

check(
  'Write: GitHub token → blocked',
  {
    file_path: 'env.js',
    content: 'GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456', // gitleaks:allow — fake fixture
  },
  2,
);

check(
  'Write: no secret → allowed',
  {
    file_path: 'hello.js',
    content: 'console.log("Hello, world!")',
  },
  0,
);

// ── BIP39 seed: blocked regardless of separator (comma/JSON/space) ─────────────
// A real seed backup is often stored as a JSON array (e.g. wallet exports
// `{"mnemonic":[...]}`) — demoting that shape to WARN let a real leaked seed
// through with exit 0. No format is demoted anymore: every validated match
// blocks the write.
// gitleaks:allow — fake fixture, not a real mnemonic (deterministic word slice for tests)
const SEED_WORDS = ['actual', 'actress', 'actor', 'action', 'act', 'across', 'acquire', 'acoustic', 'acid', 'achieve', 'accuse', 'account'];

check(
  'Write: BIP39 seed as JSON array → blocked (no severity demotion by separator)',
  { file_path: 'tags.json', content: JSON.stringify(SEED_WORDS) },
  2,
);

check(
  'Write: BIP39 seed comma-separated → blocked (no severity demotion by separator)',
  { file_path: 'tags.txt', content: SEED_WORDS.join(', ') },
  2,
);

check(
  'Write: same words space-separated (real seed format) → still blocked',
  { file_path: 'notes.txt', content: SEED_WORDS.join(' ') },
  2,
);

check(
  'Write: wallet.json mnemonic array (11x "abandon" + "about") → blocked',
  { file_path: 'wallet.json', content: JSON.stringify({ mnemonic: Array(11).fill('abandon').concat('about') }) }, // gitleaks:allow — fake fixture, not a real seed
  2,
);

// ── Decoy match before a real secret of the SAME pattern → still blocked ───────
// Before the fix, the hook stripped the 'g' flag and called r.exec(content)
// once per pattern (first match only). If that first match was a benign
// decoy that failed validate() (e.g. the canonical BIP39 wordlist itself —
// alphabetical order, not a real mnemonic), the hook moved on to the NEXT
// PATTERN and never looked further into the content for another match of
// THIS pattern — so a real seed appearing later in the same file, matched by
// the same "Crypto mnemonic (BIP39 seed)" pattern, was never scanned at all.
// scanner.js's scanContent() already looped through all matches via
// regex.lastIndex; this locks the hook into the same behavior end-to-end.
{
  // Decoy: first 12 words of the BIP39 wordlist in canonical (alphabetical)
  // order — matches the mnemonic regex shape but fails containsMnemonic()'s
  // sliding-window check because canonical order isn't a real seed.
  // gitleaks:allow — fake fixture, canonical wordlist order, not a real mnemonic
  const decoy = ['abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident'].join(' ');
  // Real seed: same 12-word slice used elsewhere in this file, but shuffled
  // out of canonical order so it passes containsMnemonic() as a genuine match.
  // gitleaks:allow — fake fixture, not a real wallet seed
  const realSeed = SEED_WORDS.join(' ');
  const content = `канонический список слов из словаря BIP39 (не сид).\n${decoy}\nа_на_следующей_строке_настоящий_сид_через_пробелы\n${realSeed}`;
  check(
    'Write: decoy BIP39 wordlist match followed by real seed (same pattern) → blocked',
    { file_path: 'notes.txt', content },
    2,
  );
}

// ── NotebookEdit: secret in new_source is blocked ─────────────────────────────
// Before the fix, the hook only read ti.content / ti.new_string / ti.edits[]
// .new_string. settings.json's matcher regex /Write|Edit|MultiEdit/ already
// fires for 'NotebookEdit' (it contains the substring 'Edit'), so the hook
// process DID run — but it never looked at ti.new_source, the field Claude
// Code puts a Jupyter cell's new content in. A secret in a notebook cell went
// through completely silently: exit 0, no stderr warning at all.
check(
  'NotebookEdit: secret in new_source → blocked',
  {
    notebook_path: 'notebook.ipynb',
    cell_id: 'abc123',
    new_source: 'ANTHROPIC_API_KEY = "sk-ant-api03-fakekeytest1234567890abcde"', // gitleaks:allow — fake fixture
  },
  2,
);

check(
  'NotebookEdit: no secret in new_source → allowed',
  {
    notebook_path: 'notebook.ipynb',
    cell_id: 'abc123',
    new_source: 'print("hello world")',
  },
  0,
);

// ── Edge cases ────────────────────────────────────────────────────────────────
check(
  'Empty tool_input → allowed',
  {},
  0,
);

// ── DB connection string ReDoS regression: bounded via live hook ──────────────
// Security-audit finding: unbounded `[^@]+` in the "DB connection string"
// pattern (src/patterns.js) was O(n^2) with no size cap on the hook's input
// — measured ~12.2s on a 320KB payload before the fix. This locks in both
// halves of the fix (bounded regex + hook-level size cap) through the real
// process, not just the regex in isolation.
{
  const content = 'postgres://user:pass'.repeat(16000); // 320,000 chars, no "@" anywhere
  const start = Date.now();
  const r = runHook({ file_path: 'notes.txt', content });
  const elapsedMs = Date.now() - start;
  assert.strictEqual(r.status, 0, `[DB conn ReDoS payload] expected exit 0 (no match, no "@"), got ${r.status}\nstderr: ${r.stderr}`);
  assert.ok(elapsedMs < 1000, `[DB conn ReDoS payload] expected hook to return in <1s, took ${elapsedMs}ms`);
  console.log(`✓ Write: 320KB payload with no "@" → allowed in ${elapsedMs}ms (<1s, ReDoS regression)`);
  passed++;
}

// ── Hook-level input size cap ──────────────────────────────────────────────────
// A payload over the hook's own size limit (separate from scanner.js's 5MB
// file-size limit — this hook must stay fast for interactive writes) is
// skipped (fail-open, like scanner.js's file_too_large WARN) rather than
// scanned or blocked.
check(
  'Write: content over hook size limit (1MB) → allowed, not scanned',
  { file_path: 'huge.txt', content: 'x'.repeat(1024 * 1024 + 1) },
  0,
);

// ── Malformed stdin: fail-open (framework issue, not user secret) ─────────────
function runHookRaw(rawInput) {
  return spawnSync(process.execPath, [HOOK], { input: rawInput, encoding: 'utf8' });
}

{
  const r = runHookRaw('');
  assert.strictEqual(r.status, 0, `[empty stdin] expected exit 0, got ${r.status}`);
  console.log('✓ Empty stdin (malformed) → fail-open (allowed)');
  passed++;
}

{
  const r = runHookRaw('not valid json {{{');
  assert.strictEqual(r.status, 0, `[invalid JSON stdin] expected exit 0, got ${r.status}`);
  console.log('✓ Invalid JSON stdin → fail-open (allowed)');
  passed++;
}

// ── README regression: hook blocks on the FIRST secret, not "ALL instances" ───
// README's "Reports ALL instances of each secret per file" describes the
// publish-time scanner (src/scanner.js's scanContent(), used by the `aiguard`
// CLI) — NOT this interactive write-time hook. The hook is built to interrupt
// the write the instant it confirms a real secret, so it must report exactly
// ONE finding (the first pattern match in SECRET_PATTERNS order) and exit —
// it must never keep scanning to also report a second, different secret
// sitting later in the same write. "Anthropic API key" is pattern index 0 in
// src/patterns.js; "GitHub token (classic)" comes much later — if the hook
// enumerated everything (scanner-style) instead of failing fast, stderr would
// also mention the GitHub token.
{
  const content = [
    'ANTHROPIC_KEY=sk-ant-api03-fakekeytest1234567890abcde', // gitleaks:allow — fake fixture
    'GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456', // gitleaks:allow — fake fixture
  ].join('\n');
  const r = runHook({ file_path: 'env.js', content });
  assert.strictEqual(r.status, 2, `[fail-fast on first secret] expected exit 2, got ${r.status}\nstderr: ${r.stderr}`);
  assert.ok(
    r.stderr.includes('Anthropic API key'),
    `[fail-fast on first secret] expected stderr to name the first match (Anthropic API key), got: ${r.stderr}`
  );
  assert.ok(
    !r.stderr.includes('GitHub token'),
    `[fail-fast on first secret] hook must stop at the first secret and NOT also report the second (GitHub token), got: ${r.stderr}`
  );
  console.log('✓ Write: two different secrets → hook blocks and reports only the first, not both (README: hook ≠ "reports ALL instances")');
  passed++;
}

// ── aiguard:allow / .aiguardignore — same rules as the publish-time CLI ──
// Fixture lives in a variable so this source file can mark the definition
// line and not trip the live write hook while still sending an unmarked
// secret to the hook process under test.
const AWS_HOOK_FIXTURE = 'AKIAABCDEFGHIJKLMNOP'; // aiguard:allow gitleaks:allow — fake fixture, not a real key

check(
  'Write: AWS key without marker → blocked',
  { file_path: 'env.js', content: `key = ${AWS_HOOK_FIXTURE}` },
  2,
);

check(
  'Write: same AWS key with aiguard:allow on the same line → allowed',
  { file_path: 'env.js', content: `key = ${AWS_HOOK_FIXTURE} // aiguard:allow` },
  0,
);

check(
  'Write: same AWS key with leakward:allow on the same line → allowed',
  { file_path: 'env.js', content: `key = ${AWS_HOOK_FIXTURE} // leakward:allow` },
  0,
);

check(
  'Edit: same AWS key with gitleaks:allow alias → allowed',
  { file_path: 'env.js', old_string: 'placeholder', new_string: `key = ${AWS_HOOK_FIXTURE} // gitleaks:allow` },
  0,
);

{
  const seed = SEED_WORDS.join(' ');
  check(
    'Write: BIP39 seed followed by a next-line aiguard:allow → still blocked (greedy overshoot)',
    { file_path: 'notes.txt', content: `${seed}\naiguard:allow` },
    2,
  );
}

{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aiguard-hook-ignore-'));
  fs.writeFileSync(path.join(dir, '.aiguardignore'), 'ignored-secret.js\n');
  const r = runHook(
    { file_path: 'ignored-secret.js', content: `key = ${AWS_HOOK_FIXTURE}` },
    { cwd: dir },
  );
  assert.strictEqual(
    r.status, 0,
    `[Write: path in .aiguardignore] expected exit 0 (file not scanned), got ${r.status}\nstderr: ${r.stderr}`
  );
  console.log('✓ Write: file listed in .aiguardignore is not scanned (unmarked secret allowed)');
  passed++;

  const r2 = runHook(
    { file_path: 'other.js', content: `key = ${AWS_HOOK_FIXTURE}` },
    { cwd: dir },
  );
  assert.strictEqual(
    r2.status, 2,
    `[Write: sibling file not in .aiguardignore] expected exit 2, got ${r2.status}\nstderr: ${r2.stderr}`
  );
  console.log('✓ Write: sibling file not listed in .aiguardignore is still blocked');
  passed++;

  const r3 = runHook(
    { file_path: '.aiguardignore', content: `key = ${AWS_HOOK_FIXTURE}` },
    { cwd: dir },
  );
  assert.strictEqual(
    r3.status, 2,
    `[Write: .aiguardignore itself] expected exit 2 (ignore file is never skipped), got ${r3.status}\nstderr: ${r3.stderr}`
  );
  console.log('✓ Write: .aiguardignore itself is still scanned (never self-ignored)');
  passed++;

  const broken = fs.mkdtempSync(path.join(os.tmpdir(), 'aiguard-hook-badglob-'));
  fs.writeFileSync(path.join(broken, '.aiguardignore'), '[]\n');
  const r4 = runHook(
    { file_path: 'clean.js', content: 'console.log("ok")' },
    { cwd: broken },
  );
  assert.strictEqual(
    r4.status, 0,
    `[Write: broken .aiguardignore glob] expected exit 0, got ${r4.status}\nstderr: ${r4.stderr}`
  );
  console.log('✓ Write: broken .aiguardignore glob does not lock the hook');
  passed++;
}

{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leakward-hook-ignore-'));
  fs.writeFileSync(path.join(dir, '.leakwardignore'), 'ignored-secret.js\n');
  const r = runHook(
    { file_path: 'ignored-secret.js', content: `key = ${AWS_HOOK_FIXTURE}` },
    { cwd: dir },
  );
  assert.strictEqual(
    r.status, 0,
    `[Write: path in .leakwardignore] expected exit 0 (file not scanned), got ${r.status}\nstderr: ${r.stderr}`
  );
  console.log('✓ Write: file listed in .leakwardignore is not scanned');
  passed++;

  const r2 = runHook(
    { file_path: '.leakwardignore', content: `key = ${AWS_HOOK_FIXTURE}` },
    { cwd: dir },
  );
  assert.strictEqual(
    r2.status, 2,
    `[Write: .leakwardignore itself] expected exit 2 (ignore file is never skipped), got ${r2.status}\nstderr: ${r2.stderr}`
  );
  console.log('✓ Write: .leakwardignore itself is still scanned (never self-ignored)');
  passed++;
}

console.log(`\n✅ hook.test.js: ${passed} тестов прошло`);
