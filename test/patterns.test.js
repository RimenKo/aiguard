'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { SECRET_PATTERNS } = require('../src/patterns');
const { scanContent } = require('../src/scanner');

const mnemonicPattern = SECRET_PATTERNS.find((p) => p.name === 'Crypto mnemonic (BIP39 seed)');
assert.ok(mnemonicPattern, 'Crypto mnemonic (BIP39 seed) pattern not found in patterns.js');

const numberedPattern = SECRET_PATTERNS.find((p) => p.name === 'Crypto mnemonic (numbered BIP39 seed)');
assert.ok(numberedPattern, 'Crypto mnemonic (numbered BIP39 seed) pattern not found in patterns.js');

const genericSecretPattern = SECRET_PATTERNS.find((p) => p.name === 'Generic secret in env');
assert.ok(genericSecretPattern, 'Generic secret in env pattern not found in patterns.js');

// 24 real BIP39 words picked from scattered positions in the official list —
// NOT in canonical (alphabetical) order. A real mnemonic's word order comes
// from random entropy, so fixtures must be scrambled too: a canonical-order
// slice (e.g. "abandon ability able...") looks exactly like a wordlist
// *definition* (see bip39.js) rather than an actual seed, and the detector
// is specifically designed to tell those apart.
const SEED_WORDS = [
  'laptop', 'alien', 'romance', 'cereal', 'fruit', 'absent', 'unique', 'craft',
  'always', 'noodle', 'heart', 'wheel', 'arrive', 'stand', 'action', 'identify',
  'relief', 'enrich', 'web', 'butter', 'maze', 'agree', 'siege', 'fiscal',
];

// Common English words confirmed absent from the BIP39 wordlist.
const NON_BIP39_WORDS = [
  'computer', 'keyboard', 'printer', 'speaker', 'charger', 'battery',
  'adapter', 'desktop', 'folder', 'website', 'browser', 'teacher',
];

function words(n) {
  assert.ok(n <= SEED_WORDS.length, `need ${n} words, only have ${SEED_WORDS.length}`);
  return SEED_WORDS.slice(0, n);
}

// Same detection logic scanner.js's scanContent() runs: regex.exec loop + validate().
function detectsWith(pattern, content) {
  pattern.regex.lastIndex = 0;
  let m;
  while ((m = pattern.regex.exec(content)) !== null) {
    if (m[0].length === 0) { pattern.regex.lastIndex++; continue; }
    if (!pattern.validate || pattern.validate(m[0])) return true;
  }
  return false;
}

function detects(content) {
  return detectsWith(mnemonicPattern, content);
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

// ── Required acceptance tests (T2) ─────────────────────────────────
test('12 words, comma-separated', () => {
  assert.strictEqual(detects(words(12).join(', ')), true);
});

test('12 words, JSON array', () => {
  assert.strictEqual(detects(JSON.stringify(words(12))), true);
});

test('12 words, CRLF-separated', () => {
  assert.strictEqual(detects(words(12).join('\r\n')), true);
});

test('15 words, space-separated', () => {
  assert.strictEqual(detects(words(15).join(' ')), true);
});

test('12 regular English words (not BIP39) — must NOT trigger', () => {
  assert.strictEqual(detects(NON_BIP39_WORDS.join(' ')), false);
});

// ── Extra coverage — other separators/lengths named in the task spec ─
test('12 words, tab-separated', () => {
  assert.strictEqual(detects(words(12).join('\t')), true);
});

test('12 words, CR-only separated (old Mac line endings)', () => {
  assert.strictEqual(detects(words(12).join('\r')), true);
});

test('18 words, space-separated', () => {
  assert.strictEqual(detects(words(18).join(' ')), true);
});

test('21 words, comma-separated', () => {
  assert.strictEqual(detects(words(21).join(',')), true);
});

test('24 words, space-separated (regression)', () => {
  assert.strictEqual(detects(words(24).join(' ')), true);
});

test('Python-style single-quoted array', () => {
  const py = '[' + words(12).map((w) => `'${w}'`).join(', ') + ']';
  assert.strictEqual(detects(py), true);
});

test('Mixed case still detected', () => {
  assert.strictEqual(detects(words(12).map((w) => w.toUpperCase()).join(' ')), true);
});

test('11 words (below minimum) — must NOT trigger', () => {
  assert.strictEqual(detects(words(11).join(' ')), false);
});

// ── Regression: seed glued to a label or trailing word ─────────────
// A greedy run-length regex used to swallow the extra word, land on a total
// count like 13/14 that matches no valid mnemonic length, and lose the real
// seed hiding inside. validate() now slides a window for the mnemonic length
// instead of demanding the whole run match exactly.
test('seed prefixed with a label word — must still trigger', () => {
  assert.strictEqual(detects('wallet phrase ' + words(12).join(' ')), true);
});

test('seed suffixed with a trailing word — must still trigger', () => {
  assert.strictEqual(detects(words(12).join(' ') + ' backup'), true);
});

test('seed embedded mid-sentence — must still trigger', () => {
  assert.strictEqual(detects('note ' + words(15).join(' ') + ' end'), true);
});

// ── Regression: don't flag a wordlist definition as a leaked seed ──
// bip39.js (and any project vendoring the BIP39 wordlist) lists words in
// ascending canonical order — that must NOT be treated as a real mnemonic.
test('canonical-order wordlist slice — must NOT trigger (would flag bip39.js itself)', () => {
  const { BIP39_WORDS } = require('../src/bip39');
  const canonicalOrder = [...BIP39_WORDS].slice(0, 12);
  const jsArrayStyle = canonicalOrder.map((w) => `'${w}'`).join(', ');
  assert.strictEqual(detects(jsArrayStyle), false);
});

test('self-scan: scanning this project\'s own src/bip39.js finds nothing', () => {
  const content = fs.readFileSync(path.join(__dirname, '..', 'src', 'bip39.js'), 'utf8');
  assert.strictEqual(detects(content), false);
});

// ── Numbered mnemonic pattern — same length set as the plain pattern ─
test('numbered format, 12 words (regression)', () => {
  const numbered = words(12).map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, 15 words', () => {
  const numbered = words(15).map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, 18 words', () => {
  const numbered = words(18).map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, 21 words', () => {
  const numbered = words(21).map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, one word per line (backup/screenshot style)', () => {
  const numbered = words(12).map((w, i) => `${i + 1}. ${w}`).join('\n');
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

test('numbered format, canonical-order dictionary listing — must NOT trigger', () => {
  const { BIP39_WORDS } = require('../src/bip39');
  const canonicalOrder = [...BIP39_WORDS].slice(0, 12);
  const numbered = canonicalOrder.map((w, i) => `${i + 1}. ${w}`).join(' ');
  assert.strictEqual(detectsWith(numberedPattern, numbered), false);
});

test('numbered format, extra numbered item glued on — seed still found via sliding window', () => {
  const numbered = words(12).map((w, i) => `${i + 1}. ${w}`).join(' ') + ' 13. backup';
  assert.strictEqual(detectsWith(numberedPattern, numbered), true);
});

// ── Round-3 fix: markdown bullet-list seeds ─────────────────────────
test('seed as a markdown dash list, one word per line', () => {
  const md = words(12).map((w) => `- ${w}`).join('\n');
  assert.strictEqual(detects(md), true);
});

test('seed as a markdown asterisk list, one word per line', () => {
  const md = words(15).map((w) => `* ${w}`).join('\n');
  assert.strictEqual(detects(md), true);
});

test('seed as a bullet (•) list, one word per line', () => {
  const md = words(12).map((w) => `• ${w}`).join('\n');
  assert.strictEqual(detects(md), true);
});

// ── No severityOverride: BIP39 match severity does not depend on separator ─
// An earlier version demoted comma/JSON-array matches to WARN to reduce
// false positives on tag/i18n word lists — but that let a real seed backup
// stored the same way (e.g. a wallet's `{"mnemonic":[...]}`) through with
// only a WARN (exit 0). A missed seed is unrecoverable; a false-positive tag
// list is just a WARN a human can dismiss — so the BIP39 patterns no longer
// define severityOverride at all, and every validated match stays at the
// caller's default severity (HIGH) no matter how the words are separated.
test('BIP39 seed pattern has no severityOverride (severity does not depend on separator)', () => {
  assert.strictEqual(mnemonicPattern.severityOverride, undefined);
});

test('numbered BIP39 seed pattern has no severityOverride either', () => {
  assert.strictEqual(numberedPattern.severityOverride, undefined);
});

// ── Generic secret patterns: PASSWORD/SECRET/TOKEN + any *_KEY name ────
const genericKeyPattern = SECRET_PATTERNS.find((p) => p.name === 'Generic secret key (*_KEY)');
assert.ok(genericKeyPattern, 'Generic secret key (*_KEY) pattern not found in patterns.js');

function detectsGeneric(content) {
  return detectsWith(genericSecretPattern, content);
}
function detectsKey(content) {
  return detectsWith(genericKeyPattern, content);
}

test('ENCRYPTION_KEY (not in the old 7-word enum) is caught', () => {
  assert.strictEqual(detectsKey('ENCRYPTION_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('SIGNING_KEY (not in the old 7-word enum) is caught', () => {
  assert.strictEqual(detectsKey('SIGNING_KEY: abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('STRIPE_KEY (not in the old 7-word enum) is caught', () => {
  assert.strictEqual(detectsKey('STRIPE_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('SECRET_KEY (compound word, not just standalone SECRET) is caught', () => {
  assert.strictEqual(detectsKey('SECRET_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('previously enumerated API_KEY still caught (regression)', () => {
  assert.strictEqual(detectsKey('API_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('previously enumerated PRIVATE_KEY still caught (regression)', () => {
  assert.strictEqual(detectsKey('PRIVATE_KEY=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('standalone PASSWORD/SECRET/TOKEN (no _KEY suffix) still caught (regression)', () => {
  assert.strictEqual(detectsGeneric('PASSWORD=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('SECRET=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsGeneric('TOKEN=abcdef1234567890'), true); // gitleaks:allow — fake fixture, not a real key
});

test('double-quoted value with spaces is caught (*_KEY pattern)', () => {
  assert.strictEqual(detectsKey('SECRET_KEY = "my super secret password"'), true);
});

test('single-quoted value with spaces is caught (PASSWORD/SECRET/TOKEN pattern)', () => {
  assert.strictEqual(detectsGeneric("PASSWORD = 'my super secret password'"), true);
});

test('unquoted value with spaces is NOT caught (no reliable end boundary)', () => {
  assert.strictEqual(detectsKey('SECRET_KEY = my super secret password'), false);
});

// ── Found live 2026-08-14: real-world false positives from a bare
// PASSWORD|SECRET|TOKEN match with no word-boundary, no punctuation
// exclusion, and no value-shape check — a SQL upsert column, a Python
// kwarg, and a numeric-cost kwarg all read as "secrets" before this fix.
// Fixtures below are built via string concatenation so the trigger shape
// never appears as one contiguous literal in this source file — the
// running aiguard install (now fixed) would otherwise flag its own
// regression fixtures while this file is being written.
test('SQL upsert column ("col = excluded.other_col") is NOT caught — code, not a secret', () => {
  assert.strictEqual(detectsGeneric('to' + 'ken' + ' = excluded.cost_per_input_' + 'token,'), false);
});

test('Python kwarg call ("token=func(args)") is NOT caught — code, not a secret', () => {
  assert.strictEqual(detectsGeneric('to' + 'ken' + '=float(row[3]),'), false);
});

test('Python numeric kwarg ("..._token=0.000005") is NOT caught — a bare number is never a real secret', () => {
  assert.strictEqual(detectsGeneric('cost_per_input_' + 'to' + 'ken' + '=0.000005,'), false);
});

test('unquoted value with no digit and no case variation is NOT caught (all-lowercase identifier)', () => {
  assert.strictEqual(detectsGeneric('TOKEN' + '=lowercaseonlyvalue'), false);
});

test('unquoted value WITH a digit is still caught (regression, false-positive fix did not weaken real detection)', () => {
  assert.strictEqual(detectsGeneric('TOKEN' + '=abcXYZ123' + 'value'), true); // gitleaks:allow — fake fixture, not a real key
});

test('unquoted value with mixed case but no digit is still caught (regression)', () => {
  assert.strictEqual(detectsGeneric('TOKEN' + '=abcDEFghi' + 'JKLmno'), true); // gitleaks:allow — fake fixture, not a real key
});

test('value under 8 chars is NOT caught (length floor unchanged)', () => {
  assert.strictEqual(detectsKey('API_KEY=short'), false);
});

test('unrelated lowercase "key" without underscore is NOT caught (e.g. `const key = "..."`)', () => {
  assert.strictEqual(detectsKey('const key = "abcdef1234567890";'), false); // gitleaks:allow — fake fixture, not a real key
});

// ── Round-2 fix: *_KEY must be case-sensitive (env-var convention only) ─
// Found by an independent /validate reviewer: the first cut of this pattern
// used the /i flag, so it also flagged ordinary lowercase code identifiers
// that just happen to end in _key — not secrets at all.
test('ordinary lowercase code identifiers ending in _key are NOT caught (false-positive fix)', () => {
  assert.strictEqual(detectsKey('cache_key = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('primary_key = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('foreign_key = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
  assert.strictEqual(detectsKey('s3_object_key = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
});

// ── Round-2 fix: ReDoS regression guard ─────────────────────────────────
// Found by an independent /validate reviewer: the original `[A-Z][A-Z0-9]*_KEY`
// (unbounded `*` directly before a required literal) backtracks O(n^2) on any
// long alphanumeric run with no "_KEY" in it — measured ~6.9s on 80KB of
// hex-like text before the {0,63} bound was added. This locks in the fix.
test('long alphanumeric run with no _KEY does not cause catastrophic backtracking (ReDoS regression)', () => {
  const hostile = 'A1'.repeat(40000); // 80,000 chars, no underscore anywhere
  const start = Date.now();
  detectsKey(hostile);
  const elapsedMs = Date.now() - start;
  assert.ok(elapsedMs < 500, `expected near-linear scan time (<500ms), took ${elapsedMs}ms`);
});

// ── DB connection string: ReDoS regression guard ────────────────────────
// Found by a security audit: `[^@]+` (unbounded) directly before the
// required `@` backtracks O(n^2) on any long run of "scheme://user:pass"
// text that never contains an "@" — measured ~3.1s on 160KB of repeated
// 'postgres://user:pass' before the {1,256} bound was added (12.2s on 320KB
// through the live claude-hook). This locks in the fix.
const dbConnPattern = SECRET_PATTERNS.find((p) => p.name === 'DB connection string');
assert.ok(dbConnPattern, 'DB connection string pattern not found in patterns.js');

function detectsDbConn(content) {
  return detectsWith(dbConnPattern, content);
}

test('repeated "postgres://user:pass" with no "@" anywhere does not cause catastrophic backtracking (ReDoS regression)', () => {
  const hostile = 'postgres://user:pass'.repeat(8000); // 160,000 chars, no "@" anywhere
  const start = Date.now();
  detectsDbConn(hostile);
  const elapsedMs = Date.now() - start;
  assert.ok(elapsedMs < 100, `expected near-linear scan time (<100ms), took ${elapsedMs}ms`);
});

test('real DB connection string is still caught (regression)', () => {
  assert.strictEqual(
    detectsDbConn('DATABASE_URL=postgres://myuser:mypassword123@db.example.com:5432/mydb'), // gitleaks:allow — fake fixture
    true,
  );
});

// ── AWS temporary (ASIA) keys + *_KEY_ID / *_KEY_VERSION name coverage ──
// Found in an independent security audit: the AWS Access Key ID pattern only
// matched the AKIA (long-term) prefix, missing ASIA (temporary STS/SSO/
// assume-role) keys — the standard shape in any CI/CD pipeline. Separately,
// the generic *_KEY pattern required "_KEY" to sit directly before "="/":",
// so AWS_ACCESS_KEY_ID (where "_ID" follows "_KEY") was caught by NO pattern
// at all except by coincidence if its value happened to look like an AKIA
// key — never by variable name.
const awsKeyIdPattern = SECRET_PATTERNS.find((p) => p.name === 'AWS Access Key ID');
assert.ok(awsKeyIdPattern, 'AWS Access Key ID pattern not found in patterns.js');

function detectsAwsKeyId(content) {
  return detectsWith(awsKeyIdPattern, content);
}

test('AWS temporary (ASIA) key value is caught', () => {
  assert.strictEqual(
    detectsAwsKeyId('AWS_ACCESS_KEY_ID=ASIAABCDEFGHIJKLMNOP'), // gitleaks:allow — fake fixture, not a real key
    true,
  );
});

test('AWS long-term (AKIA) key value is still caught (regression)', () => {
  assert.strictEqual(
    detectsAwsKeyId('AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP'), // gitleaks:allow — fake fixture, not a real key
    true,
  );
});

test('AWS_ACCESS_KEY_ID caught by variable name (*_KEY_ID), even with a non-AKIA/ASIA-shaped value', () => {
  assert.strictEqual(
    detectsKey('AWS_ACCESS_KEY_ID=abcdefgh12345678'), // gitleaks:allow — fake fixture, not a real key
    true,
  );
});

test('AWS_ACCESS_KEY_VERSION caught by variable name (*_KEY_VERSION)', () => {
  assert.strictEqual(
    detectsKey('AWS_ACCESS_KEY_VERSION=abcdefgh12345678'), // gitleaks:allow — fake fixture, not a real key
    true,
  );
});

test('lowercase cache_key_id is NOT caught (false-positive guard unchanged after *_KEY_ID extension)', () => {
  assert.strictEqual(detectsKey('cache_key_id = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
});

test('lowercase primary_key_id is NOT caught (false-positive guard unchanged after *_KEY_ID extension)', () => {
  assert.strictEqual(detectsKey('primary_key_id = "abcdefgh12345678"'), false); // gitleaks:allow — fake fixture, not a real key
});

// ── aiguard:allow — same-line marker suppresses a finding that the same
// pattern still reports without the marker. Uses scanContent() (the path
// both the CLI and, via the same helper, the write hook consult) rather
// than detectsWith(), because the marker is a scanner-layer rule, not a
// regex change. Fixture value lives in a variable so this source line
// itself can carry a marker and not trip the live write hook.
const AWS_ALLOW_FIXTURE = 'AKIAABCDEFGHIJKLMNOP'; // aiguard:allow gitleaks:allow — fake fixture, not a real key

test('line with aiguard:allow is not flagged by the same pattern that flags the unmarked line', () => {
  const unmarked = `const key = "${AWS_ALLOW_FIXTURE}";`;
  const marked = `const key = "${AWS_ALLOW_FIXTURE}"; // aiguard:allow`;
  assert.ok(
    scanContent('fixture.js', unmarked, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'control: unmarked AWS-shaped key must still be reported'
  );
  assert.strictEqual(
    scanContent('fixture.js', marked, 'HIGH').filter((f) => f.type === 'secret_pattern').length,
    0,
    'same key on a line with aiguard:allow must not be reported'
  );
});

test('aiguard:allow on a neighboring line does not suppress the match (marker is not a nearby switch)', () => {
  const content = `// aiguard:allow\nconst key = "${AWS_ALLOW_FIXTURE}";`;
  assert.ok(
    scanContent('fixture.js', content, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'a marker on the previous line must not suppress a finding on the next line'
  );
});

test('gitleaks:allow is accepted as an alias of aiguard:allow', () => {
  const marked = `const key = "${AWS_ALLOW_FIXTURE}"; // gitleaks:allow`;
  assert.strictEqual(
    scanContent('fixture.js', marked, 'HIGH').filter((f) => f.type === 'secret_pattern').length,
    0,
    'gitleaks:allow on the same line must suppress the finding'
  );
});

test('leakward:allow is accepted as the public spelling of aiguard:allow', () => {
  const marked = `const key = "${AWS_ALLOW_FIXTURE}"; // leakward:allow`;
  assert.strictEqual(
    scanContent('fixture.js', marked, 'HIGH').filter((f) => f.type === 'secret_pattern').length,
    0,
    'leakward:allow on the same line must suppress the finding'
  );
});

test('aiguard:allow on a CR-only previous line does not suppress the next line', () => {
  const content = `// aiguard:allow\rconst key = "${AWS_ALLOW_FIXTURE}";`;
  assert.ok(
    scanContent('fixture.js', content, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'a CR-separated previous line with a marker must not suppress the next line'
  );
});

test('BIP39 seed is still flagged when the next line is a bare aiguard:allow (greedy overshoot)', () => {
  const seed = words(12).join(' ');
  const content = `${seed}\naiguard:allow`;
  assert.ok(
    scanContent('fixture.js', content, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'a marker on the line after a seed must not suppress the seed (greedy {11,} can swallow "aiguard")'
  );
});

test('BIP39 seed on one line with aiguard:allow is still suppressed', () => {
  const seed = words(12).join(' ');
  const content = `${seed} // aiguard:allow`;
  assert.strictEqual(
    scanContent('fixture.js', content, 'HIGH').filter((f) => f.type === 'secret_pattern').length,
    0,
    'a marker on the same line as the seed must still suppress it'
  );
});

test('BIP39 seed is still flagged when the next line is a bare leakward:allow (greedy overshoot)', () => {
  const seed = words(12).join(' ');
  const content = `${seed}\nleakward:allow`;
  assert.ok(
    scanContent('fixture.js', content, 'HIGH').some((f) => f.type === 'secret_pattern'),
    'a marker on the line after a seed must not suppress the seed (greedy {11,} can swallow "leakward")'
  );
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
