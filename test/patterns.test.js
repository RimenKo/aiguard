'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { SECRET_PATTERNS } = require('../src/patterns');

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

// ── severityOverride: comma/JSON-array format → WARN, space/newline → null ─
test('severityOverride is a function on the BIP39 seed pattern', () => {
  assert.strictEqual(typeof mnemonicPattern.severityOverride, 'function');
});

test('severityOverride: comma-separated BIP39 match returns WARN', () => {
  assert.strictEqual(mnemonicPattern.severityOverride(words(12).join(', ')), 'WARN');
});

test('severityOverride: JSON-array BIP39 match (double-quoted words) returns WARN', () => {
  assert.strictEqual(mnemonicPattern.severityOverride(JSON.stringify(words(12))), 'WARN');
});

test('severityOverride: space-separated BIP39 match returns null (no override, stays HIGH)', () => {
  assert.strictEqual(mnemonicPattern.severityOverride(words(12).join(' ')), null);
});

test('severityOverride: newline-separated BIP39 match returns null (no override, stays HIGH)', () => {
  assert.strictEqual(mnemonicPattern.severityOverride(words(12).join('\n')), null);
});

test('severityOverride: space-separated seed glued to comma text returns null (real seed, not a list)', () => {
  // Greedy regex may sweep nearby comma-text into the same match; the
  // letter-space-letter signal from seed words must keep severity HIGH.
  assert.strictEqual(mnemonicPattern.severityOverride(words(12).join(' ') + ', some, extra, text'), null);
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

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
