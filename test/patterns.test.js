'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { SECRET_PATTERNS } = require('../src/patterns');

const mnemonicPattern = SECRET_PATTERNS.find((p) => p.name === 'Crypto mnemonic (BIP39 seed)');
assert.ok(mnemonicPattern, 'Crypto mnemonic (BIP39 seed) pattern not found in patterns.js');

const numberedPattern = SECRET_PATTERNS.find((p) => p.name === 'Crypto mnemonic (numbered BIP39 seed)');
assert.ok(numberedPattern, 'Crypto mnemonic (numbered BIP39 seed) pattern not found in patterns.js');

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

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
