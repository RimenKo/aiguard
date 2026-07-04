'use strict';

const assert = require('assert');
const path = require('path');
const { spawnSync } = require('child_process');

const HOOK = path.join(__dirname, '..', 'claude-hook', 'aiguard-hook.js');

function runHook(toolInput) {
  return spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ tool_input: toolInput }),
    encoding: 'utf8',
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

// ── Edge cases ────────────────────────────────────────────────────────────────
check(
  'Empty tool_input → allowed',
  {},
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

console.log(`\n✅ hook.test.js: ${passed} тестов прошло`);
