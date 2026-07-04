#!/usr/bin/env node
'use strict';

// Hook script for Claude Code PreToolUse (Write / Edit / MultiEdit).
// Reads the tool-call JSON from stdin, collects all text being written,
// and blocks the operation (exit 2) if any secret pattern matches.
//
// Path assumptions: this file lives at <pkg-root>/claude-hook/aiguard-hook.js
// so ../src/patterns is always resolvable both in dev and when installed.

const path = require('path');
const fs = require('fs');

// Fail-closed on require error: if patterns can't load, block the operation.
// Silently passing writes when the security check can't run defeats the purpose.
let SECRET_PATTERNS;
try {
  ({ SECRET_PATTERNS } = require(path.join(__dirname, '..', 'src', 'patterns')));
} catch (err) {
  process.stderr.write(`aiguard: не удалось загрузить паттерны — ${err.message}\nОперация заблокирована.\n`);
  process.exit(2);
}

// Fail-open on malformed stdin: bad JSON means a hook setup issue on Claude
// Code's side, not a user secret. Allow the operation rather than blocking
// all writes indefinitely due to a framework bug.
let input;
try {
  input = JSON.parse(fs.readFileSync(0, 'utf8'));
} catch (_) {
  process.exit(0);
}

const ti = (input && input.tool_input) || {};

// Collect every text chunk being written by this tool call:
//   Write      → ti.content
//   Edit       → ti.new_string
//   MultiEdit  → ti.edits[i].new_string  (was missing before this fix)
const texts = [];
if (ti.content) texts.push(ti.content);
if (ti.new_string) texts.push(ti.new_string);
if (Array.isArray(ti.edits)) {
  for (const e of ti.edits) {
    if (e.new_string) texts.push(e.new_string);
  }
}

const content = texts.join('\n');
if (!content) process.exit(0);

for (const { name, regex, validate } of SECRET_PATTERNS) {
  const r = new RegExp(regex.source, (regex.flags || '').replace('g', ''));
  const m = r.exec(content);
  if (!m) continue;
  if (validate && !validate(m[0])) continue;
  process.stderr.write(`aiguard: обнаружен секрет (${name}) — операция заблокирована.\n`);
  process.exit(2);
}
