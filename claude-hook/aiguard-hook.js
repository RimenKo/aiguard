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

// Fail-closed on require error: if patterns or the shared allow/ignore
// helpers can't load, block the operation. Silently passing writes when
// the security check can't run defeats the purpose.
let SECRET_PATTERNS, matchIsAllowed, isFileIgnored;
try {
  ({ SECRET_PATTERNS } = require(path.join(__dirname, '..', 'src', 'patterns')));
  ({ matchIsAllowed, isFileIgnored } = require(path.join(__dirname, '..', 'src', 'allow')));
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

// Fail-closed on any error while collecting text or scanning for secrets:
// a crash here must never let a write through unchecked (same reasoning as
// the patterns-require fail-closed above). This also covers a future
// pattern's validate() throwing — that would otherwise crash the process
// with no exit(2).
try {
  // Collect every text chunk being written by this tool call:
  //   Write        → ti.content
  //   Edit         → ti.new_string
  //   MultiEdit    → ti.edits[i].new_string  (was missing before this fix)
  //   NotebookEdit → ti.new_source  (was missing before this fix — the matcher
  //                  regex /Write|Edit|MultiEdit/ already fires on this tool
  //                  since 'NotebookEdit' contains the substring 'Edit', but
  //                  the hook never read this field, so a secret in a Jupyter
  //                  cell passed through completely silently, exit 0)
  const texts = [];
  if (ti.content) texts.push(ti.content);
  if (ti.new_string) texts.push(ti.new_string);
  if (ti.new_source) texts.push(ti.new_source);
  if (Array.isArray(ti.edits)) {
    for (const e of ti.edits) {
      if (e && e.new_string) texts.push(e.new_string);
    }
  }

  const content = texts.join('\n');
  if (!content) process.exit(0);

  // .aiguardignore: a file listed there is not scanned at all — same rule
  // as the publish-time CLI. Checked before the pattern loop so an ignored
  // path can contain any fixture without blocking the write. file_path is
  // Write/Edit/MultiEdit; notebook_path is NotebookEdit.
  const targetPath = ti.file_path || ti.notebook_path;
  if (targetPath && isFileIgnored(targetPath)) process.exit(0);

  // Cap scanned size: this is an interactive write-time hook (blocks the
  // editor until it exits), not the publish-time scan, so it must return in a
  // fraction of a second, not tolerate the scanner's 5 MB ceiling
  // (src/scanner.js MAX_FILE_SIZE_BYTES). A well-formed secret is never
  // megabytes long, so nothing real is missed by not scanning past this point
  // — fail open (allow, like scanner.js's file_too_large WARN) rather than
  // fail closed, since blocking every large-but-legitimate write would make
  // the hook itself the productivity problem it's meant to avoid.
  const MAX_CONTENT_SIZE_BYTES = 1 * 1024 * 1024;
  if (Buffer.byteLength(content, 'utf8') > MAX_CONTENT_SIZE_BYTES) {
    process.stderr.write(`aiguard: содержимое больше ${MAX_CONTENT_SIZE_BYTES / (1024 * 1024)} МБ — не проверено на секреты (лимит интерактивного хука).\n`);
    process.exit(0);
  }

  // Default severity matches scanner.js's scanContent() default for regular
  // project files ('HIGH'). A pattern's severityOverride (if it defines one —
  // see src/patterns.js) can lower a specific match to 'WARN'; only
  // HIGH/CRITICAL block the write, so the hook agrees with the publish-time
  // scan instead of blocking things the scan itself would only warn about. No
  // pattern currently defines one: the BIP39 mnemonic patterns intentionally
  // always stay HIGH regardless of separator (comma/JSON/space) — a missed
  // real seed is unrecoverable, while a false-positive tag list is just a
  // WARN a human can dismiss.
  // Walk every match per pattern (not just the first) — mirrors
  // src/scanner.js's scanContent(). A pattern can match more than once in the
  // same content (e.g. a decoy word-list that fails validate() followed
  // later by a real secret of the same pattern); stopping at the first match
  // meant a real secret sitting after a benign false-positive of the same
  // pattern was never checked at all.
  for (const { name, regex, validate, severityOverride } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    let m;
    while ((m = regex.exec(content)) !== null) {
      if (m[0].length === 0) { regex.lastIndex++; continue; }
      if (validate) {
        try { if (!validate(m[0])) continue; } catch (_) { continue; }
      }
      if (matchIsAllowed(content, m.index, m[0].length, validate)) continue;
      let severity = 'HIGH';
      if (severityOverride) {
        try { severity = severityOverride(m[0]) ?? severity; } catch (_) { severity = 'HIGH'; }
      }
      if (severity === 'WARN') {
        process.stderr.write(`aiguard: похоже на секрет (${name}), но низкая уверенность — не заблокировано.\n`);
        continue;
      }
      process.stderr.write(`aiguard: обнаружен секрет (${name}) — операция заблокирована.\n`);
      process.exit(2);
    }
  }
} catch (err) {
  process.stderr.write(`aiguard: ошибка при проверке на секреты — ${err.message}\nОперация заблокирована.\n`);
  process.exit(2);
}
