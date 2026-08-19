'use strict';

const fs = require('fs');
const path = require('path');

// Same-line suppression, modeled on gitleaks:allow. leakward:allow is the
// public spelling; aiguard:allow and gitleaks:allow stay as aliases so
// existing comments (this repo has 20+ gitleaks:allow fixtures, plus the
// aiguard:allow lines that motivated the feature) keep working. Requiring
// a leakward:allow-only spelling would have left every existing comment
// still blocking the write hook. \b so "leakward:allowlist" is not a marker.
const ALLOW_MARKER_RE = /(?:leakward|aiguard|gitleaks):allow\b/;
const IGNORE_FILENAMES = ['.aiguardignore', '.leakwardignore'];

function lineHasAllowMarker(line) {
  return ALLOW_MARKER_RE.test(line);
}

// A finding is suppressed when the match's overlapping lines carry a
// marker AND any leftover unmarked text is not itself a valid secret.
// Same-line markers always suppress. A marker on a neighboring line that
// a greedy multiline regex (BIP39) merely swallowed does NOT suppress,
// because the leftover seed still validates. A marker on the previous or
// next non-overlapping line never suppresses.
function isLineBreak(ch) {
  return ch === '\n' || ch === '\r' || ch === '\u2028' || ch === '\u2029';
}

function matchIsAllowed(content, matchIndex, matchLength, validate) {
  if (typeof content !== 'string' || matchIndex < 0) return false;
  const start = matchIndex;
  const end = matchIndex + Math.max(matchLength || 0, 1);
  // Treat LF, CR, CRLF, and Unicode line/paragraph separators as breaks —
  // a CR-only or U+2028 file must not collapse into one "line".
  let lineStart = start;
  while (lineStart > 0 && !isLineBreak(content[lineStart - 1])) lineStart--;
  let lineEnd = Math.max(end - 1, start);
  while (lineEnd < content.length && !isLineBreak(content[lineEnd])) lineEnd++;
  const block = content.slice(lineStart, lineEnd);
  const lines = block.split(/\r\n|\n|\r|\u2028|\u2029/);
  const unmarked = [];
  let marked = 0;
  for (const line of lines) {
    if (lineHasAllowMarker(line)) marked++;
    else unmarked.push(line);
  }
  if (marked === 0) return false;
  if (unmarked.length === 0) return true;
  // A greedy multiline regex (BIP39 `{11,}`) can swallow the next
  // 3–8-letter word — including "leakward" / "aiguard" on a following
  // `leakward:allow` / `aiguard:allow` line. If the leftover unmarked text is still a
  // valid secret on its own, the marker was not on the secret: do
  // not suppress. Patterns without validate() stay fail-closed: a
  // leftover unmarked line is reported.
  if (typeof validate !== 'function') return false;
  try {
    if (validate(unmarked.join('\n'))) return false;
  } catch (_) { /* leftover is not itself a valid secret */ }
  return true;
}

function parseIgnoreRules(content) {
  const rules = [];
  if (!content) return rules;
  if (content.charCodeAt(0) === 0xFEFF) content = content.slice(1);
  content = content.normalize('NFC');
  for (const raw of content.split(/\r\n|\n|\r|\u2028|\u2029/)) {
    // gitignore: unescaped trailing spaces are insignificant. Leading
    // spaces stay part of the pattern.
    const line = raw.replace(/\\ /g, '\0').replace(/[ \t]+$/, '').replace(/\0/g, ' ');
    if (!line || line.startsWith('#')) continue;
    let negated = false;
    let pattern = line;
    if (pattern.startsWith('!')) {
      negated = true;
      pattern = pattern.slice(1);
      if (!pattern) continue;
    }
    rules.push({ negated, pattern });
  }
  return rules;
}

function isIgnoreFilename(relPath) {
  const posix = String(relPath || '').split(/[\\/]/).join('/');
  return IGNORE_FILENAMES.includes(posix);
}

function loadIgnoreRules(rootDir) {
  if (!rootDir) return [];
  // Legacy file first, leakward last so a new .leakwardignore can override
  // a leftover .aiguardignore via gitignore last-match-wins.
  const rules = [];
  for (const name of IGNORE_FILENAMES) {
    try {
      rules.push(...parseIgnoreRules(fs.readFileSync(path.join(rootDir, name), 'utf8')));
    } catch (_) {
      // Missing or unreadable: skip that file. Safer than treating a
      // read error as "ignore the whole tree".
    }
  }
  return rules;
}

function globToRegExpSource(glob) {
  let src = '';
  let i = 0;
  while (i < glob.length) {
    if (glob[i] === '\\' && i + 1 < glob.length) {
      const next = glob[i + 1];
      // Escaped glob metacharacters must also be escaped in the regex
      // (`\*` → `\*`, not a bare `*` quantifier).
      if (/[.+^${}()|\\*?[\]]/.test(next)) src += '\\';
      src += next;
      i += 2;
      continue;
    }
    if (glob[i] === '*' && glob[i + 1] === '*') {
      if (glob[i + 2] === '/') {
        src += '(?:.*/)?';
        i += 3;
      } else {
        src += '.*';
        i += 2;
      }
    } else if (glob[i] === '*') {
      src += '[^/]*';
      i += 1;
    } else if (glob[i] === '?') {
      src += '[^/]';
      i += 1;
    } else if (glob[i] === '[') {
      const close = glob.indexOf(']', i + 1);
      if (close === -1) {
        src += '\\[';
        i += 1;
      } else {
        src += glob.slice(i, close + 1);
        i = close + 1;
      }
    } else {
      if (/[.+^${}()|\\]/.test(glob[i])) src += '\\';
      src += glob[i];
      i += 1;
    }
  }
  return src;
}

function compileRule(pattern) {
  // Do not turn every `\` into `/` — that made `\*` (literal asterisk in
  // gitignore) compile as `/*` and ignore the whole tree. Path separators
  // in this file are `/`, same as gitignore.
  let p = pattern;
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.replace(/\/+$/, '');
  // A slash anywhere except a trailing one (already stripped) anchors the
  // pattern at the ignore-file directory — same rule as gitignore.
  const anchored = p.startsWith('/') || p.includes('/');
  if (p.startsWith('/')) p = p.slice(1);

  const body = globToRegExpSource(p);
  const prefix = anchored ? '^' : '(?:^|/)';
  // Non-dir patterns match the path itself or anything under it (so `build`
  // ignores `build/output.js`). Dir-only patterns require a child path
  // (`logs/` does not ignore a file whose whole name is `logs`).
  const suffix = dirOnly ? '/.*$' : '(?:/.*)?$';
  try {
    return new RegExp(prefix + body + suffix);
  } catch (_) {
    // A broken character class (e.g. `[]`) must not crash the hook —
    // that would block every Write, including a fix to the ignore file.
    return null;
  }
}

function isPathIgnored(relPath, rules) {
  if (!rules || rules.length === 0) return false;
  const posix = String(relPath || '').split(/[\\/]/).join('/').normalize('NFC');
  if (!posix || posix === '.') return false;

  let ignored = false;
  for (const rule of rules) {
    if (rule._re === undefined) rule._re = compileRule(rule.pattern);
    if (!rule._re) continue;
    if (rule._re.test(posix)) ignored = !rule.negated;
  }
  return ignored;
}

// The write-time hook has no explicit project root — Claude Code launches
// it with cwd = the project being edited, which is the same "root of the
// scanned tree" the CLI uses. Only that root's ignore files apply
// (we do not walk up to $HOME or /): a stray home-directory ignore file
// must not silently disable the hook for every project.
function isFileIgnored(filePath, cwd) {
  if (!filePath) return false;
  let root = path.resolve(cwd || process.cwd());
  try { root = fs.realpathSync(root); } catch (_) { /* cwd missing — keep lexical */ }
  const rules = loadIgnoreRules(root);
  if (rules.length === 0) return false;
  let abs = path.resolve(root, filePath);
  try { abs = fs.realpathSync(abs); } catch (_) { /* new file, not on disk yet */ }
  const rel = path.relative(root, abs);
  if (!rel || rel === '.' || rel.startsWith('..') || path.isAbsolute(rel)) return false;
  // Always scan the ignore files themselves for secrets. (A broken glob no
  // longer locks the hook — compileRule returns null — but a live key
  // pasted into the ignore file must still be blocked.)
  if (isIgnoreFilename(rel)) return false;
  return isPathIgnored(rel, rules);
}

module.exports = {
  IGNORE_FILENAMES,
  isIgnoreFilename,
  lineHasAllowMarker,
  matchIsAllowed,
  parseIgnoreRules,
  loadIgnoreRules,
  isPathIgnored,
  isFileIgnored,
};
