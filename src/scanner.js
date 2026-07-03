'use strict';

const fs = require('fs');
const path = require('path');
const { AI_FOLDERS, AI_SECRET_FILES, SECRET_PATTERNS } = require('./patterns');

/**
 * Returns list of files that will be included in npm publish.
 * Union of two real sources of truth: `git ls-files` (what git tracks / would
 * `git push`) and `npm pack --dry-run --json` (what npm would actually
 * publish). No hand-rolled .gitignore/.npmignore parsing — both commands
 * already implement their own exclusion rules correctly (including the
 * package.json "files" field, which npm applies natively), so re-deriving
 * either ourselves only adds a second, worse copy of logic that already
 * exists and is exactly right.
 */

// npm never publishes these regardless of .npmignore/.gitignore/git tracking —
// they're excluded from the packed tarball unconditionally. A git-tracked (or
// merely untracked-and-unignored) node_modules would otherwise ride along
// through the git-sourced half of the union below and get reported as "will
// be published", which isn't true and just trains the user to distrust
// findings.
//
// Only ever applied to the git-sourced half of the union, never to npm's own
// manifest: verified against npm-packlist's own source, npm's default rule
// for these two names is anchored ("/node_modules"), i.e. it only excludes
// them at the project ROOT — a nested node_modules/ (e.g. a vendored
// src/node_modules/) is real, publishable content as far as npm is
// concerned. Filtering npm's own confirmed output here would wrongly drop
// that. Over-filtering the git side is the safe direction to err in: it's
// merely our own supplementary source, and anything real npm actually
// publishes gets added back by the union regardless.
const NPM_NEVER_PUBLISHED = ['node_modules', '.git'];

// Per-segment match, not prefix match, for the same reason NPM_NEVER_PUBLISHED
// is only ever applied to the git-sourced half of the union (real npm's own
// root-anchored rule is applied by npm itself, not here). Splitting on both
// separators covers paths already normalized to path.sep as well as the rare
// literal '/' that slips through.
function isUnderAnyDir(relPath, dirNames) {
  const segments = relPath.split(/[\\/]/);
  return dirNames.some((d) => segments.includes(d));
}

// 10s is generous for listing paths (as opposed to scanGitHistory's diff
// content, which can be large) — just a backstop against a wedged git
// process (lock contention, stalled network FS) hanging the whole scan.
const GIT_COMMAND_TIMEOUT_MS = 10000;

// npm CLI startup (module resolution, config file reads) is slower than a
// single git invocation, so this gets more headroom before being treated as
// wedged. Still just a backstop — a local dry-run pack does no network I/O.
const NPM_COMMAND_TIMEOUT_MS = 15000;

function isGitRepo(projectRoot) {
  const { execFileSync } = require('child_process');
  try {
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
      cwd: projectRoot, stdio: 'pipe', timeout: GIT_COMMAND_TIMEOUT_MS,
    });
    return true;
  } catch (_) {
    return false;
  }
}

// Returns the files git actually knows about — tracked files plus untracked
// files that aren't excluded — or null if the `git ls-files` call itself
// failed (huge output, timeout, permissions, corrupted index). This is the
// FIRST of the two sources of truth this file relies on: git's own exclude
// engine evaluates .gitignore (including "!pattern" negation) exactly like a
// real `git push` would, and a file committed before a later .gitignore rule
// excluded it stays tracked (git never re-applies ignore rules
// retroactively) — both cases a hand-rolled ignore-file parser gets wrong.
// Paths are normalized to path.sep — git always prints '/'.
function getGitTrackedFiles(projectRoot) {
  const { execFileSync } = require('child_process');
  try {
    const output = execFileSync(
      'git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
      { cwd: projectRoot, stdio: 'pipe', maxBuffer: 50 * 1024 * 1024, timeout: GIT_COMMAND_TIMEOUT_MS }
    ).toString('utf8');
    return output.split('\0').filter(Boolean).map((p) => p.split('/').join(path.sep));
  } catch (_) {
    return null;
  }
}

// Returns the EXACT file list `npm publish` would ship, straight from npm's
// own packer — or null if the call itself couldn't be trusted (npm missing,
// timeout, non-zero exit, or output that doesn't parse as the manifest shape
// we expect), so the caller can fall back instead of treating "npm failed"
// as "this project publishes nothing".
//
// --ignore-scripts is mandatory, not optional: `npm pack`, even with
// --dry-run, still executes the target's prepack/postpack lifecycle scripts
// (verified empirically — dry-run only skips writing the tarball, not
// running scripts). A secret scanner has no business executing arbitrary
// code from the project it's supposed to be passively reading.
//
// Paths come back npm-normalized with '/' separators; converted to path.sep
// to compare equal with the rest of this file's path.relative()-produced
// paths (same reasoning as getGitTrackedFiles() above).
//
// `errorDetail`, if passed, gets npm's own one-line explanation pushed onto
// it on failure (e.g. "code EJSONPARSE" for a broken package.json) — so the
// caller's warning says *why* npm pack couldn't be trusted instead of just
// that it couldn't.
function getNpmPackFiles(projectRoot, errorDetail) {
  const { execFileSync } = require('child_process');
  let output;
  try {
    output = execFileSync(
      'npm', ['pack', '--dry-run', '--json', '--ignore-scripts'],
      { cwd: projectRoot, stdio: 'pipe', maxBuffer: 50 * 1024 * 1024, timeout: NPM_COMMAND_TIMEOUT_MS }
    ).toString('utf8');
  } catch (err) {
    if (errorDetail) {
      const line = (err.stderr || '').toString('utf8')
        .split('\n')
        .map((l) => l.replace(/^npm error\s*/i, '').trim())
        .find(Boolean);
      errorDetail.push(line || err.message || 'неизвестная ошибка');
    }
    return null;
  }

  let parsed;
  try { parsed = JSON.parse(output); } catch (_) { return null; }

  const manifest = Array.isArray(parsed) ? parsed[0] : null;
  if (!manifest || !Array.isArray(manifest.files)) return null;

  return manifest.files
    .filter((f) => f && typeof f.path === 'string')
    .map((f) => f.path.split('/').join(path.sep));
}

// Wraps getGitTrackedFiles() with the one filter that isn't about exclusion
// rules at all: dropping a tracked path that is itself a symlink, so its
// target is only ever reached and scanned through its OWN tracked entry.
// Without this, a git-tracked symlink to another tracked file would report
// that file's secret twice — once per name.
//
// Known accepted trade-off: if the symlink's target is itself excluded from
// this file list (e.g. gitignored, so it never gets its own entry),
// filtering the symlink out here means a secret reachable ONLY through that
// symlink goes unscanned. That's intentional, not a regression: only the
// symlink's target-path STRING is ever committed/published, never the
// target's content, so nothing actually leaks this way — flagging it would
// have produced a false "will be published" HIGH instead. Properly telling
// "target excluded but harmless" apart from "target excluded and genuinely
// at risk" would need following the symlink and re-checking its target
// against the full source-of-truth union, which is out of scope here.
//
// Returns null when there's nothing usable to report: either projectRoot
// isn't a git repository at all (normal — e.g. before `git init`, no warning
// needed), or it is one but `git ls-files` itself failed (abnormal — the
// repo is there but broken, so `warnings`, if passed, gets a notice that
// coverage just got worse instead of silently looking as thorough as a
// clean run).
function getGitFileList(projectRoot, warnings) {
  if (!isGitRepo(projectRoot)) return null;

  const gitFiles = getGitTrackedFiles(projectRoot);
  if (gitFiles === null) {
    if (warnings) {
      warnings.push('Это git-репозиторий, но команда "git ls-files" не отработала (повреждённый индекс, таймаут или сбой) — вместо списка git используется полный обход папки проекта, без учёта .gitignore.');
    }
    return null;
  }

  return gitFiles.filter((f) => {
    try {
      return !fs.lstatSync(path.join(projectRoot, f)).isSymbolicLink();
    } catch (_) {
      return true; // gone since git listed it — let safeRead()'s own try/catch handle the miss
    }
  });
}

// Resolves `relPath` against `root` and returns the absolute path only if it
// stays inside root. Defense in depth for section 3 in scan() below:
// publishFiles comes from git/npm's own output, which shouldn't ever contain
// a traversal, but this guards against reading (and printing) a file
// outside the project if it somehow did. Also rejects a path whose real
// target (after resolving symlinks) escapes root.
//
// `root` itself is resolved through realpath too, not just `full` — on
// macOS/Linux common roots like /tmp are themselves symlinks (/tmp ->
// /private/tmp). Comparing a lexical root against a realpath'd file would
// make every file look like it escapes root, silently dropping the whole
// project from the scan.
function realRootOf(root) {
  try {
    return fs.realpathSync(path.resolve(root));
  } catch (_) {
    return path.resolve(root); // project root doesn't exist on disk (yet) — lexical fallback
  }
}

function resolveWithinRoot(root, relPath) {
  const resolvedRoot = realRootOf(root);
  const full = path.resolve(resolvedRoot, relPath);
  if (full !== resolvedRoot && !full.startsWith(resolvedRoot + path.sep)) {
    return null;
  }
  try {
    const real = fs.realpathSync(full);
    if (real !== resolvedRoot && !real.startsWith(resolvedRoot + path.sep)) {
      return null;
    }
  } catch (err) {
    // ENOENT (not created yet) is fine — the string-based check above already ran.
    // Any other error (e.g. a broken/permission-denied symlink in the middle of
    // the path) means we can't confirm where it really points — fail closed.
    if (err.code !== 'ENOENT') return null;
  }
  return full;
}

// Last-resort fallback for when a source of truth this scan needs isn't
// available (git for a non-npm project, or npm for an npm project whose
// `npm pack` call failed — see getPublishFiles and scan() below) —
// deliberately NOT a re-implemented ignore-file parser. It walks the whole
// tree, skipping only the two directories npm categorically never publishes
// at the root (see NPM_NEVER_PUBLISHED), and nothing else: no
// .gitignore/.npmignore parsing, no "files" field emulation, no glob
// matching. Scanning too much (e.g. a gitignored build artifact that
// wouldn't really publish) is the safe direction to err in for a leak
// scanner — silently scanning too little, the way a half-correct
// ignore-file emulation risks, is not.
//
// `warnings`, if passed, collects a notice for each directory that couldn't
// even be listed (e.g. permission denied) — the one case where this walk
// itself would otherwise silently scan less than it looks like it does. A
// single file disappearing between readdir and lstat (a normal race, not a
// coverage gap) is not reported here — same as the rest of this file's walks.
function walkAllFiles(startDir, warnings) {
  const results = [];
  const visited = new Set();
  // Итеративный обход — без рекурсии, не упирается в лимит стека
  const queue = [startDir];

  while (queue.length > 0) {
    const dir = queue.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir);
    } catch (_) {
      if (warnings) warnings.push(path.relative(startDir, dir) || '.');
      continue;
    }

    for (const entry of entries) {
      if (entry === 'node_modules' || entry === '.git') continue;

      const full = path.join(dir, entry);
      const rel  = path.relative(startDir, full);

      let stat;
      try { stat = fs.lstatSync(full); } catch (_) { continue; } // gone between readdir and lstat — race, not a coverage gap
      if (stat.isSymbolicLink()) continue;

      if (stat.isDirectory()) {
        let realPath;
        try { realPath = fs.realpathSync(full); } catch (_) { continue; }
        if (visited.has(realPath)) continue;
        visited.add(realPath);
        queue.push(full);
      } else {
        results.push(rel);
      }
    }
  }
  return results;
}

// `gitWarnings`, if passed, collects a notice when git-aware file discovery
// (see getGitFileList above) couldn't complete.
// `npmWarnings`, if passed, collects a notice when `npm pack --dry-run`
// itself couldn't complete (see getNpmPackFiles above).
// `npmConfirmed`, if passed, gets every path npm's own manifest actually
// listed (NFC-normalized) — so the caller can tell "npm itself will publish
// this" apart from "only git tracks this". That distinction matters for
// messaging: a file caught ONLY through git tracking really will leak, but
// via `git push`, not `npm publish` — saying "will be published to npm"
// about it is factually wrong about the channel, even though flagging it at
// all is correct. This also naturally covers the case where .npmignore
// excludes a file that's git-tracked anyway (e.g. via `git add -f`): npm's
// own manifest won't confirm it, so it correctly ends up reported as
// git-only, never as "will publish to npm".
// `walkWarnings`, if passed, collects a notice for each directory the
// walkAllFiles() fallback (see above) couldn't even list — only reachable
// when npm pack itself failed, so this scan is that fallback's one caller.
function getPublishFiles(projectRoot, gitWarnings, npmWarnings, npmConfirmed, walkWarnings) {
  const rawGitFiles = getGitFileList(projectRoot, gitWarnings);
  const gitFiles = (rawGitFiles || []).filter((f) => !isUnderAnyDir(f, NPM_NEVER_PUBLISHED));

  const npmErrorDetail = [];
  const npmFiles = getNpmPackFiles(projectRoot, npmErrorDetail);

  if (npmFiles === null) {
    if (npmWarnings) {
      const reason = npmErrorDetail[0] ? ` Причина: ${npmErrorDetail[0]}` : '';
      npmWarnings.push(`Команда "npm pack --dry-run" не отработала (npm недоступен, таймаут, невалидный package.json или другая ошибка самого npm) — вместо точного списка публикации используется полный обход папки проекта (без учёта .npmignore и "files"), чтобы не пропустить секрет из-за деградации источника.${reason}`);
    }
    const fallbackFiles = walkAllFiles(projectRoot, walkWarnings).filter((f) => !isUnderAnyDir(f, NPM_NEVER_PUBLISHED));
    // Both lists must compare byte-for-byte per file, or the Set below fails
    // to de-duplicate a name that differs only in Unicode normalization
    // form: git normalizes to NFC, but fs.readdirSync() (used by
    // walkAllFiles) can return NFD for the same name — common on macOS for
    // names with combining accents (e.g. "café.js").
    const merged = new Set(gitFiles.map((f) => f.normalize('NFC')));
    for (const f of fallbackFiles) merged.add(f.normalize('NFC'));
    return Array.from(merged);
  }

  // Same NFC-normalizing merge as the fallback branch above, for the same
  // reason: npm's output and git's output must compare byte-for-byte per
  // file for the Set to actually de-duplicate.
  const npmFilesNFC = npmFiles.map((f) => f.normalize('NFC'));
  if (npmConfirmed) {
    for (const f of npmFilesNFC) npmConfirmed.add(f);
  }

  const merged = new Set(gitFiles.map((f) => f.normalize('NFC')));
  for (const f of npmFilesNFC) merged.add(f);
  return Array.from(merged);
}

/**
 * Main scan: returns array of findings { file, type, match }
 */
function scan(projectRoot) {
  projectRoot = projectRoot || process.cwd();
  const findings = [];

  const pkgPath = path.join(projectRoot, 'package.json');
  const isNpmProject = fs.existsSync(pkgPath);

  // For npm projects: only files that will be published (git ∪ npm pack).
  // For other projects (Python, Go, etc.): whatever git tracks (would `git push`).
  const gitWarnings = [];
  const npmWarnings = [];
  const npmConfirmedFiles = new Set();
  const walkWarnings = [];
  let publishFiles;
  if (isNpmProject) {
    publishFiles = getPublishFiles(projectRoot, gitWarnings, npmWarnings, npmConfirmedFiles, walkWarnings);
  } else {
    const gitFiles = getGitFileList(projectRoot, gitWarnings);
    publishFiles = gitFiles !== null ? gitFiles : walkAllFiles(projectRoot, walkWarnings);
  }

  const context = isNpmProject ? 'npm-пакет' : 'git-коммит';
  // True only when npm pack --dry-run itself succeeded — i.e. npmConfirmedFiles
  // is a trustworthy "npm will really publish exactly this" answer, not an
  // empty set from a failed/skipped call. Only then can "not in
  // npmConfirmedFiles" be read as "npm itself excludes this" rather than
  // "we don't know".
  const npmPackSucceeded = isNpmProject && npmWarnings.length === 0;

  // 0. git-aware file discovery didn't fully complete — say so instead of
  //    silently looking as thorough as a normal run (see getGitFileList).
  for (const detail of gitWarnings) {
    findings.push({ severity: 'WARN', type: 'git_awareness_degraded', file: '.', detail });
  }

  // 0b. `npm pack --dry-run` itself didn't complete — say so instead of
  //     silently relying on a full-directory fallback without flagging the
  //     gap (see getNpmPackFiles / getPublishFiles).
  for (const detail of npmWarnings) {
    findings.push({ severity: 'WARN', type: 'npm_pack_degraded', file: '.', detail });
  }

  // 0c. The walkAllFiles() fallback itself couldn't list one or more
  //     directories (e.g. permission denied) — say so instead of silently
  //     scanning less than even that last-resort walk claims to cover.
  for (const dir of walkWarnings) {
    findings.push({
      severity: 'WARN',
      type: 'directory_unreadable',
      file: dir,
      detail: `Не удалось прочитать папку "${dir}" при полном обходе проекта (нет доступа или похожая ошибка) — её содержимое пропущено, секреты внутри не проверены.`,
    });
  }

  // 1. Check for AI tool folders in published files
  for (const aiFolder of AI_FOLDERS) {
    const inPublish = publishFiles.filter(f => f.startsWith(aiFolder + '/') || f === aiFolder);
    if (inPublish.length > 0) {
      // npm pack succeeded but confirms only SOME (or none) of these paths →
      // the rest are only here via the git-sourced half of the union — could
      // be git-tracked-then-ignored, or simply untracked and excluded by npm
      // for an unrelated reason (e.g. npm's own unanchored `.npmrc` rule)
      // that git tracking alone doesn't tell us. Either way real npm won't
      // publish them, so don't claim "уйдёт в npm-пакет" — but also don't
      // claim "отслеживается в git"/"убери из истории git" as fact, since we
      // don't actually know the file was ever committed. Count both groups
      // separately rather than a single any()-check, or a folder with even
      // one npm-confirmed file would claim the whole folder ships via npm.
      let detail;
      if (npmPackSucceeded) {
        const npmCount = inPublish.filter((f) => npmConfirmedFiles.has(f)).length;
        const gitOnlyCount = inPublish.length - npmCount;
        if (npmCount === 0) {
          detail = `Папка AI-инструмента не уйдёт через npm publish (${inPublish.length} файлов), но остаётся в проекте и может раскрыться другим путём — например при git push, если файлы уже закоммичены. Добавь в .gitignore; если уже коммитились — убери из истории git.`;
        } else if (gitOnlyCount === 0) {
          detail = `Папка AI-инструмента попадёт в ${context} (${inPublish.length} файлов). Добавь в .npmignore/.gitignore.`;
        } else {
          detail = `Папка AI-инструмента: ${npmCount} файлов попадёт в npm-пакет, ещё ${gitOnlyCount} npm publish не включит, но они остаются в проекте и могут раскрыться другим путём (например git push, если уже закоммичены). Добавь в .npmignore/.gitignore; если уже коммитились — убери из истории git.`;
        }
      } else {
        detail = `Папка AI-инструмента попадёт в ${context} (${inPublish.length} файлов). Добавь в .npmignore/.gitignore.`;
      }
      findings.push({
        severity: 'HIGH',
        type: 'ai_folder_in_publish',
        file: aiFolder + '/',
        detail,
      });
    }
  }

  // 2. Check known AI secret files
  for (const secretFile of AI_SECRET_FILES) {
    const full = path.join(projectRoot, secretFile);
    if (!fs.existsSync(full)) continue;

    const inPublish = publishFiles.includes(secretFile);
    if (inPublish) {
      // Same reasoning as section 1 above: only relabel the channel when npm
      // pack ran successfully and positively excluded this exact file — and
      // even then, don't assert it's git-tracked as fact (it might only be
      // untracked-and-excluded-by-npm-for-an-unrelated-reason), just that
      // npm publish won't be the leak path.
      const npmConfirms = npmConfirmedFiles.has(secretFile);
      const detail = (npmPackSucceeded && !npmConfirms)
        ? 'Этот файл содержит API-ключи и токены — npm publish его не включит, но он остаётся в проекте и может раскрыться другим путём (например git push, если уже закоммичен). Добавь в .gitignore; если уже коммитился — убери из истории git.'
        : `Этот файл содержит API-ключи и токены — он уйдёт в ${context}!`;
      // File WILL be published or leaked — CRITICAL, scan content too
      findings.push({
        severity: 'CRITICAL',
        type: 'ai_secret_file_published',
        file: secretFile,
        detail,
      });
      const content = safeRead(full);
      if (content) {
        findings.push(...scanContent(secretFile, content, 'CRITICAL'));
      }
    } else {
      // File exists locally but excluded — scan content anyway so the user
      // knows which specific secrets are at risk if the ignore ever breaks.
      const content = safeRead(full);
      const secretsInside = content ? scanContent(secretFile, content, 'WARN') : [];
      if (secretsInside.length > 0) {
        findings.push({
          severity: 'WARN',
          type: 'ai_secret_file_exists',
          file: secretFile,
          detail: `Исключён из публикации, но содержит ${secretsInside.length} секрет(ов) — опасно если .npmignore сломается.`,
        });
        findings.push(...secretsInside);
      } else {
        findings.push({
          severity: 'WARN',
          type: 'ai_secret_file_exists',
          file: secretFile,
          detail: 'Файл существует локально, но исключён из публикации. Убедись, что .npmignore актуален.',
        });
      }
    }
  }

  // 3. Scan all published files for secret patterns
  for (const relFile of publishFiles) {
    if (AI_SECRET_FILES.includes(relFile)) continue;
    if (isBinary(relFile)) continue;

    const full = resolveWithinRoot(projectRoot, relFile);
    if (!full) continue; // defense in depth — publishFiles should already be root-safe
    const content = safeRead(full);
    if (!content) continue;

    findings.push(...scanContent(relFile, content, 'HIGH'));
  }

  // 4. Check .npmignore is missing AI folders (npm projects only)
  //    Skip if "files" field is set in package.json — it already restricts what gets published.
  let pkgFiles = [];
  if (isNpmProject) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      pkgFiles = pkg.files || [];
    } catch (_) {}
  }
  const hasFilesField = pkgFiles.length > 0;

  if (isNpmProject && !hasFilesField) {
    const npmIgnorePath = path.join(projectRoot, '.npmignore');
    const hasNpmIgnore = fs.existsSync(npmIgnorePath);
    if (!hasNpmIgnore) {
      const hasGitIgnore = fs.existsSync(path.join(projectRoot, '.gitignore'));
      if (!hasGitIgnore) {
        findings.push({
          severity: 'WARN',
          type: 'no_npmignore',
          file: '.npmignore',
          detail: 'Нет .npmignore — все файлы проекта уйдут в npm, включая папки AI-инструментов.',
        });
      }
    } else {
      const ignoreContent = fs.readFileSync(npmIgnorePath, 'utf8');
      for (const aiFolder of AI_FOLDERS) {
        // Only warn if the folder actually exists — otherwise no leak risk
        if (!ignoreContent.includes(aiFolder) && fs.existsSync(path.join(projectRoot, aiFolder))) {
          findings.push({
            severity: 'WARN',
            type: 'ai_folder_not_in_npmignore',
            file: '.npmignore',
            detail: `Папка ${aiFolder} не исключена из .npmignore.`,
          });
        }
      }
    }
  }

  return findings;
}

function scanContent(filePath, content, severity) {
  const results = [];
  for (const { name, regex, validate } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    let m;
    while ((m = regex.exec(content)) !== null) {
      if (m[0].length === 0) { regex.lastIndex++; continue; }
      if (validate) {
        try { if (!validate(m[0])) continue; } catch (_) { continue; }
      }
      results.push({
        severity,
        type: 'secret_pattern',
        file: filePath,
        detail: `${name}: ${mask(m[0])}`,
      });
    }
  }
  return results;
}

function mask(value) {
  if (value.length <= 8) return '***';
  return value.slice(0, 6) + '***' + value.slice(-4);
}

function safeRead(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    if (isBinaryBuffer(buf)) return null;
    return buf.toString('utf8');
  } catch (_) {
    return null;
  }
}

function isBinary(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return ['.png','.jpg','.jpeg','.gif','.ico','.woff','.woff2',
          '.ttf','.eot','.pdf','.zip','.tar','.gz','.mp4','.mp3'].includes(ext);
}

function isBinaryBuffer(buf) {
  for (let i = 0; i < Math.min(512, buf.length); i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

/**
 * Scans git history for secrets that were ever committed.
 * Extracts all "added" lines from every commit and runs secret patterns on them.
 * Returns deduplicated findings tagged with the first commit SHA where the secret appeared.
 */
function scanGitHistory(projectRoot) {
  const { execFileSync } = require('child_process');
  const findings = [];

  // Verify this is a git repository
  try {
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: projectRoot, stdio: 'pipe' });
  } catch (_) {
    return [{ severity: 'WARN', type: 'no_git', file: '.', detail: 'Не гит-репозиторий — история не проверяется.' }];
  }

  // Get all added lines from all commits (additions only, no context)
  // Split by commit so we can tag findings with the SHA
  let logOutput;
  try {
    logOutput = execFileSync(
      'git', ['log', '--all', '--no-color', '-U0', '--diff-filter=A', '--format=COMMIT:%H'],
      { cwd: projectRoot, stdio: 'pipe', maxBuffer: 50 * 1024 * 1024 }
    ).toString();
  } catch (_) {
    return [];
  }

  // Parse into {sha, addedLines} blocks
  const blocks = [];
  let current = null;
  for (const line of logOutput.split('\n')) {
    if (line.startsWith('COMMIT:')) {
      current = { sha: line.slice(7, 15), lines: [] };
      blocks.push(current);
    } else if (current && line.startsWith('+') && !line.startsWith('+++')) {
      current.lines.push(line.slice(1));
    }
  }

  // Scan each commit block, deduplicate by (pattern + masked value)
  const seen = new Set();
  for (const { sha, lines } of blocks) {
    if (!lines.length) continue;
    const hits = scanContent(`git:коммит ${sha}`, lines.join('\n'), 'HIGH');
    for (const hit of hits) {
      const key = hit.detail;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push(hit);
      }
    }
  }

  return findings;
}

module.exports = { scan, scanGitHistory };
