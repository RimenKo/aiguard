'use strict';

const fs = require('fs');
const path = require('path');
const { AI_FOLDERS, AI_SECRET_FILES, SECRET_PATTERNS } = require('./patterns');

/**
 * Returns list of files that will be included in npm publish.
 * Respects .npmignore and package.json "files" field.
 */
// npm never publishes these regardless of .npmignore/.gitignore/git tracking —
// they're excluded from the packed tarball unconditionally. A git-tracked (or
// merely untracked-and-unignored) node_modules would otherwise ride along
// through getAllFilesGitAware()'s union and get reported as "will be
// published", which isn't true and just trains the user to distrust findings.
const NPM_NEVER_PUBLISHED = ['node_modules', '.git'];

// Per-segment match, not prefix match — npm excludes node_modules/.git at
// ANY depth (e.g. a vendored src/node_modules/), not just at project root.
// Splitting on both separators covers paths already normalized to path.sep
// as well as the rare literal '/' that slips through.
function isUnderAnyDir(relPath, dirNames) {
  const segments = relPath.split(/[\\/]/);
  return dirNames.some((d) => segments.includes(d));
}

// `skipped`, if passed, collects "files" entries that were dropped because they
// (or their symlink target) resolve outside projectRoot — so the caller can
// warn instead of silently scanning less than it claims to.
// `gitWarnings`, if passed, collects human-readable notices when git-aware
// file discovery (see getAllFilesGitAware below) couldn't complete.
// `npmWarnings`, if passed, collects a notice when `npm pack --dry-run`
// itself couldn't complete (see getNpmPackFiles below).
//
// Strategy: compute our own emulated publish list first (unchanged from
// before), then UNION it with the exact manifest `npm pack --dry-run --json`
// reports — never replace. Emulation and npm's real packer each catch things
// the other misses:
//   - npm's manifest is the only one that knows about npm's own always-ignore
//     defaults + always-include specials (package.json/README/LICENSE), and
//     doesn't hardcode "dist" as excluded the way buildIgnoreList() does — so
//     it catches a secret in dist/ (published for real, but hidden from our
//     emulation) or in package.json/README when "files" is set but doesn't
//     list them (npm still publishes them unconditionally).
//   - our emulation is the only one that consults git tracking directly
//     (getGitTrackedFiles), which is how it catches a file that was committed
//     before a later .gitignore rule excluded it — real `npm pack` (this npm
//     version) treats .gitignore as pure glob-exclusion and does NOT consult
//     git tracking, so it misses that case on its own.
// Unioning keeps both catches; the only cost is scanning a few paths that
// won't actually end up in the tarball, which is the safe direction to err
// in for a leak scanner.
// `npmConfirmed`, if passed, gets every path npm's own manifest actually
// listed (NFC-normalized) — so the caller can tell "npm itself will publish
// this" apart from "only our own git/ignore-based emulation thinks so". That
// distinction matters for messaging: a file caught ONLY through the
// git-tracked-then-later-ignored path (see getGitTrackedFiles) really will
// leak, but via `git push`, not `npm publish` — saying "will be published to
// npm" about it is factually wrong about the channel, even though flagging
// it at all is correct.
function getPublishFiles(projectRoot, skipped, gitWarnings, npmWarnings, npmConfirmed) {
  // Read package.json
  const pkgPath = path.join(projectRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return [];

  let pkg = {};
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch (_) {}

  let emulated;
  if (pkg.files && Array.isArray(pkg.files) && pkg.files.length > 0) {
    // If "files" field is set — only those are published
    emulated = expandGlobs(pkg.files, projectRoot, skipped);
  } else {
    // Otherwise everything except .npmignore / .gitignore exclusions
    const files = getAllFilesGitAware(projectRoot, buildIgnoreList(projectRoot), gitWarnings);
    emulated = files.filter((f) => !isUnderAnyDir(f, NPM_NEVER_PUBLISHED));
  }

  const npmErrorDetail = [];
  const npmFiles = getNpmPackFiles(projectRoot, npmErrorDetail);
  if (npmFiles === null) {
    if (npmWarnings) {
      const reason = npmErrorDetail[0] ? ` Причина: ${npmErrorDetail[0]}` : '';
      npmWarnings.push(`Команда "npm pack --dry-run" не отработала (npm недоступен, таймаут, невалидный package.json или другая ошибка самого npm) — список публикуемых файлов эмулируется вручную и может разойтись с тем, что реально отправит npm publish (например secret в dist/, или package.json/README при заданном "files").${reason}`);
    }
    return emulated;
  }

  // Same NFC-normalizing merge getAllFilesGitAware() uses above, for the same
  // reason: the two lists must compare byte-for-byte per file or the Set
  // fails to de-duplicate a name that differs only in Unicode normalization
  // form between npm's output and our own fs walk.
  const npmFilesNFC = npmFiles.map((f) => f.normalize('NFC'));
  if (npmConfirmed) {
    for (const f of npmFilesNFC) npmConfirmed.add(f);
  }

  const merged = new Set(emulated.map((f) => f.normalize('NFC')));
  for (const f of npmFilesNFC) merged.add(f);
  return Array.from(merged);
}

function buildIgnoreList(projectRoot) {
  const defaultIgnore = [
    'node_modules', '.git', '.DS_Store', '*.log',
    'coverage', 'dist', '.nyc_output',
  ];

  const npmIgnorePath = path.join(projectRoot, '.npmignore');
  const gitIgnorePath = path.join(projectRoot, '.gitignore');

  let lines = [...defaultIgnore];
  if (fs.existsSync(npmIgnorePath)) {
    lines = lines.concat(readIgnoreFile(npmIgnorePath));
  } else if (fs.existsSync(gitIgnorePath)) {
    lines = lines.concat(readIgnoreFile(gitIgnorePath));
  }
  return lines.filter(Boolean);
}

function readIgnoreFile(filePath) {
  return fs.readFileSync(filePath, 'utf8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

function getAllFiles(startDir, ignoreList, base) {
  base = base || startDir;
  const results = [];
  const visited = new Set();
  // Итеративный обход — без рекурсии, не упирается в лимит стека
  const queue = [startDir];

  while (queue.length > 0) {
    const dir = queue.pop();
    let entries;
    try { entries = fs.readdirSync(dir); } catch (_) { continue; }

    for (const entry of entries) {
      const full = path.join(dir, entry);
      const rel  = path.relative(base, full);

      if (isIgnored(rel, entry, ignoreList)) continue;

      let stat;
      try { stat = fs.lstatSync(full); } catch (_) { continue; }
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
// failed (huge output, timeout, permissions). Unlike buildIgnoreList() +
// isIgnored() above, this asks git directly, so it gets two things right
// that the hand-rolled parser can't: a file committed before it was added to
// .gitignore stays tracked (git never re-applies ignore rules retroactively),
// and "!pattern" negation lines work exactly like real git, since git's own
// exclude engine evaluates them instead of our regex-based isIgnored().
// Paths are normalized to path.sep — git always prints '/', but getAllFiles()
// above returns path.relative()'s native separator, and the two lists must
// compare equal for the Set-based merge below to actually de-duplicate.
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

// Wraps getAllFiles() with getGitTrackedFiles() so a git-tracked or
// negation-un-ignored file is never silently dropped by the hand-rolled
// ignore parser. Falls back to the plain ignore-based list, unchanged, when
// projectRoot isn't a git repository — same result as before this function
// existed. `warnings`, if passed, collects a notice for the one case that
// fails silently otherwise: projectRoot IS a git repo, but `git ls-files`
// itself errored out (huge repo, timeout) — the scan still completes, just
// without git's extra coverage, and the caller can surface that instead of
// quietly looking as thorough as a successful run.
function getAllFilesGitAware(projectRoot, ignoreList, warnings) {
  const ignoreBasedFiles = getAllFiles(projectRoot, ignoreList);
  if (!isGitRepo(projectRoot)) return ignoreBasedFiles;

  const gitFiles = getGitTrackedFiles(projectRoot);
  if (gitFiles === null) {
    if (warnings) {
      warnings.push('Это git-репозиторий, но команда "git ls-files" не отработала (таймаут или сбой) — файлы сверены только через разбор .gitignore/.npmignore, без списка git.');
    }
    return ignoreBasedFiles;
  }

  // Same invariant getAllFiles() already enforces above: a path that is
  // itself a symlink is never in the list, so its target (if inside root)
  // is only ever reached and scanned through its OWN tracked path. Without
  // this, a git-tracked symlink to another tracked file would report that
  // file's secret twice — once per name — since resolveWithinRoot() follows
  // the symlink and reads the same underlying content section 3 already
  // reads for the target's own entry.
  //
  // Known accepted trade-off: if the symlink's target is itself excluded
  // from this file list (e.g. gitignored, so it never gets its own entry),
  // filtering the symlink out here means a secret reachable ONLY through
  // that symlink goes unscanned. That's intentional, not a regression: only
  // the symlink's target-path STRING is ever committed/published, never the
  // target's content, so nothing actually leaks — the previous behavior of
  // scanning through it produced a false "will be published" HIGH instead.
  // Properly telling "target excluded but harmless" apart from "target
  // excluded and genuinely at risk" needs the full source-of-truth merge
  // that's explicitly out of scope here (tracked as a follow-up).
  const gitFilesNoSymlinks = gitFiles.filter((f) => {
    try {
      return !fs.lstatSync(path.join(projectRoot, f)).isSymbolicLink();
    } catch (_) {
      return true; // gone since git listed it — let safeRead()'s own try/catch handle the miss
    }
  });

  // Both lists must compare byte-for-byte for the same file, or the Set
  // below silently fails to de-duplicate it: git normalizes filenames to
  // NFC, but fs.readdirSync() (used by getAllFiles above) can return NFD
  // for the very same name — common on macOS for names with combining
  // accents (e.g. a Cyrillic "й" or "café.js"). Composing both to NFC
  // before merging keeps one file as one entry; reading the NFC-composed
  // path still works even when the on-disk name is NFD, since macOS
  // filesystems resolve lookups Unicode-normalization-insensitively.
  //
  // Known accepted risk, macOS-only tool: on a byte-exact filesystem
  // (ext4/Linux) two files whose names are canonically equivalent but
  // byte-distinct (one NFC, one NFD) can legitimately coexist — normalizing
  // both to NFC would collapse them into one Set entry and silently drop
  // the other from the scan. Not fixed here: on this project's actual
  // target (macOS/APFS), the two forms can't coexist as separate files at
  // all (confirmed empirically — writing both forms to the same directory
  // yields a single file), so there is no environment here to construct or
  // verify a fix against. A real fix would key de-duplication by inode
  // (fs.lstatSync().ino) instead of by name string.
  const merged = new Set(ignoreBasedFiles.map((f) => f.normalize('NFC')));
  for (const f of gitFilesNoSymlinks) merged.add(f.normalize('NFC'));
  return Array.from(merged);
}

// Converts a gitignore/npmignore glob pattern to a RegExp.
// Supports: * (within dir), ** (any depth), ? (single char), no {brace} expansion.
function globToRegex(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const regexStr = escaped
    .replace(/\*\*/g, '.*')      // ** = any path including slashes
    .replace(/\*/g,  '[^/]*')    // *  = any chars except slash
    .replace(/\?/g,  '[^/]');    // ?  = one char except slash
  return new RegExp('^' + regexStr + '$');
}

function isIgnored(rel, name, ignoreList) {
  return ignoreList.some(pattern => {
    if (!pattern || pattern.startsWith('#') || pattern.startsWith('!')) return false;

    const anchored  = pattern.startsWith('/');
    const p         = anchored ? pattern.slice(1) : pattern;
    const dirOnly   = p.endsWith('/');
    const cleanPat  = dirOnly ? p.slice(0, -1) : p;

    if (/[*?]/.test(cleanPat)) {
      const re = globToRegex(cleanPat);
      if (anchored) return re.test(rel) || re.test(rel.split('/')[0]);
      // Non-anchored glob: match against basename OR full relative path
      return re.test(name) || re.test(rel);
    }

    // Exact / prefix match
    if (anchored) return rel === cleanPat || rel.startsWith(cleanPat + '/');
    return name === cleanPat || rel === cleanPat || rel.startsWith(cleanPat + '/');
  });
}

// Resolves `relPath` against `root` and returns the absolute path only if it
// stays inside root. Blocks package.json "files" entries like "../../.env"
// from making the scanner read (and print) files outside the project.
// Also rejects a path whose real target (after resolving symlinks) escapes
// root — a symlink checked into the project can point outside it.
//
// `root` itself is resolved through realpath too, not just `full` — on
// macOS/Linux common roots like /tmp are themselves symlinks (/tmp ->
// /private/tmp). Comparing a lexical root against a realpath'd file would
// make every file look like it escapes root, silently dropping the whole
// project from the scan.
//
// Shared with expandGlobs(), which needs the same real root as the `base`
// it hands to getAllFiles() — mixing a lexical base with a realpath'd
// startDir makes path.relative() emit "../.." garbage for every file in a
// directory (e.g. a "files": ["src"] entry), which then fails the safety
// check below and gets silently dropped, same failure as the root mismatch
// this function exists to prevent.
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

function expandGlobs(patterns, root, skipped) {
  const systemOnly = ['node_modules', '.git', '.DS_Store', 'coverage', 'dist', '.nyc_output'];

  // If any entry is a glob, we can't resolve it without a glob library.
  // Fall back to scanning the whole project — conservative but safe.
  // Check ALL patterns first so we don't discard partially accumulated results.
  if (patterns.some(p => /[*?{]/.test(p))) {
    return getAllFiles(root, systemOnly, root);
  }

  const results = [];
  for (const pattern of patterns) {
    const full = resolveWithinRoot(root, pattern);
    if (!full) {
      // Escapes project root (literal "../", absolute path, or a symlink
      // pointing outside) — refuse to read it, same as npm would refuse to
      // publish it. Record it so scan() can surface a warning instead of
      // silently scanning less than package.json claims to publish.
      if (skipped) skipped.push(pattern);
      continue;
    }

    let stat;
    try { stat = fs.statSync(full); } catch (_) { continue; } // gone between existsSync and statSync, or unreadable

    if (stat.isDirectory()) {
      // `full` is already real (resolveWithinRoot resolved it through
      // realpath) — `base` must be real too, or path.relative(base, entry)
      // emits "../.." garbage for every file whenever `root` is reached
      // through a symlinked ancestor, and those files get silently dropped
      // downstream instead of ending up in the scan.
      results.push(...getAllFiles(full, [], realRootOf(root)));
    } else {
      results.push(pattern);
    }
  }
  return results;
}

/**
 * Main scan: returns array of findings { file, type, match }
 */
function scan(projectRoot) {
  projectRoot = projectRoot || process.cwd();
  const findings = [];

  const pkgPath = path.join(projectRoot, 'package.json');
  const isNpmProject = fs.existsSync(pkgPath);

  // For npm projects: only files that will be published.
  // For other projects (Python, Go, etc.): all non-gitignored files.
  const skippedFiles = [];
  const gitWarnings = [];
  const npmWarnings = [];
  const npmConfirmedFiles = new Set();
  const publishFiles = isNpmProject
    ? getPublishFiles(projectRoot, skippedFiles, gitWarnings, npmWarnings, npmConfirmedFiles)
    : getAllFilesGitAware(projectRoot, buildIgnoreList(projectRoot), gitWarnings);

  const context = isNpmProject ? 'npm-пакет' : 'git-коммит';
  // True only when npm pack --dry-run itself succeeded — i.e. npmConfirmedFiles
  // is a trustworthy "npm will really publish exactly this" answer, not an
  // empty set from a failed/skipped call. Only then can "not in
  // npmConfirmedFiles" be read as "npm itself excludes this" rather than
  // "we don't know".
  const npmPackSucceeded = isNpmProject && npmWarnings.length === 0;

  // 0. "files" entries that point outside the project (directly or via a
  //    symlink) are never read — but say so instead of quietly scanning
  //    less than package.json claims to publish.
  for (const pattern of skippedFiles) {
    findings.push({
      severity: 'WARN',
      type: 'files_entry_outside_root',
      file: pattern,
      detail: `Путь "${pattern}" в package.json "files" ведёт за пределы папки проекта (напрямую или через симлинк) — aiguard его НЕ прочитал. Если это ожидаемо (например ссылка на общий пакет в монорепозитории) — проверь его содержимое отдельно.`,
    });
  }

  // 0b. git-aware file discovery didn't fully complete — say so instead of
  //     silently looking as thorough as a normal run (see getAllFilesGitAware).
  for (const detail of gitWarnings) {
    findings.push({ severity: 'WARN', type: 'git_awareness_degraded', file: '.', detail });
  }

  // 0c. `npm pack --dry-run` itself didn't complete — say so instead of
  //     silently relying on our own emulation without flagging the gap
  //     (see getNpmPackFiles / getPublishFiles).
  for (const detail of npmWarnings) {
    findings.push({ severity: 'WARN', type: 'npm_pack_degraded', file: '.', detail });
  }

  // 1. Check for AI tool folders in published files
  for (const aiFolder of AI_FOLDERS) {
    const inPublish = publishFiles.filter(f => f.startsWith(aiFolder + '/') || f === aiFolder);
    if (inPublish.length > 0) {
      // npm pack succeeded but confirms only SOME (or none) of these paths →
      // the rest are only here via our own (broader, safety-first) emulation
      // — could be git-tracked-then-ignored, or simply untracked and excluded
      // by npm for an unrelated reason (e.g. npm's own unanchored `.npmrc`
      // rule) that our emulation doesn't replicate. Either way real npm won't
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
