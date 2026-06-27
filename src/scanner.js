'use strict';

const fs = require('fs');
const path = require('path');
const { AI_FOLDERS, AI_SECRET_FILES, SECRET_PATTERNS } = require('./patterns');

/**
 * Returns list of files that will be included in npm publish.
 * Respects .npmignore and package.json "files" field.
 */
function getPublishFiles(projectRoot) {
  // Read package.json
  const pkgPath = path.join(projectRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return [];

  let pkg = {};
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch (_) {}

  // If "files" field is set — only those are published
  if (pkg.files && Array.isArray(pkg.files) && pkg.files.length > 0) {
    return expandGlobs(pkg.files, projectRoot);
  }

  // Otherwise everything except .npmignore / .gitignore exclusions
  return getAllFiles(projectRoot, buildIgnoreList(projectRoot));
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

function expandGlobs(patterns, root) {
  const systemOnly = ['node_modules', '.git', '.DS_Store', 'coverage', 'dist', '.nyc_output'];

  // If any entry is a glob, we can't resolve it without a glob library.
  // Fall back to scanning the whole project — conservative but safe.
  // Check ALL patterns first so we don't discard partially accumulated results.
  if (patterns.some(p => /[*?{]/.test(p))) {
    return getAllFiles(root, systemOnly, root);
  }

  const results = [];
  for (const pattern of patterns) {
    const full = path.join(root, pattern);
    if (fs.existsSync(full)) {
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        results.push(...getAllFiles(full, [], root));
      } else {
        results.push(pattern);
      }
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
  const publishFiles = isNpmProject
    ? getPublishFiles(projectRoot)
    : getAllFiles(projectRoot, buildIgnoreList(projectRoot));

  const context = isNpmProject ? 'npm-пакет' : 'git-коммит';

  // 1. Check for AI tool folders in published files
  for (const aiFolder of AI_FOLDERS) {
    const inPublish = publishFiles.filter(f => f.startsWith(aiFolder + '/') || f === aiFolder);
    if (inPublish.length > 0) {
      findings.push({
        severity: 'HIGH',
        type: 'ai_folder_in_publish',
        file: aiFolder + '/',
        detail: `Папка AI-инструмента попадёт в ${context} (${inPublish.length} файлов). Добавь в .npmignore/.gitignore.`,
      });
    }
  }

  // 2. Check known AI secret files
  for (const secretFile of AI_SECRET_FILES) {
    const full = path.join(projectRoot, secretFile);
    if (!fs.existsSync(full)) continue;

    const inPublish = publishFiles.includes(secretFile);
    if (inPublish) {
      // File WILL be published — CRITICAL, scan content too
      findings.push({
        severity: 'CRITICAL',
        type: 'ai_secret_file_published',
        file: secretFile,
        detail: `Этот файл содержит API-ключи и токены — он уйдёт в ${context}!`,
      });
      const content = safeRead(full);
      if (content) {
        findings.push(...scanContent(secretFile, content, 'CRITICAL'));
      }
    } else {
      // File exists locally but is excluded from publish — warn only
      findings.push({
        severity: 'WARN',
        type: 'ai_secret_file_exists',
        file: secretFile,
        detail: 'Файл существует локально, но исключён из публикации. Убедись, что .npmignore актуален.',
      });
    }
  }

  // 3. Scan all published files for secret patterns
  for (const relFile of publishFiles) {
    if (AI_SECRET_FILES.includes(relFile)) continue;
    if (isBinary(relFile)) continue;

    const full = path.join(projectRoot, relFile);
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

module.exports = { scan };
