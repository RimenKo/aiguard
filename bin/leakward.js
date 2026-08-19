#!/usr/bin/env node
'use strict';

const path = require('path');
const { scan, scanGitHistory, getStagedFiles } = require('../src/scanner');

const args = process.argv.slice(2).filter(a => !a.startsWith('--'));
const flags = process.argv.slice(2).filter(a => a.startsWith('--'));

if (flags.includes('--help') || flags.includes('-h')) {
  console.log(`leakward — catches AI-tool secrets and folders before npm publish / git push

Usage:
  leakward [path]              Scan a project (default: current directory)
  leakward [path] --staged     Scan only files staged for commit (git diff --cached)
  leakward [path] --npm-only   Scan only what \`npm pack\` would publish (used by prepublishOnly)
  leakward [path] --history    Also scan the full git history for leaked secrets
  leakward --help              Show this help

  aiguard                      deprecated alias — same flags and exit codes

Suppression (same rules in this CLI and in the Claude Code write hook):
  leakward:allow    put on the same line (typically in a comment) to skip that finding
  aiguard:allow     accepted as a deprecated alias — same meaning
  gitleaks:allow    accepted as an alias — same meaning
  .leakwardignore   gitignore-style path/glob list at the project root; matching files are not scanned
  .aiguardignore    accepted as a deprecated alias — same meaning

Exit code: 0 = clean, 1 = blocked (secrets or AI-tool folders found).
`);
  process.exit(0);
}

const historyMode = flags.includes('--history');
// Scan ONLY what `npm pack --dry-run --json` would actually publish — used by
// `prepublishOnly` so git-tracked-but-not-npm-published fixtures (e.g. test/
// secret fixtures excluded via package.json "files") don't block `npm
// publish`. The regular (no-flag) run keeps scanning git ∪ npm, since it also
// guards against a `git push` leak, not just an npm publish one.
const npmOnlyMode = flags.includes('--npm-only');
// Scan ONLY files staged for commit — for a pre-commit hook that must run on
// every commit without re-scanning the whole tree each time.
const stagedMode = flags.includes('--staged');
const projectRoot = args[0] ? path.resolve(args[0]) : process.cwd();

// Refuse to scan home directory — it triggers macOS permission dialogs for
// every protected folder (Google Drive, Apple Music, etc.) and makes no sense
// as a project root. The tool is designed for project directories only.
const homeDir = require('os').homedir();
if (projectRoot === homeDir) {
  console.error('\n⛔  Запускать из домашней папки нельзя — укажи конкретный проект:');
  console.error(`    leakward ~/ClaudeCode/my-project\n`);
  process.exit(1);
}

const ICONS = { CRITICAL: '🚨', HIGH: '⚠️ ', WARN: '💡' };
const COLORS = {
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
};

function colorize(severity, text) {
  if (severity === 'CRITICAL') return COLORS.red + COLORS.bold + text + COLORS.reset;
  if (severity === 'HIGH')     return COLORS.yellow + text + COLORS.reset;
  return COLORS.cyan + text + COLORS.reset;
}

console.log(`\n${COLORS.bold}leakward${COLORS.reset} — проверка утечек AI-инструментов`);
console.log(`Проект: ${projectRoot}\n`);

let findings;
try {
  const scanOptions = { npmOnly: npmOnlyMode };
  if (stagedMode) {
    const staged = getStagedFiles(projectRoot);
    if (staged === null) {
      console.error('⛔  --staged: не удалось получить список застейдженных файлов (не git-репозиторий, повреждённый индекс или сбой git).');
      process.exit(1);
    }
    scanOptions.files = staged;
  }
  findings = scan(projectRoot, scanOptions);
  if (historyMode) {
    console.log('🔍 Проверяю git-историю...\n');
    const historyFindings = scanGitHistory(projectRoot);
    if (historyFindings.length > 0) {
      findings = findings.concat(historyFindings);
    }
  }
} catch (err) {
  console.error('Ошибка сканирования:', err.message);
  process.exit(1);
}

if (findings.length === 0) {
  console.log('✅ Всё чисто — секретов и AI-папок в публикации не найдено.\n');
  process.exit(0);
}

// Group by severity
const critical = findings.filter(f => f.severity === 'CRITICAL');
const high     = findings.filter(f => f.severity === 'HIGH');
const warn     = findings.filter(f => f.severity === 'WARN');

const printGroup = (items, label) => {
  if (!items.length) return;
  console.log(colorize(items[0].severity, `${ICONS[items[0].severity]} ${label} (${items.length}):`));
  for (const f of items) {
    console.log(`   ${COLORS.bold}${f.file}${COLORS.reset}`);
    console.log(`   ${f.detail}`);
    console.log();
  }
};

printGroup(critical, 'КРИТИЧНО — публикация заблокирована');
printGroup(high,     'ВЫСОКИЙ РИСК — публикация заблокирована');
printGroup(warn,     'РЕКОМЕНДАЦИИ');

const blocking = critical.length + high.length;

if (blocking > 0) {
  if (critical.length > 0) {
    console.log(`${COLORS.red}${COLORS.bold}❌ Публикация заблокирована: ${critical.length} критичных + ${high.length} высоких проблем.${COLORS.reset}`);
    console.log(`Добавь в .npmignore:\n`);
    console.log(`  .claude\n  .cursor\n  .env\n  *.local\n`);
  } else {
    console.log(`${COLORS.yellow}${COLORS.bold}❌ Публикация заблокирована: найдены секреты в публикуемых файлах.${COLORS.reset}`);
    console.log(`Убери секреты из файлов или перенеси в переменные окружения.\n`);
  }
  process.exit(1);
} else {
  if (warn.length > 0) {
    console.log(`${COLORS.cyan}💡 Найдено ${warn.length} рекомендаций. Проверь перед публикацией.${COLORS.reset}\n`);
  }
  process.exit(0);
}
