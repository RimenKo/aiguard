#!/usr/bin/env node
'use strict';

const path = require('path');
const { scan } = require('../src/scanner');

const args = process.argv.slice(2);
const projectRoot = args[0] ? path.resolve(args[0]) : process.cwd();

// Refuse to scan home directory — it triggers macOS permission dialogs for
// every protected folder (Google Drive, Apple Music, etc.) and makes no sense
// as a project root. The tool is designed for project directories only.
const homeDir = require('os').homedir();
if (projectRoot === homeDir) {
  console.error('\n⛔  Запускать из домашней папки нельзя — укажи конкретный проект:');
  console.error(`    aiguard ~/ClaudeCode/my-project\n`);
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

console.log(`\n${COLORS.bold}aiguard${COLORS.reset} — проверка утечек AI-инструментов`);
console.log(`Проект: ${projectRoot}\n`);

let findings;
try {
  findings = scan(projectRoot);
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
