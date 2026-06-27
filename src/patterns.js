'use strict';

// AI-tool folders that often contain secrets
const AI_FOLDERS = [
  '.claude',
  '.cursor',
  '.continue',
  '.aider',
  '.codeium',
  '.copilot-workspace',
];

// Files inside AI folders that are known to store secrets
const AI_SECRET_FILES = [
  '.claude/settings.local.json',
  '.cursor/mcp.json',
  '.cursor/settings.json',
];

// Regex patterns for secrets — ordered by severity
const SECRET_PATTERNS = [
  { name: 'Anthropic API key',  regex: /sk-ant-[a-zA-Z0-9\-_]{20,}/g },
  { name: 'OpenAI API key',     regex: /sk-[a-zA-Z0-9]{20,}/g },
  { name: 'AWS Access Key',     regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'GitHub token',       regex: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'Google API key',     regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'Stripe live key',    regex: /sk_live_[a-zA-Z0-9]{24,}/g },
  { name: 'Telegram bot token', regex: /\d{8,10}:[A-Za-z0-9_\-]{35}/g },
  { name: 'Private key block',  regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  {
    name: 'DB connection string',
    regex: /(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^\s"']+/g,
  },
  {
    name: 'Generic secret in env',
    regex: /(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*["']?[^\s"']{8,}["']?/gi,
  },
];

module.exports = { AI_FOLDERS, AI_SECRET_FILES, SECRET_PATTERNS };
