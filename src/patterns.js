'use strict';

// AI-tool folders that often contain secrets
const AI_FOLDERS = [
  '.claude',
  '.cursor',
  '.continue',
  '.aider',
  '.codeium',
  '.copilot-workspace',
  '.windsurf',
  '.trae',
  '.roo-cline',
  '.roo',
  '.github/copilot',
];

// Files known to store secrets in AI-assisted projects
// These are checked separately — CRITICAL if published, WARN if only local
const AI_SECRET_FILES = [
  '.claude/settings.local.json',
  '.cursor/mcp.json',
  '.cursor/settings.json',
  // CLAUDE.md is the #1 leak source in public repos:
  // our research found 138 secrets across 362 GitHub files,
  // 63+ in CLAUDE.md variants alone — devs paste secrets into context files
  'CLAUDE.md',
  'claude.md',
  '.claude/CLAUDE.md',
];

// Regex patterns for secrets — ordered by category
const SECRET_PATTERNS = [
  // ── AI providers ──────────────────────────────────────────────
  { name: 'Anthropic API key',        regex: /sk-ant-[a-zA-Z0-9\-_]{20,}/g },
  { name: 'OpenAI API key',           regex: /sk-(?:proj-)?[a-zA-Z0-9]{20,}/g },
  { name: 'xAI / Grok key',          regex: /xai-[a-zA-Z0-9]{20,}/g },
  { name: 'Google API key',           regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'Groq API key',             regex: /gsk_[a-zA-Z0-9]{20,}/g },
  { name: 'HuggingFace token',        regex: /hf_[a-zA-Z0-9]{20,}/g },
  { name: 'Replicate token',          regex: /r8_[a-zA-Z0-9]{20,}/g },
  { name: 'Mistral API key',          regex: /(?:MISTRAL[_\-]?API[_\-]?KEY)\s*[=:]\s*["']?[a-zA-Z0-9]{32,}["']?/gi },
  { name: 'Together AI key',          regex: /(?:TOGETHER[_\-]?API[_\-]?KEY)\s*[=:]\s*["']?[a-zA-Z0-9]{40,}["']?/gi },

  // ── Cloud providers ───────────────────────────────────────────
  { name: 'AWS Access Key ID',        regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Access Key',    regex: /(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key)\s*[=:]\s*["']?[A-Za-z0-9\/+=]{40}["']?/gi },
  { name: 'GCP service account',      regex: /"type"\s*:\s*"service_account"/g },
  { name: 'Azure client secret',      regex: /(?:AZURE[_\-]?CLIENT[_\-]?SECRET)\s*[=:]\s*["']?[^\s"']{8,}["']?/gi },
  { name: 'DigitalOcean token',       regex: /dop_v1_[a-zA-Z0-9]{43}/g },
  { name: 'Cloudflare API token',     regex: /(?:CF[_\-]?(?:API[_\-]?)?TOKEN)\s*[=:]\s*["']?[A-Za-z0-9_\-]{40,}["']?/gi },
  { name: 'Cloudflare Global Key',    regex: /(?:CF[_\-]?(?:API[_\-]?)?KEY)\s*[=:]\s*["']?[a-f0-9]{37}["']?/gi },

  // ── Source control & dev platforms ────────────────────────────
  { name: 'GitHub token (classic)',   regex: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub OAuth token',       regex: /gho_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub Actions token',     regex: /ghs_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub fine-grained PAT',  regex: /github_pat_[a-zA-Z0-9_]{82}/g },
  { name: 'GitLab token',             regex: /glpat-[a-zA-Z0-9\-_]{20}/g },
  { name: 'npm automation token',     regex: /npm_[a-zA-Z0-9]{36}/g },

  // ── Payments ──────────────────────────────────────────────────
  { name: 'Stripe live secret key',   regex: /sk_live_[a-zA-Z0-9]{24,}/g },
  { name: 'Stripe restricted key',    regex: /rk_live_[a-zA-Z0-9]{24,}/g },
  { name: 'PayPal client secret',     regex: /(?:paypal[_\-]?(?:client[_\-]?)?secret)\s*[=:]\s*["']?[A-Za-z0-9\-_]{20,}["']?/gi },
  { name: 'Braintree access token',   regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g },

  // ── Communication & messaging ─────────────────────────────────
  { name: 'Slack bot token',          regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g },
  { name: 'Slack user token',         regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}/g },
  { name: 'Discord bot token',        regex: /[MNO][a-zA-Z0-9_\-]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}/g },
  { name: 'Telegram bot token',       regex: /\d{8,10}:[A-Za-z0-9_\-]{35}/g },
  { name: 'Twilio auth token',        regex: /(?:twilio[_\-]?(?:auth[_\-]?)?token)\s*[=:]\s*["']?[a-f0-9]{32}["']?/gi },
  { name: 'SendGrid API key',         regex: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g },
  { name: 'Mailgun API key',          regex: /key-[a-zA-Z0-9]{32}/g },
  { name: 'Resend API key',           regex: /re_[a-zA-Z0-9]{20,}/g },
  { name: 'Postmark server token',    regex: /(?:postmark[_\-]?(?:server[_\-]?)?token)\s*[=:]\s*["']?[a-zA-Z0-9\-]{36}["']?/gi },

  // ── Databases & storage ───────────────────────────────────────
  { name: 'DB connection string',     regex: /(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^\s"'`]+/g },
  { name: 'Supabase service key',     regex: /sbp_[a-zA-Z0-9]{40}/g },
  { name: 'Notion token',             regex: /(?:secret_|ntn_)[a-zA-Z0-9]{40,}/g },
  { name: 'PlanetScale token',        regex: /pscale_tkn_[a-zA-Z0-9_]{32,}/g },
  { name: 'Neon DB connection',       regex: /ep-[a-z\-]+-[a-z0-9]+\.(?:us|eu)-[a-z]+-[0-9]+\.aws\.neon\.tech/g },
  { name: 'Pinecone API key',         regex: /(?:PINECONE[_\-]?API[_\-]?KEY)\s*[=:]\s*["']?[a-zA-Z0-9\-]{36,}["']?/gi },

  // ── Hosting & deployment ──────────────────────────────────────
  { name: 'Vercel token',             regex: /(?:VERCEL[_\-]?TOKEN)\s*[=:]\s*["']?[a-zA-Z0-9]{24,}["']?/gi },
  { name: 'Netlify token',            regex: /(?:NETLIFY[_\-]?(?:AUTH[_\-]?)?TOKEN)\s*[=:]\s*["']?[a-zA-Z0-9]{24,}["']?/gi },
  { name: 'Heroku API key',           regex: /(?:HEROKU[_\-]?API[_\-]?KEY)\s*[=:]\s*["']?[a-f0-9\-]{36}["']?/gi },
  { name: 'Railway token',            regex: /(?:RAILWAY[_\-]?TOKEN)\s*[=:]\s*["']?[a-zA-Z0-9\-_]{20,}["']?/gi },
  { name: 'Fly.io token',             regex: /FlyV1 [a-zA-Z0-9+\/=]{100,}/g },

  // ── Monitoring & analytics ────────────────────────────────────
  { name: 'Sentry auth token',        regex: /(?:SENTRY[_\-]?(?:AUTH[_\-]?)?TOKEN)\s*[=:]\s*["']?[a-f0-9]{64}["']?/gi },
  { name: 'Datadog API key',          regex: /(?:DD[_\-]?API[_\-]?KEY)\s*[=:]\s*["']?[a-f0-9]{32}["']?/gi },

  // ── Crypto — #1 finding in our GitHub research (45 cases) ────
  {
    name: 'Crypto mnemonic (12 words)',
    // BIP39: exactly 12 lowercase English words separated by spaces
    // Not anchored to line start — catches inline mnemonics too
    regex: /\b(?:[a-z]{3,8}\s){11}[a-z]{3,8}\b(?=\s|$|[^a-z])/g,
  },
  { name: 'Ethereum private key',     regex: /(?:0x)?[0-9a-fA-F]{64}(?=[^0-9a-fA-F]|$)/g },
  { name: 'Bitcoin WIF private key',  regex: /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/g },

  // ── Keys & certificates ───────────────────────────────────────
  { name: 'Private key block',        regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'JWT secret',               regex: /(?:JWT[_\-]?SECRET|TOKEN[_\-]?SECRET)\s*[=:]\s*["']?[^\s"']{32,}["']?/gi },

  // ── Generic catch-all ─────────────────────────────────────────
  {
    name: 'Generic secret in env',
    regex: /(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY)\s*[=:]\s*["']?[^\s"']{8,}["']?/gi,
  },
];

module.exports = { AI_FOLDERS, AI_SECRET_FILES, SECRET_PATTERNS };
