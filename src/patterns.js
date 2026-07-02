'use strict';

const { BIP39_WORDS } = require('./bip39');

// BIP39_WORDS preserves the official spec order (a Set built from an array
// literal keeps insertion order in JS) — used below to tell a wordlist
// definition (words listed in ascending canonical order, e.g. bip39.js
// itself) apart from an actual mnemonic, whose word order comes from random
// entropy. A monotonically increasing run of 12+ canonical indices has
// probability ~1/12! per window for a real seed — treating it as "not a
// seed" costs no real detections but kills the single biggest self-inflicted
// false positive: any project (including this one) that vendors the BIP39
// wordlist.
const BIP39_INDEX = new Map();
{
  let i = 0;
  for (const w of BIP39_WORDS) BIP39_INDEX.set(w, i++);
}

function isCanonicalOrder(words) {
  let prev = -1;
  for (const w of words) {
    const idx = BIP39_INDEX.get(w);
    if (idx === undefined || idx <= prev) return false;
    prev = idx;
  }
  return true;
}

// Slides a window of official BIP39 lengths across `words` and returns true
// if any window is both a real mnemonic length AND >=90% dictionary words —
// lets a genuine seed survive even when it's glued to a label or trailing
// word ("wallet phrase: <12 words>", "<12 words> // backup") that the greedy
// token-run regex swept into the same match.
const MNEMONIC_LENGTHS = [24, 21, 18, 15, 12];
function containsMnemonic(words) {
  for (const len of MNEMONIC_LENGTHS) {
    for (let i = 0; i + len <= words.length; i++) {
      const window = words.slice(i, i + len);
      const inDict = window.filter((w) => BIP39_WORDS.has(w)).length;
      if (inDict / len >= 0.9 && !isCanonicalOrder(window)) return true;
    }
  }
  return false;
}

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
    name: 'Crypto mnemonic (BIP39 seed)',
    // Matches a run of 12+ words in any case (lower, UPPER, Mixed),
    // separated by spaces, commas, tabs, line breaks (LF/CRLF/CR), or
    // markdown list bullets (-, *, •) — including JSON/Python-array form
    // where each word is quoted ("abandon","ability",... or 'abandon',
    // 'ability', ...).
    // No upper bound on the run: a real seed is often glued to a label or
    // trailing word ("wallet phrase: <12 words>"), so validate() slides a
    // window for the actual mnemonic length (12/15/18/21/24) instead of
    // requiring the whole run to be exactly that long.
    regex: /\b["']?[a-zA-Z]{3,8}["']?(?:[ \t\r\n,*•-]+["']?[a-zA-Z]{3,8}["']?){11,}\b/g,
    validate: (match) => {
      try {
        const words = match.trim().toLowerCase().split(/[ \t\r\n,"'*•-]+/).filter(Boolean);
        return containsMnemonic(words);
      } catch (_) { return false; }
    },
  },
  {
    name: 'Crypto mnemonic (numbered BIP39 seed)',
    // Matches numbered formats: "1. abandon 2. ability ... 12. zoo",
    // "1) abandon 2) ability...", or one numbered word per line — common in
    // backup exports and screenshots. Same sliding-window validate() as the
    // plain pattern, so an extra numbered item glued to a real seed doesn't
    // push the total length out of the valid set and lose the match.
    regex: /1[.)]\s*[a-zA-Z]{3,8}(?:\s*\d+[.)]\s*[a-zA-Z]{3,8}){11,}/g,
    validate: (match) => {
      try {
        const words = match.toLowerCase().replace(/\d+[.)]\s*/g, ' ').trim().split(/\s+/).filter(w => /^[a-z]+$/.test(w));
        return containsMnemonic(words);
      } catch (_) { return false; }
    },
  },
  {
    name: 'Ethereum private key',
    // Only flag a 64-hex string when it sits next to a key/secret label —
    // a bare 64-hex string is just as likely a SHA-256 hash or git object id.
    regex: /(?:private[_\-]?key|privkey|secret[_\-]?key|eth[_\-]?key|wallet[_\-]?key)["']?\s*[=:]\s*["']?(?:0x)?[0-9a-fA-F]{64}\b/gi,
  },
  { name: 'Bitcoin WIF private key',  regex: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g },

  // ── Keys & certificates ───────────────────────────────────────
  { name: 'Private key block',        regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'JWT secret',               regex: /(?:JWT[_\-]?SECRET|TOKEN[_\-]?SECRET)\s*[=:]\s*["']?[^\s"']{32,}["']?/gi },

  // ── Generic catch-all ─────────────────────────────────────────
  {
    name: 'Generic secret in env',
    regex: /(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY)\s*[=:]\s*["']?[^\s"']{8,}["']?/gi,
  },

  // ── Base64-obfuscated secrets ──────────────────────────────────
  // Catches secrets hidden as Base64 strings next to a key/token label.
  // Decodes the candidate and checks if it matches any known secret prefix.
  {
    name: 'Base64-encoded secret',
    regex: /(?:key|token|secret|password|credential)["']?\s*[=:]\s*["']?([A-Za-z0-9+/]{40,}={0,2})["']?/gi,
    validate: (match) => {
      try {
        const b64 = match.match(/[A-Za-z0-9+/]{40,}={0,2}/)?.[0];
        if (!b64) return false;
        const decoded = Buffer.from(b64, 'base64').toString('utf8');
        return /sk-ant-|sk-proj-|AKIA[0-9A-Z]|xai-|sk_live_|ghp_|ghs_|gho_|github_pat_|npm_|SG\.|xoxb-/.test(decoded);
      } catch (_) { return false; }
    },
  },
];

module.exports = { AI_FOLDERS, AI_SECRET_FILES, SECRET_PATTERNS };
