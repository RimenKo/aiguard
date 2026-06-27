# aiguard

**Stop AI coding tools from leaking your secrets.**

Claude Code, Cursor, Copilot, and Windsurf write fast — and regularly sneak API keys, session tokens, and crypto seed phrases into your public repos and npm packages. `aiguard` catches them before `npm publish` or `git push`.

```bash
npm install -g @rimenko-dev/aiguard
aiguard
```

[![npm version](https://badge.fury.io/js/%40rimenko-dev%2Faiguard.svg)](https://www.npmjs.com/package/@rimenko-dev/aiguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Real-world findings

We scanned 50,000 public GitHub repositories for AI tool artifacts. Results:

| Metric | Count |
|--------|-------|
| Files analyzed | 362 |
| Unique secrets found | **138** |
| Crypto seed phrases (12-word mnemonics) | **45** |
| Database connection strings | 40 |
| Generic API keys | 22 |
| Plaintext passwords | 16 |
| Anthropic API keys | 3 |
| AWS access keys | 2 |
| SSH private keys | 4 |

**The #1 leak vector: `CLAUDE.md`.**
Developers paste credentials into Claude Code's context file (CLAUDE.md) so the AI can reference them — then commit it to a public repo. We found over 63 `CLAUDE.md` variants containing live secrets.

**45 crypto seed phrases** were exposed in project files. That's 45 wallets — potentially drained.

---

## The problem

Your AI assistant stores credentials in hidden folders:

| Tool | Folder | What's stored |
|------|--------|---------------|
| Claude Code | `.claude/` | API keys, MCP server tokens, CLAUDE.md context |
| Cursor | `.cursor/` | OAuth tokens, MCP configs, API keys |
| Windsurf | `.windsurf/` | Auth tokens, workspace credentials |
| Aider | `.aider/` | Model API keys, git credentials |
| Continue | `.continue/` | LLM provider keys, embeddings tokens |
| Codeium | `.codeium/` | Authentication tokens |

These folders are **not excluded by default** from `npm publish` or `git push`. One missing `.npmignore` line, or a `CLAUDE.md` with a seed phrase committed to a public repo, and secrets are exposed — forever cached by GitHub.

---

## What it catches

**AI tool folders in your publish** — `.claude/`, `.cursor/`, `.windsurf/`, etc. included in npm tarball or git commit.

**Known AI context files with secrets** — `CLAUDE.md`, `mcp.json`, `settings.local.json`.

**Secrets in published files** — 55+ patterns across every major provider:

| Category | Services |
|----------|----------|
| AI providers | Anthropic, OpenAI, xAI/Grok, Gemini, Groq, HuggingFace, Replicate, Mistral |
| Cloud | AWS, GCP service accounts, Azure, DigitalOcean, Cloudflare |
| Source control | GitHub (classic / OAuth / Actions / fine-grained PAT), GitLab |
| Payments | Stripe, PayPal, Braintree |
| Messaging | Slack, Discord, Telegram bots, Twilio |
| Email | SendGrid, Mailgun, Resend, Postmark |
| Databases | PostgreSQL, MySQL, MongoDB, Redis, Supabase, PlanetScale, Neon, Pinecone |
| Hosting | Vercel, Netlify, Heroku, Railway, Fly.io, npm tokens |
| Monitoring | Sentry, Datadog |
| **Crypto** | **BIP39 12-word mnemonics, Ethereum private keys, Bitcoin WIF keys** |
| Keys | RSA / EC / SSH private keys, JWT secrets |
| Catch-all | Any `PASSWORD=`, `SECRET=`, `API_KEY=`, `TOKEN=` longer than 8 chars |

---

## Usage

```bash
# Scan current directory
aiguard

# Scan a specific project
aiguard /path/to/project
```

**Exit codes:**
- `0` — clean or warnings only
- `1` — CRITICAL or HIGH findings (publish blocked)

**Example output:**

```
aiguard — AI secret leak scanner
Project: /my-package

🚨 CRITICAL — publish blocked (1):
   .claude/settings.local.json
   This file contains API keys and tokens — it will be included in your npm package!

⚠️  HIGH RISK — publish blocked (1):
   CLAUDE.md
   Crypto mnemonic (12 words): abandon abandon ***...*** 

❌ Publish blocked: 1 critical + 1 high findings.
Add to .npmignore:
  .claude
  .cursor
  .env
  *.local
```

---

## Use as a pre-publish hook

Add to your `package.json` to block every `npm publish` automatically:

```json
{
  "scripts": {
    "prepublishOnly": "aiguard"
  }
}
```

---

## Use as a Claude Code hook

Runs before every Bash command inside Claude Code — catches secrets before they land in committed files.

Add to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "npx @rimenko-dev/aiguard"
          }
        ]
      }
    ]
  }
}
```

Or copy the included config:

```bash
cp node_modules/@rimenko-dev/aiguard/claude-hook/settings.json .claude/settings.json
```

---

## Severity levels

| Level | Meaning | Blocks publish? |
|-------|---------|-----------------|
| 🚨 CRITICAL | AI secret file will be included in the package | ✅ Yes |
| ⚠️ HIGH | Known secret pattern found in a file that will be published | ✅ Yes |
| 💡 WARN | Potential risk (file exists locally, `.npmignore` gap) | ❌ No |

---

## How it works

**For npm projects** (has `package.json`):
1. Resolves exactly which files `npm publish` would include — respects `files` field and `.npmignore`
2. Scans only those files — no false positives from files that won't be published
3. Blocks publish on CRITICAL or HIGH findings

**For non-npm projects** (Go, Python, Rust, etc.):
1. Scans all non-gitignored files
2. Reports findings before `git push`

---

## Recommended `.npmignore`

```
.claude
.cursor
.windsurf
.continue
.aider
.codeium
.env
.env.*
*.local
CLAUDE.md
```

---

## Install

```bash
npm install -g @rimenko-dev/aiguard
```

Or run without installing:

```bash
npx @rimenko-dev/aiguard
```

---

## Contributing

Pull requests welcome. To add new secret patterns, edit `src/patterns.js` — each entry needs a `name` and a `regex` with the `g` flag.

---

## License

MIT — [github.com/RimenKo/aiguard](https://github.com/RimenKo/aiguard)
