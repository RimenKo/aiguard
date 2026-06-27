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
Developers paste credentials into Claude Code's context file so the AI can reference them — then commit it to a public repo. We found over 63 `CLAUDE.md` variants containing live secrets.

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
| GitHub Copilot | `.github/copilot/` | Auth tokens |
| Trae | `.trae/` | Session credentials |
| Roo | `.roo/`, `.roo-cline/` | Model keys |

These folders are **not excluded by default** from `npm publish` or `git push`. One missing `.npmignore` line, or a `CLAUDE.md` with a seed phrase committed to a public repo, and secrets are exposed — forever cached by GitHub.

---

## What it catches

### AI tool folders in your publish
`.claude/`, `.cursor/`, `.windsurf/`, and 9 more — if any are included in your npm tarball or git commit, publish is blocked.

### Known AI context files with secrets
`CLAUDE.md`, `mcp.json`, `settings.local.json` — scanned and blocked if published. Even when excluded from publish, `aiguard` shows you **which specific secrets** are inside, so you know the blast radius if your ignore config ever breaks.

### Secrets in published files — 55+ patterns

| Category | Services |
|----------|----------|
| AI providers | Anthropic, OpenAI, xAI/Grok, Gemini, Groq, HuggingFace, Replicate, Mistral, Together AI |
| Cloud | AWS, GCP service accounts, Azure, DigitalOcean, Cloudflare |
| Source control | GitHub (classic / OAuth / Actions / fine-grained PAT), GitLab, npm tokens |
| Payments | Stripe, PayPal, Braintree |
| Messaging | Slack, Discord, Telegram bots, Twilio |
| Email | SendGrid, Mailgun, Resend, Postmark |
| Databases | PostgreSQL, MySQL, MongoDB, Redis, Supabase, PlanetScale, Neon, Pinecone |
| Hosting | Vercel, Netlify, Heroku, Railway, Fly.io |
| Monitoring | Sentry, Datadog |
| **Crypto** | **BIP39 12/24-word mnemonics (any format), Ethereum private keys, Bitcoin WIF** |
| Keys | RSA / EC / SSH private keys, JWT secrets |
| **Base64** | **Encoded secrets — decoded and matched against known prefixes** |
| Catch-all | Any `PASSWORD=`, `SECRET=`, `API_KEY=`, `TOKEN=` longer than 8 chars |

### Git history scan
Catches secrets that were committed in the past — even if they were deleted later. GitHub caches all commits forever.

```bash
aiguard --history
```

---

## Usage

```bash
# Scan current directory (blocks npm publish / git push)
aiguard

# Scan a specific project
aiguard /path/to/project

# Scan git history for past leaks
aiguard --history

# Combine both
aiguard /path/to/project --history
```

**Exit codes:**
- `0` — clean or warnings only
- `1` — CRITICAL or HIGH findings (publish blocked)

**Example output:**

```
aiguard — AI secret leak scanner
Project: /my-package

🚨 CRITICAL — publish blocked (1):
   CLAUDE.md
   This file contains API keys and tokens — it will be included in your npm package!

⚠️  HIGH RISK — publish blocked (2):
   CLAUDE.md
   Anthropic API key: sk-ant-***...agAA
   CLAUDE.md
   Crypto mnemonic (BIP39 seed): abandon ability ***...*** 

💡 WARNINGS (1):
   .env
   Excluded from publish but contains 2 secrets: AWS Access Key ID, Generic secret in env

❌ Publish blocked: 1 critical + 2 high findings.
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

## Use as a global Claude Code hook

**Install once, protect all projects automatically.**

Runs before every `git commit`, `git push`, and `npm publish` in any Claude Code session — no per-project setup needed.

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$HOME/.claude/bin/aiguard-guard.sh\"",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

Save this as `~/.claude/bin/aiguard-guard.sh` (chmod +x):

```bash
#!/bin/bash
CMD=$(python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('command', ''))
except:
    pass
" 2>/dev/null)

if ! echo "$CMD" | grep -qE '^\s*(git\s+(push|commit|tag)\b|npm\s+publish\b)'; then
    exit 0
fi

if command -v aiguard &>/dev/null; then
    aiguard "$(pwd)" 2>&1
    exit $?
else
    npx --yes @rimenko-dev/aiguard "$(pwd)" 2>&1
    exit $?
fi
```

---

## Use as a pre-commit hook (git)

```bash
# In your project root:
echo '#!/bin/sh\naiguard .' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

---

## Severity levels

| Level | Meaning | Blocks publish? |
|-------|---------|-----------------|
| 🚨 CRITICAL | AI secret file will be included in the package | ✅ Yes |
| ⚠️ HIGH | Known secret pattern found in a publishable file | ✅ Yes |
| 💡 WARN | Risk exists locally (excluded file contains secrets, missing .npmignore) | ❌ No |

---

## How it works

**For npm projects** (has `package.json`):
1. Resolves exactly which files `npm publish` would include — respects `files` field and `.npmignore` (including wildcard patterns like `*.env`, `*.local`)
2. Scans only those files — no false positives from files that won't be published
3. Reports ALL instances of each secret per file (not just the first)
4. Blocks publish on CRITICAL or HIGH findings

**For non-npm projects** (Go, Python, Rust, etc.):
1. Scans all non-gitignored files
2. Reports findings before `git push`

**Crypto mnemonic validation:**
Candidate phrases are validated against the full official BIP39 wordlist (2048 words). At least 90% of words must be real BIP39 words — ordinary English sentences are not flagged.

**Base64 detection:**
Strings labeled as keys/tokens are decoded from Base64, then the decoded value is checked against all known secret prefixes (`sk-ant-`, `AKIA`, `sk_live_`, etc.).

**What it does NOT scan:**
- Environment variables (runtime values, not in files)
- Binary files, images, PDFs
- Non-standard secret formats with no known prefix

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

Pull requests welcome. To add new secret patterns, edit `src/patterns.js` — each entry needs a `name` and a `regex` with the `g` flag. Patterns that need post-match validation (like BIP39 mnemonics) can add a `validate(match)` function.

---

## License

MIT — [github.com/RimenKo/aiguard](https://github.com/RimenKo/aiguard)
