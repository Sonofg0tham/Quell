# Quell

[![VS Marketplace Version](https://img.shields.io/visual-studio-marketplace/v/Sonofg0tham.quell)](https://marketplace.visualstudio.com/items?itemName=Sonofg0tham.quell)
[![VS Marketplace Installs](https://img.shields.io/visual-studio-marketplace/i/Sonofg0tham.quell)](https://marketplace.visualstudio.com/items?itemName=Sonofg0tham.quell)

**Stop leaking secrets to AI.** Quell intercepts your prompts, scans for API keys, tokens, passwords, and connection strings — and replaces them with secure placeholders before the AI ever sees them. Real values are stored safely in your OS Keychain.

> 100% offline. Zero network calls. Zero telemetry. Your secrets never leave your machine.

<!-- Screenshots — drop PNGs into assets/ and uncomment these lines
![Quell sidebar dashboard](assets/screenshot-sidebar.png)
![Inline diagnostics and Quick Fix](assets/screenshot-diagnostics.png)
![Before and after redaction](assets/screenshot-redaction.png)
-->

---

## 🚨 The Problem

Every time you paste code into an AI chat (Copilot, Cursor, Windsurf, Antigravity), secrets get silently transmitted to cloud-hosted models:

| What You Do | What Leaks |
|---|---|
| Paste `.env` asking "why won't my DB connect?" | Database passwords, API keys |
| Copy `payment.ts` asking "why is Stripe failing?" | `sk_live_XXXXXXX` (live Stripe key) |
| AI IDE indexes your workspace | Every `.env`, `config.json`, `credentials.yml` |

**Quell is the security layer between you and the AI.**

---

## ⚡ How It Works

1. **You write code** with real secrets
2. **Quell scans** using 75+ regex patterns + Shannon entropy analysis
3. **AI receives safe placeholders** — `{{SECRET_xxx}}` instead of your real keys

```diff
# Before (DANGEROUS)
- STRIPE_KEY=sk_live_REPLACE_WITH_YOUR_KEY
- DATABASE_URL=postgres://admin:YOUR_PASSWORD@db.example.com:5432/mydb

# After Quell (SAFE)
+ STRIPE_KEY={{SECRET_52c14bbbc02e}}
+ DATABASE_URL={{SECRET_f6d2e5e49c86}}
+ AWS_REGION=us-east-1  ← non-secret, left unchanged
```

---

## ✨ Features

### 📋 Copy Redacted (`Ctrl+Shift+C`)
Select code → press the shortcut → paste into any AI chat. Secrets are replaced, non-secrets are preserved. The primary workflow.

### 📥 Sanitized Paste (`Ctrl+Shift+V`)
Paste from any source with secrets automatically stripped. Works with code copied from browsers, terminals, or other files.

### 🔍 75+ Secret Patterns
Regex-based detection covering:

| Category | Examples |
|---|---|
| **Cloud** | AWS (`AKIA...`), Google Cloud, Azure |
| **AI/ML** | OpenAI, Anthropic, Hugging Face, Gemini |
| **Payments** | Stripe (`sk_live_...`), Square, PayPal |
| **Version Control** | GitHub PATs, GitLab, Bitbucket |
| **Communication** | Slack, Discord, Telegram, Twilio |
| **Databases** | PostgreSQL, MongoDB, Redis, MySQL URIs |
| **Auth** | JWTs, Bearer tokens, Basic Auth, OAuth |
| **Crypto** | RSA, EC, OpenSSH, PGP private keys |
| **Hosting** | Vercel, Netlify, Heroku, DigitalOcean, Fly.io |
| **BaaS** | Supabase (`sb_publishable_...`, `sb_secret_...`) |
| **+ 30 more** | SendGrid, Shopify, Datadog, NPM, PyPI... |

### 📊 Shannon Entropy Analysis
Catches high-randomness tokens that don't match any known pattern — configurable threshold and minimum token length.

### 🤖 AI Indexing Shield
One-click toggle that generates `.cursorignore`, `.windsurfignore`, `.antigravityignore`, `.aiderignore`, and `.aiignore` files — blocking AI IDEs from silently indexing your secret files.

### ⚡ Clipboard Sentry & Auto-Sanitize
Passive clipboard monitoring that warns you within 1 second when a secret is on your clipboard. Enable **Auto-Sanitize** from the sidebar dashboard to automatically replace clipboard secrets with safe placeholders — so even a regular `Ctrl+V` into Cursor or Windsurf chat is safe.

### 🔍 Live Editor Diagnostics
Exposed secrets are highlighted with yellow squiggly underlines in real-time as you type. They appear in VS Code's **Problems** panel. Click the 💡 lightbulb (or `Ctrl+.`) for a one-click **Quick Fix** to redact them instantly.

### 🔒 Secure Storage
Secrets stored in your **OS Keychain** via VS Code's SecretStorage API (Windows Credential Manager / macOS Keychain / libsecret). Never written to disk in plaintext. Restorable anytime.

### 📝 Inline Decorations
`{{SECRET_xxx}}` placeholders get orange dashed borders and 🔒 icons in the editor. Hover for restore options.

### 💬 Chat Participant (`@quell`)
Talk to `@quell` in VS Code's chat panel. Every prompt is scanned before it reaches the AI. Use `/context` to safely share `.env` file structure.

### ⚠️ Smart Save Warnings
Get notified when saving a file that still contains raw secrets — with a one-click "Redact Now" option. Dismiss warnings per-file for the rest of your session. They only come back if you add new secrets to that file.

---

## ⚙️ Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `quell.enableEntropyScanning` | `true` | Enable Shannon Entropy analysis |
| `quell.entropyThreshold` | `4.5` | Minimum entropy to flag (2.0–7.0) |
| `quell.minimumTokenLength` | `20` | Minimum token length for entropy scanning |
| `quell.customPatterns` | `[]` | Custom regex patterns (`[{name, regex}]`) |
| `quell.whitelistPatterns` | `[]` | Regex patterns to exclude from detection |
| `quell.showInlineDecorations` | `true` | Show inline decorations for placeholders |
| `quell.confirmBeforeRedact` | `false` | Confirmation dialog before file redaction |
| `quell.autoSanitizeClipboard` | `false` | Auto-replace clipboard secrets with placeholders |

---

## 📦 Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| Copy Redacted | `Ctrl+Shift+C` | Copy with secrets redacted |
| Sanitized Paste | `Ctrl+Shift+V` | Paste with secrets stripped |
| Redact Active File | — | Redact all secrets in current file |
| Redact Selection | — | Redact secrets in selected text |
| Restore Secrets | — | Restore placeholders from Keychain |
| Scan Workspace | — | Full workspace secret audit |
| Show Log | — | Open the Quell output panel |

---

## 🔐 Privacy & Security

- **100% offline** — zero network calls, zero telemetry, zero external APIs
- **OS Keychain storage** — secrets encrypted at rest by your operating system
- **Non-destructive** — real values always restorable from the Keychain
- **Open source** — [audit the code yourself](https://github.com/sonofg0tham/Quell)

---

## 🤝 Compatible IDEs

| IDE | Supported | AI Shield |
|-----|-----------|-----------|
| VS Code | ✅ | `.aiignore` |
| Cursor | ✅ | `.cursorignore` |
| Windsurf | ✅ | `.windsurfignore` |
| Antigravity | ✅ | `.antigravityignore` |
| Aider | ✅ | `.aiderignore` |

---

## 🎓 Guided Onboarding

New to Quell? On first install, a **Getting Started walkthrough** opens automatically in the VSCode Welcome tab. It walks you through:

1. What Quell does and why you need it
2. A **live demo** with fake credentials so you can see detection in action
3. The two key shortcuts (`Ctrl+Shift+C` and `Ctrl+Shift+V`)
4. Setting up the AI Indexing Shield
5. How your secrets are stored (OS Keychain, fully offline)

You can reopen it anytime from the Command Palette: `Quell: Getting Started`.

## 🚀 Quick Start

1. Install Quell from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=Sonofg0tham.quell)
2. Follow the onboarding walkthrough
3. Press `Ctrl+Shift+C` to copy code safely for AI chat
4. Enable the **AI Indexing Shield** in the sidebar to block AI file indexing
5. Enable **Clipboard Auto-Sanitize** in the sidebar for maximum protection
6. Use `@quell /context` to safely share `.env` structure

---

## 📄 License

[MIT](LICENSE) — free and open source.
