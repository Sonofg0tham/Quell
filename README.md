# 🛡️ VibeGuard

**Prevent secret leakage in AI chats — fully offline, zero network calls.**

VibeGuard intercepts your prompts, scans for API keys / tokens / passwords / connection strings, and replaces them with secure placeholders before the AI ever sees them. Real values are stored safely in your OS Keychain.

> Built for the age of AI-assisted coding. Your secrets stay on your machine.

---

## ✨ Features

### 🔍 Chat Participant
Talk to `@vibeguard` in your IDE's chat panel. Every prompt is scanned before it reaches the AI.

- Detects secrets and shows a security intercept with redacted output
- `/context` command shares a redacted view of your `.env` files (keys visible, values masked)

### 🧬 75+ Secret Patterns
Regex-based detection for:
- **Cloud**: AWS, Google Cloud, Azure
- **AI/ML**: OpenAI, Anthropic, Hugging Face, Cohere, Replicate, Gemini
- **Payments**: Stripe, Square, PayPal
- **Version Control**: GitHub, GitLab, Bitbucket (PATs, OAuth, fine-grained tokens)
- **Communication**: Slack, Discord, Telegram, Twilio
- **Email**: SendGrid, Mailgun, Mailchimp
- **Hosting**: Heroku, Vercel, Netlify, DigitalOcean, Render, Railway, Fly.io
- **Auth**: JWT, Bearer, Basic Auth, OAuth
- **Cryptographic**: RSA, EC, DSA, OpenSSH, PGP private keys
- **Databases**: PostgreSQL, MySQL, MongoDB, Redis, AMQP connection URIs
- **Infrastructure**: Hashicorp Vault, Terraform Cloud, Doppler
- **E-commerce**: Shopify
- **Monitoring**: Datadog, Sentry, New Relic
- **Package Registries**: NPM, PyPI, NuGet, RubyGems

### 📊 Shannon Entropy Analysis
Catches high-randomness tokens that don't match any known pattern — configurable threshold and token length.

### 🔒 Secure Storage
Secrets are stored in your **OS Keychain** via VS Code's SecretStorage API. Never written to disk in plaintext.

### 📝 Inline Decorations
Placeholder tokens (`{{SECRET_xxx}}`) are highlighted inline with orange borders and 🔒 icons.

### 🖱️ Context Menu
Right-click to:
- **Redact Selection** — scan and replace secrets in highlighted text
- **Redact Active File** — scan the entire file
- **Restore Secrets** — bring back real values from the keychain

### 🔎 Workspace Scanner
Scan your entire workspace for secrets across all code files with a single command.

### ⚠️ Save Warning
Get warned when saving a file that still contains raw secrets.

### 📊 Status Bar
Persistent shield indicator showing protection state (idle / scanning / alert / safe).

### 📋 Output Log
Full activity log in the Output panel under "VibeGuard".

---

## ⚙️ Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `vibeguard.enableEntropyScanning` | `true` | Enable Shannon Entropy analysis |
| `vibeguard.entropyThreshold` | `4.5` | Minimum entropy to flag (2.0–7.0) |
| `vibeguard.minimumTokenLength` | `20` | Minimum token length for entropy scanning |
| `vibeguard.customPatterns` | `[]` | Custom regex patterns (`[{name, regex}]`) |
| `vibeguard.whitelistPatterns` | `[]` | Regex patterns to exclude from detection |
| `vibeguard.showInlineDecorations` | `true` | Show inline decorations for placeholders |
| `vibeguard.confirmBeforeRedact` | `true` | Confirmation dialog before file redaction |

---

## 📦 Commands

| Command | Description |
|---------|-------------|
| `VibeGuard: Redact Secrets in Active File` | Scan and redact the current file |
| `VibeGuard: Redact Secrets in Selection` | Scan and redact selected text |
| `VibeGuard: Restore Secrets in Active File` | Restore placeholders from keychain |
| `VibeGuard: Scan Workspace for Secrets` | Full workspace scan with report |
| `VibeGuard: Show VibeGuard Log` | Open the output panel |

---

## 🔐 Privacy & Security

- **100% offline** — zero network calls, zero telemetry
- **No external APIs** — all detection is regex + entropy, running locally
- **OS Keychain storage** — secrets stored via VS Code's SecretStorage (backed by your OS credential manager)
- **Open source** — audit the code yourself

---

## 🚀 Getting Started

1. Install the extension (VSIX or Marketplace)
2. Open any workspace
3. Use `@vibeguard` in the chat panel, or right-click any file to scan
4. Use `/context` to safely share `.env` file structure with the AI

---

## 🤝 Compatible IDEs

Works with any VS Code-based IDE:
- VS Code
- Cursor
- Windsurf
- Antigravity (Gemini Code Assist)

---

## 📄 License

MIT
