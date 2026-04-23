# Changelog

All notable changes to Quell will be documented in this file.

## [2.7.0] - 2026-04-23

### 🔍 New Detection Patterns
- **OpenRouter API Key** (`sk-or-v1-...`) — multi-model routing for AI apps
- **Groq API Key** (`gsk_...`) — fast inference provider
- **Perplexity API Key** (`pplx-...`) — search-augmented LLM
- **xAI API Key** (`xai-...`) — Grok models
- **LangSmith API Key** (`lsv2_pt_...` / `lsv2_sk_...`) — LLM tracing & eval

### 🧹 Pattern Hygiene
- **Tightened** Mailgun regex to hex-only (was accepting any 32-char alphanumeric after `key-`)
- **Tightened** Okta regex with word boundaries (was firing on any `00`-prefixed string)
- **Removed** Cohere `co-` pattern — prefix is too generic; entropy pass catches the real keys
- **Removed** Heroku — loose regex with no test coverage, platform usage declining
- **Removed** Firebase Cloud Messaging legacy pattern — Google deprecated the legacy FCM API
  in June 2024. OAuth service accounts are still covered by the existing Google pattern.

### 🎨 UI
- **Activity-bar sidebar icon** redesigned as a circle with a redaction-bar tail (the Quell
  mark), using `currentColor` so it recolours with the VSCode theme instead of always
  rendering blue.
- **Marketplace icon** replaced — the 3D crystal render is gone. The new flat two-tone mark
  uses Quell blue (`#60A5FA`) for the circle and a coral accent (`#F97316`) for the
  redaction bar, matching the sidebar silhouette so both surfaces read as one product.
- **`assets/icon.svg`** added as the vector master for the Marketplace PNG, so future size
  variants and theme adjustments can be regenerated without losing quality.

## [2.6.0] - 2026-04-22

### 🔍 New Detection Patterns
- **PlanetScale API Token** (`pscale_tkn_...`) — database branching platform
- **Resend API Key** (`re_...`) — transactional email API
- **Linear API Key** (`lin_api_...`) — project management API

### 🧪 Scanner Correctness
- **PostgreSQL URI double-detection regression test** — added explicit tests confirming a
  PostgreSQL connection URI is always counted as a single secret, even when the embedded
  password is high-entropy. Guards against future regressions in the detection pipeline.

### 📝 Notes
- Lemon Squeezy keys are JWTs and were already covered by the JSON Web Token pattern.
- Mistral, Loops, and Neon keys have no distinctive token prefix; they are caught by the
  Shannon entropy pass (threshold 4.5 bits).

## [2.5.1] - 2026-04-20

### 🔧 Publish Fix
- **VSIX test file exclusion** — `.vscodeignore` now excludes compiled test files
  (`out/packages/scanner/src/test/**`, `packages/scanner/dist-test/**`,
  `packages/scanner/src/test/**`). The VS Code Marketplace secret scanner was
  flagging test fixture strings in compiled test output as real secrets. Test files
  have no place in a published extension.

## [2.5.0] - 2026-04-17

### 🛡️ Vault Management
- **Clear Vault command** — `Quell: Clear Vault (delete all stored secrets)` permanently removes all secrets from the OS Keychain. Uses a `globalState`-backed index (since VSCode SecretStorage has no enumeration API) to track which placeholders have been stored. Includes a modal confirmation before deleting.

### ⚙️ Test Key Filtering
- **`quell.redactTestKeys` setting** (default: `false`) — officially-published test/demo credentials (e.g. `AKIAIOSFODNN7EXAMPLE`) are now left alone by default, since they are intentionally safe and appear in READMEs and tutorials. Set to `true` to redact them like any other secret.

### 🔒 Security Hygiene
- **Placeholder length increased** — `{{SECRET_...}}` identifiers now use 16 hex characters (up from 12) for better collision resistance across large vaults.
- **CodeQL CI** — GitHub Actions workflow added: CodeQL security scan runs on every push/PR to `main` and weekly. Uses `security-extended` + `security-and-quality` query suites. The security tool now scans itself.

### 📋 Contribution scaffolding
- Added `CONTRIBUTING.md`, issue templates (bug, feature, pattern suggestion), and security advisory redirect.

### 🔐 Security
- **Webview command allowlist** — the sidebar webview now validates every `executeCommand` message against an explicit `ALLOWED_COMMANDS` set. Previously any webview message could trigger arbitrary VSCode commands; now only the 11 permitted Quell commands are accepted. Eliminates a webview RCE vector.

### ⚡ Performance
- **O(1) duplicate-secret deduplication** — `SecretScanner.redact()` previously used `string.split().join()` and a linear `Map.has()` scan to deduplicate secrets. Now uses a reverse `valueToPlaceholder` Map for O(1) lookup and `String.replaceAll()` with a callback, improving performance on large files with repeated secrets.

### ♿ Accessibility
- **ARIA descriptions on toggle buttons** — the AI Shield and Auto-Sanitize toggle buttons in the sidebar now carry `aria-describedby` attributes pointing to descriptive hint text, improving screen reader experience.

### 📦 Dependencies
- `@types/vscode` bumped from `^1.90.0` to `^1.115.0` — picks up 25 releases of API type definitions.

## [2.4.0] - 2026-03-22

### 🎓 Native Onboarding Walkthrough
- **Getting Started walkthrough** — new users now see a 5-step guided walkthrough in the VSCode Welcome page on first install: explains what Quell does, runs a live demo with fake credentials, teaches the two key shortcuts, sets up AI Shield, and builds trust in the offline/keychain privacy model
- **Demo file command** — `Quell: Open Demo File` opens an untitled file with fake AWS credentials so you can watch detection and redaction in action

### 🔔 Smarter Save Warnings
- **Session-level dismissal** — save warnings now include a "Dismiss for this session" button. Once dismissed, that file stays silent for the rest of the session unless you add new secrets (in which case the warning comes back)
- Previously the warning fired on every single save of a file containing secrets — this was the most common source of noise

### ⚙️ Default Change
- **`confirmBeforeRedact` now defaults to `false`** — the modal confirmation before redacting has been turned off by default. It blocked the editor on every redaction and added friction without benefit for most workflows. You can re-enable it in Settings if you want the extra prompt

### 🔒 Added Patterns
- **Supabase Publishable Key** (`sb_publishable_...`) — new Supabase anon key format
- **Supabase Secret Key** (`sb_secret_...`) — new Supabase service role key format

## [2.3.0] - 2026-03-14

### 🛡️ Smarter Quick Fix
- **Per-secret Quick Fix** — the `💡` lightbulb now offers "Redact this secret" to replace a single flagged secret inline, alongside the existing "Redact all secrets in file" option

### 🔍 Better First-Run Experience
- Clean workspaces now show a confirmation toast on first install instead of silence
- Initial scan now notes if your workspace exceeded the 50-file preview limit and prompts a full scan

### ⚙️ Reliability
- Invalid custom regex patterns now log a warning in the Quell output channel instead of silently failing
- Marketplace: added gallery banner and improved keywords for discoverability

## [2.2.0] - 2026-03-11

### ✨ Cursor & Windsurf Protection
- **Clipboard Auto-Sanitize** — when enabled, Quell monitors your clipboard every second and automatically replaces copied secrets with safe `{{SECRET_...}}` placeholders before you can paste them into native AI chats
- **Dashboard toggle** — enable/disable Auto-Sanitize directly from the Quell sidebar (no need to find it in settings)
- Auto-dismiss notification (5s timeout) when secrets are sanitized

### 🔍 Live Editor Diagnostics
- **Inline secret warnings** — exposed secrets now show yellow squiggly underlines in the editor in real-time
- **Problems Panel** integration — all detected secrets appear in VS Code's Problems tab
- **Quick Fix lightbulb** — click 💡 or press `Ctrl+.` to instantly redact secrets from the editor

### 🐛 Major False Positive Reduction
- Removed `secret` keyword from Password regex (too common in code like `console.error('secret:', ...)`)
- Password/Token regexes no longer match across line breaks and are length-capped
- Entropy scanner now skips: SCREAMING_SNAKE_CASE identifiers, camelCase/PascalCase variables, dotted property access, env variable references, webpack identifiers, URL-encoded paths, base64 source maps, base32/base36 character sets, minified CSS/JS fragments
- Workspace scan excludes: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `.next*/`, `.nuxt/`, `.vercel/`, `_next/`, `static/chunks/`

### 🛠 UX Improvements
- **Sidebar buttons now work without clicking into the editor first** — Redact File, Restore Secrets, etc. operate on the last focused file
- **Clickable findings** in the dashboard — click a file in the Findings list to open it directly
- Clipboard Sentry warning now offers one-click "Enable Auto-Sanitize" button
- Clipboard polling interval reduced from 3s to 1s for faster interception

## [2.1.0] - 2026-03-11

### ✨ Rebrand: Quell
- **Renamed from VyberGuard to Quell** — new identity across all UI, commands, and branding
- Cleaned up all internal identifiers, settings, and command IDs to use `quell.*`
- Updated AI Shield markers and status bar branding

## [2.0.0] - 2026-03-05

### ✨ Redesign & Identity
- **Consolidated identity as VyberGuard** (previously VibeGuard)
- **Premium sidebar redesign** — glassmorphism cards, teal accent gradients, pulse animations, breathing status dot, shimmer effects, and refined typography
- **Updated extension icon** — sleek shield + lock design

### Fixed
- Payment provider regex (Stripe, PayPal, Square) now catches a wider range of key formats, including keys with underscores and varying lengths
- Sidebar "Intercepted" label renamed to "Detected" for clarity — Scan All finds secrets, it doesn't redact them
- Stale "VibeGuard" references cleaned up across all files

## [1.5.0] - 2026-02-28

### Added
- **AI Indexing Shield** — one-click protection that generates `.cursorignore`, `.windsurfignore`, `.antigravityignore`, `.aiderignore`, and `.aiignore` files to block AI IDEs from reading secret files
- **Copy Redacted** (`Ctrl+Shift+C`) — copies selected text with secrets replaced by `{{SECRET_...}}` placeholders, ready to paste into any AI chat
- **Sanitized Paste** (`Ctrl+Shift+V`) — pastes clipboard content with secrets automatically stripped
- **Clipboard Sentry** — passive clipboard monitoring that warns when a secret is detected on your clipboard (polls every 3 seconds, purely informational)
- **Vibe Check** — automatic first-install workspace scan with actionable "Enable AI Shield" notification
- **Premium sidebar dashboard** — activity bar panel with shield toggle, session stats, findings list, tool grid, and engine info
- **Exposure badge** in status bar showing raw secret count after workspace scan

### Changed
- Status bar now shows multiple states: idle, AI Shield ON, scanning, alert, clean
- Sidebar includes live session statistics (scans count, detected secrets)

## [1.1.0] - 2026-02-23

### Added
- 75+ secret detection patterns (up from 14) covering AWS, Google, Azure, OpenAI, Anthropic, Stripe, GitHub, GitLab, Slack, Discord, JWTs, database connection strings, private keys, and more
- Shannon Entropy analysis for catching unknown/proprietary API keys
- Status bar indicator with live scanning/alert/safe states
- Dedicated Output Channel logging ("Quell" in Output panel)
- User-configurable settings: entropy toggle, threshold, min token length, custom patterns, whitelisting, inline decorations, confirmation dialog
- Inline editor decorations for placeholder tokens (orange borders + 🔒 icons)
- "Redact Selection" command with context menu integration
- "Scan Workspace" command for full project scanning
- File save watcher that warns about raw secrets
- Confirmation dialog before file redaction
- Comprehensive test suite (56 tests)
- README and extension icon

### Fixed
- Basic Auth regex was broken (only matched 1 character instead of full credentials)
- `EnvManager` used blocking `fs.readFileSync` — now uses async `vscode.workspace.fs.readFile`
- Placeholder IDs now use `crypto.randomUUID()` instead of `Math.random()`
- Removed overly broad Postmark/UUID regex that caused false positives
- Added `.env` to `.gitignore` (was missing — security risk)

## [1.0.0] - 2026-02-19

### Added
- Initial extension skeleton with Chat Participant
- Basic secret detection (14 regex patterns)
- Shannon Entropy scanning
- Redact Active File command
- Restore Secrets command
- Hover provider for placeholders
