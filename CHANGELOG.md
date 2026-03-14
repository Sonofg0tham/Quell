# Changelog

All notable changes to Quell will be documented in this file.

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
