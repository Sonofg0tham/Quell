# Changelog

## [1.1.0] - 2026-02-23

### Added
- 75+ secret detection patterns (up from 14) covering AWS, Google, Azure, OpenAI, Anthropic, Stripe, GitHub, GitLab, Slack, Discord, JWTs, database connection strings, private keys, and more
- Status bar indicator with live scanning/alert/safe states
- Dedicated Output Channel logging ("VyberGuard" in Output panel)
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
