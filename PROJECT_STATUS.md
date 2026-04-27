# Quell - Working Status

Living tracker of where Quell is, what's landed, and what's next. Update after every session that changes state. Sits alongside `POSITIONING.md` (strategy) and `FIX_PROMPTS/` (concrete next actions).

*Last updated: 2026-04-27 (round 12 landed: Claude Code plugin scaffold + UserPromptSubmit hook with smoke tests; fourth Quell surface in repo)*

## Snapshot

- **Repo**: `C:\\Users\\craig\\Github Repos\\Quell`, single checkout on `main`
- **Publisher**: `Sonofg0tham`
- **Extension**: v2.7.0 live on Marketplace and OpenVSX
- **Scanner npm package**: [`@sonofg0tham/quell-scanner@0.1.0`](https://www.npmjs.com/package/@sonofg0tham/quell-scanner) live on npm (zero runtime deps, 46.7 kB unpacked)
- **Claude Code plugin**: `@sonofg0tham/quell-claude@0.1.0` in repo at `packages/claude-plugin/` (not yet distributed via marketplace; install locally via `claude --plugin-dir`)
- **Licence**: MIT
- **Adoption (as of 2026-04-09)**: OpenVSX 484 downloads / 7 installs, VSCode Marketplace 65 acquisitions in last 30 days
- **Tests**: 78/78 scanner + 3/3 plugin hook = 81/81 passing
- **Working tree**: clean, up to date with origin/main

## Workflow rules for this project

- Craig is a vibe coder. Cowork session (Sonnet) reads the codebase, identifies improvements, writes comprehensive prompt docs Craig pastes into Claude Code. Claude Code does all edits, compile/test verification, commit, and push. No sandbox edits unless Craig specifically requests them.
- Sandbox cannot push. Sandbox cannot delete files on the mounted Windows filesystem.
- Work from the single `main` checkout. No worktrees.
- Jules agent is active on the repo and may land PRs between sessions — always check `git log` first.

## Future release process

With `.github/workflows/release.yml` in place, future versions work like this:

1. Bump version in `package.json` + update `CHANGELOG.md`
2. Commit and push to main
3. Push a tag: `git tag v2.6.0 && git push origin v2.6.0`
4. GitHub Actions builds `quell-2.6.0.vsix` and attaches it to a GitHub Release automatically
5. Download the VSIX from the release, upload to VS Code Marketplace manually
6. Run `npx ovsx publish quell-2.6.0.vsix -p <token>` for OpenVSX

## What's landed

### Commit `1afe650` - Supabase test cases
### Commit `a655d49` - Round 1: correctness, hygiene, false-positive reduction (58/58)
### Round 2a - Planning docs tidy commit
### Commit `3828ca6` - Round 2b: scanner extraction to packages/scanner/ (@quell/scanner v0.1.0, not yet published)
### Commit `f77977a` - Round 3a: CodeQL CI + CONTRIBUTING + issue templates
### Commit `1b626e6` - Round 3b: UUID 12→16 bump
### Commit `cd028a5` - Round 3c: quell.clearVault command (globalState vault index)
### Commit `0f1fc26` - Round 3d: quell.redactTestKeys setting (60/60, 2 new tests)
### Commit `a956e69` - Round 4a: Fix broken demo (replaced AKIA key with GitHub PAT + PostgreSQL + OpenAI)
### Commit `aa94bd2` - Round 4b: v2.5.0 bump, CHANGELOG, fix UUID length in README
### Commit `74d1427` - Round 4c: README — clearVault and redactTestKeys added to docs tables
### Commit `12021e3` - Round 4d: Extract getConfig() to src/configHelper.ts
### Commit `5a3fcf3` - Round 4e: publishConfig added to packages/scanner/package.json
### Commit `d3aa1e2` - Round 4f: .Jules/ renamed to .jules/
### Commit `879ed58` - Jules: webview RCE fix (command allowlist), SecretScanner O(1) perf, a11y, @types/vscode bump
### Round 5 (8 commits) — CHANGELOG update, hover tooltip fix, toggleAutoSanitize command registration, Clear Vault sidebar button, vaultIndexAdd O(1) optimisation, scanner README rewrite, screenshot stubs, PROJECT_STATUS update
### Round 6 (2 commits) — engines.vscode + @types/vscode aligned to ^1.107.0 (vsce fix), real marketplace screenshots landed
### Round 7 (5 commits) — v2.5.1 .vscodeignore fix, GitHub Actions release workflow, category 'Education' + preview:false, improved marketplace description, PROJECT_STATUS update
### Round 8 (5 commits) — PostgreSQL double-detection regression tests, PlanetScale + Resend + Linear patterns, v2.6.0 bump (69/69 tests)
### Round 9 (7 commits) — removed Heroku + legacy Firebase FCM, tightened Cohere/Mailgun/Okta, added OpenRouter + Groq + Perplexity + xAI + LangSmith patterns, redesigned sidebar icon as themeable shield, v2.7.0 bump (78/78 tests)
### Round 10 (3 commits) — final Q-and-redaction-bar mark replaced shield sidebar SVG, two-tone `assets/icon.svg` master added, regenerated `assets/icon.png`, `assets/hero-banner.png` removed
### Round 10b (1 commit) — CHANGELOG v2.7.0 UI section rewritten to describe the final mark, then v2.7.0 tagged
### Post-tag fix (1 commit) — `FIX_PROMPTS/` removed from tracking + ignored in git/VSIX, `permissions: contents: write` added to release.yml (previous v2.7.0 workflow run 403'd because `GITHUB_TOKEN` couldn't create a release); v2.7.0 release built locally and attached manually
### Round 11 (3 commits) — scanner package renamed twice for npm scope (final: `@sonofg0tham/quell-scanner` after Craig created a new npm account matching his GitHub handle), then published to npm with 2FA enabled
### Round 12 (3 commits) — Claude Code plugin scaffold at `packages/claude-plugin/`: `UserPromptSubmit` hook that BLOCKS prompts containing secrets (exit 2 + redacted-version stderr) so the original never reaches the model; bundled compiled scanner (no `npm install` step required); fail-open contract on bad stdin, missing scanner, scanner throws, empty prompts; 5s config timeout / 4s script safety net; 3/3 smoke tests covering clean passthrough, regex-path block (asserts redacted output AND that the original secret value is NOT in stderr), fail-open on malformed stdin. Misplaced first commit landed on `fix/code-scanning-alerts` and was cherry-picked back to `main`; CodeQL fix branch left untouched

## What's next

### Plugin v0.2 — vault + `/quell-restore` (natural next round)
The block-and-resubmit UX from v0.1.0 drops the original secret values on the floor.
v0.2 adds persistent storage (likely `${CLAUDE_PLUGIN_DATA}` keyed by placeholder)
and a slash command that swaps real values back when Claude's response references
them. This is the convenience layer that makes the safety win usable day-to-day.

### Pending — small backlog
- Wire `node packages/claude-plugin/test/redact.test.js` into the existing CI workflow so plugin regressions break CI alongside scanner regressions (after a week of dogfooding to confirm no flakes)
- Dogfood the plugin in Craig's own Claude Code sessions for a week before any wider distribution
- PostgreSQL double-detection confirmed as non-issue (same-value dedup works correctly)

### Post-launch
- Launch post (Product Hunt / HN / LinkedIn/Twitter) — covers all four surfaces: Marketplace extension, OpenVSX extension, npm scanner, Claude Code plugin. Gated on the dogfood week.
- Monitor adoption numbers, respond to issues
- Explore monetisation surfaces: team pattern packs, CI integration (uses @sonofg0tham/quell-scanner npm package)
