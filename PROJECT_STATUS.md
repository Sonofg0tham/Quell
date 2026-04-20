# Quell - Working Status

Living tracker of where Quell is, what's landed, and what's next. Update after every session that changes state. Sits alongside `POSITIONING.md` (strategy) and `FIX_PROMPTS/` (concrete next actions).

*Last updated: 2026-04-20 (round 7 landed: v2.5.1 live on marketplace, release workflow in place)*

## Snapshot

- **Repo**: `C:\\Users\\craig\\Github Repos\\Quell`, single checkout on `main`
- **Publisher**: `Sonofg0tham`
- **Version in repo**: v2.5.1 (live on VS Code Marketplace and OpenVSX)
- **Licence**: MIT
- **Adoption (as of 2026-04-09)**: OpenVSX 484 downloads / 7 installs, VSCode Marketplace 65 acquisitions in last 30 days
- **Tests**: 60/60 passing
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

## What's next

### Pending publish
- **npm (@quell/scanner)** — `cd packages/scanner && npm run build && npm publish` (needs `npm login` as Sonofg0tham first). Verify at https://www.npmjs.com/package/@quell/scanner

### Post-launch
- Launch post (Product Hunt / HN / LinkedIn/Twitter)
- Monitor adoption numbers, respond to issues
- Explore monetisation surfaces: team pattern packs, CI integration (uses @quell/scanner npm package)
