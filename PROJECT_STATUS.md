# Quell - Working Status

Living tracker of where Quell is, what's landed, and what's next. Update after every session that changes state. Sits alongside `POSITIONING.md` (strategy) and `FIX_PROMPTS/` (concrete next actions).

*Last updated: 2026-04-17 (round 3 complete, awaiting git commits)*

## Snapshot

- **Repo**: `C:\\Users\\craig\\Github Repos\\Quell`, single checkout on `main`
- **Publisher**: `Sonofg0tham`
- **Version on Marketplace**: v2.4.0
- **Licence**: MIT (stays MIT for the free tier)
- **Adoption (as of 2026-04-09)**: OpenVSX 484 downloads / 7 installs, VSCode Marketplace 65 acquisitions in last 30 days
- **Strategic direction**: keep generous free tier, extract `SecretScanner.ts` into `@quell/scanner` package to unlock CLI, GitHub Action, and monetisation surfaces

## Workflow rules for this project

- Craig is a vibe coder. Sandbox session (Cowork) does the code edits directly; Claude Code on Craig's machine handles git plumbing (add/commit/push)
- No more prompt docs by default. Sandbox makes the recommendations, applies the edits, hands a short git plan back to Claude Code
- Sandbox cannot push (security feature, consent-gated). Sandbox also cannot delete files on the mounted Windows filesystem, so file moves need `git rm` on the old copies via Claude Code
- Work from the single `main` checkout. The `claude/peaceful-dirac` worktree has been pruned
- Known sandbox gotcha: the Write tool doesn't truncate files on the mount - when overwriting a smaller-content file, null bytes get appended. Fix with a bash `python3` rewrite when it happens

## What's landed

### Commit `1afe650` - Supabase test cases
Added missing test cases for Supabase publishable and secret key patterns.

### Commit `a655d49` - Round 1 fixes
Correctness, hygiene, false-positive reduction:
- Removed broken Segment Write Key pattern (was catching Stripe keys)
- Removed redundant Google Gemini pattern (subset of Google API Key)
- Removed dead code in entropy scan (unreachable camelCase/PascalCase branch)
- Fixed `confirmBeforeRedact` default inconsistency between schema and code
- Skip files >1MB in `onWillSaveTextDocument` to avoid blocking saves
- Filter obvious placeholder passwords (changeme, hunter2, etc.) from `Password`/`Token in Assignment` matches
- Removed committed `.vsix` build artefacts and `pnpm-lock.yaml`
- Documented `Ctrl+Shift+V` rebinding in README

Compile clean, 58/58 tests passing.

### Round 2a - Planning doc / tidy commit
Committed `.gitattributes`, `POSITIONING.md`, `PROJECT_STATUS.md`, the `FIX_PROMPTS/` directory, and the `.gitignore` update.

### Commit `3828ca6` - Round 2b: scanner extraction
Moved `SecretScanner.ts` and its tests into `packages/scanner/` as `@quell/scanner` v0.1.0 (not yet published to npm). History preserved, standalone build and root build both work. Compile clean, 58/58 tests passing.

## What's next (awaiting git commits)

### Round 3 - ready to commit (4 commits)

All code is on disk. Compile clean, **60/60 tests passing** (2 new tests for `redactTestKeys`).

**Commit 1: CI + contribution scaffolding**
Files: `.github/workflows/codeql.yml` + `CONTRIBUTING.md` + `.github/ISSUE_TEMPLATE/{bug_report,feature_request,pattern_suggestion,config}.yml`
Message: "Add CodeQL CI workflow and contribution scaffolding"

**Commit 2: UUID 12→16 bump**
Files: `packages/scanner/src/SecretScanner.ts` + `packages/scanner/src/test/SecretScanner.test.ts` + `src/extension.ts`
Message: "Expand placeholder UUID from 12 to 16 hex chars"

**Commit 3: quell.clearVault command**
Files: `src/extension.ts` + `package.json`
Message: "Add quell.clearVault command to purge stored secrets from keychain"
Note: uses `context.globalState` under key `quell.vaultIndex` as a string[] index (since VSCode SecretStorage has no enumeration API). vaultIndexAdd called after every context.secrets.store. vaultIndexClear wipes the index after deleting each secret.

**Commit 4: quell.redactTestKeys setting**
Files: `packages/scanner/src/SecretScanner.ts` + `packages/scanner/src/test/SecretScanner.test.ts` + `src/extension.ts` + `src/DiagnosticProvider.ts` + `package.json`
Message: "Add quell.redactTestKeys setting to skip official test credentials"
Note: default false (test keys like AKIAIOSFODNN7EXAMPLE are left alone). Set true to treat them as real secrets. TEST_CREDENTIALS set in SecretScanner.redact(), isTestCredential() check added. 2 new tests.

**After committing, push:** `git push origin main`

### Round 4 - npm publish + GitHub Action
- `npm publish --access public` from `packages/scanner/` (needs `@quell` scope setup on Craig's npm account first)
- GitHub Action `.github/workflows/release.yml` to build + publish `.vsix` on tag push
- Consider bumping to v2.5.0 for the round 3 user-facing changes (clearVault + redactTestKeys)

### Round 5 - launch
- README screenshots (3 images, biggest adoption quick-win)
- `.Jules/` vs `.jules/` casing cleanup (cosmetic, can do in Claude Code directly)
- Product Hunt / Hacker News post
- Tweet / LinkedIn
