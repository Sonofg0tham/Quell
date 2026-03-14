# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run compile          # Compile TypeScript → ./out/
npm run watch            # Watch mode compilation
npm test                 # Compile (tsconfig.test.json) + run out/test/SecretScanner.test.js
npm run vscode:prepublish  # Pre-publish compile (same as compile)
```

Tests run standalone via Node.js — no VSCode host required. Press **F5** in VSCode to launch an Extension Host debug session (defined in `.vscode/launch.json`).

## Architecture

**Quell** is a VSCode extension that intercepts AI chat prompts, detects secrets, replaces them with `{{SECRET_xxxx}}` placeholders, and stores the real values in the OS Keychain via VSCode's `context.secrets` API.

### Subsystem layout

All subsystems are static utility classes initialized once in `src/extension.ts:activate()`:

| File | Role |
|------|------|
| `src/extension.ts` | Entry point — registers all commands, the `@quell` chat participant, and wires subsystems together |
| `src/SecretScanner.ts` | Core detection engine — fully standalone, no VSCode dependency |
| `src/SidebarProvider.ts` | Webview dashboard — renders HTML/CSS/JS inline (no bundler), communicates via `postMessage` |
| `src/DiagnosticProvider.ts` | Real-time inline diagnostics (yellow squiggles + Quick Fix) |
| `src/DecorationProvider.ts` | Visual styling of `{{SECRET_xxxx}}` placeholders in the editor |
| `src/AiShieldManager.ts` | Writes/removes marker-delimited blocks in `.cursorignore`, `.aiignore`, etc. |
| `src/EnvManager.ts` | Discovers and redacts `.env` files |
| `src/StatusBar.ts` | Status bar state machine (idle → scanning → alert → safe) |
| `src/Logger.ts` | Centralized VSCode Output Channel logging |

### Secret detection (SecretScanner)

Three-layer pipeline inside `SecretScanner.redact(text, config)`:

1. **Regex patterns** — 75+ named patterns covering AWS, Google, Azure, AI providers, payment processors, auth tokens, crypto keys, database URIs, etc.
2. **Custom patterns** — user-defined regexes from `quell.customPatterns` setting
3. **Shannon entropy analysis** — tokenizes remaining text, flags high-entropy tokens (default threshold 4.5); skips UUIDs, env-var references, camelCase identifiers, minified code, and similar false-positive sources

`SecretScanner` is decoupled from VSCode settings via the `ScannerConfig` interface, which is assembled from workspace configuration and passed in per call. This is what makes standalone testing possible.

### Placeholder lifecycle

1. Detection: `SecretScanner.redact()` returns `{ redactedText, secrets: Map<placeholder, value>, detectedTypes }`
2. Storage: real values saved to `context.secrets` (OS Keychain) keyed by placeholder
3. Restore: `quell.restoreSecrets` command reads from Keychain and replaces placeholders back

### Testing patterns

Tests live in `src/test/SecretScanner.test.ts` and use Node.js `assert` directly — no test framework. Key helpers:

```typescript
assertSecretDetected(input: string, expectedType: string)
assertNoSecrets(input: string)
```

All test fixtures use officially-published fake credentials (e.g., `AKIAIOSFODNN7EXAMPLE`). Every new detection pattern needs a corresponding test.

### Zero runtime dependencies

The extension has no production npm dependencies — only `@types/vscode`, `@types/node`, and `typescript` as devDependencies. All functionality uses VSCode APIs and Node built-ins.
