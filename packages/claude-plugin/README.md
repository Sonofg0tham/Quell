# Quell — Claude Code plugin

The point-of-use defence layer for Claude Code. A `UserPromptSubmit` hook scans every
prompt you submit for API keys, passwords, and tokens. If it finds any, the prompt is
**blocked** (never sent to Claude) and you get a redacted version you can copy and
resubmit safely.

This is the third Quell surface. The other two:
- [VSCode extension](https://marketplace.visualstudio.com/items?itemName=Sonofg0tham.quell)
- [`@sonofg0tham/quell-scanner`](https://www.npmjs.com/package/@sonofg0tham/quell-scanner) on npm

## What it does

When you press Enter on a prompt in Claude Code:

1. Hook script reads the prompt from stdin.
2. Quell's scanner runs over it (80+ regex patterns plus Shannon entropy analysis, the
   same engine that powers the VSCode extension).
3. **Clean prompt** → exits silently, prompt goes to Claude unchanged.
4. **Secret detected** → exits with code 2, prompt is erased from context, and stderr
   shows you a redacted version with `{{SECRET_xxxx}}` placeholders.

## What it doesn't do (yet)

- **No vault.** v0.1.0 drops the original secret values on the floor. If you resubmit
  the redacted prompt, the placeholders stay placeholders. v0.2 will add persistent
  storage and a `/quell-restore` slash command that swaps the real values back when
  Claude's response references them.
- **No transparent rewrite.** The Claude Code hook API does not allow modifying the
  prompt that goes to the model — only adding context alongside it (which would still
  leak the secret) or blocking outright. Quell picks the safer option.
- **One hook only.** v0.1.0 covers `UserPromptSubmit`. A future round will add
  `PreToolUse` to catch secrets that appear in tool inputs (e.g. file edits, shell
  commands).

## Install (local development)

From a checkout of this repo:

```bash
claude --plugin-dir ./packages/claude-plugin
```

To make it stick across sessions, install via Claude Code's plugin manager (once we
publish to a marketplace) — that's coming after the v0.1.0 dogfood period.

## Verify it's working

Inside a Claude Code session with the plugin loaded, paste a fake secret:

```
ghp_ABCDEFabcdef1234567890abcdef12345678
```

Expected: prompt is blocked, you see a stderr message with `🛡️  Quell blocked your
prompt — 1 secret(s) detected (GitHub Personal Access Token)`, and the original is
not sent. The fixture above is exactly 36 chars after `ghp_` so it hits the explicit
GitHub PAT regex; shorter fixtures still get caught, just by the entropy pass instead.

A clean prompt like *"how do I write a Python loop"* should pass through with no
visible Quell output.

## Fail-open guarantee

The hook is wrapped in defensive `try`/`catch` and returns exit 0 (passthrough) on:

- malformed JSON on stdin
- scanner module failing to load
- scanner throwing on bad input
- empty prompts

Whenever the hook fails open it writes a one-line reason to stderr (e.g.
`[Quell] hook fail-open: scanner load failed: ...`) so you always know why it
stepped aside. A hook that breaks your workflow is worse than a hook that
occasionally misses a secret — the VSCode extension and good Git hygiene are your
defence-in-depth.

## Updating the bundled scanner

The compiled scanner lives at `scanner/` inside this plugin. To refresh it after
changes to `packages/scanner/src/`:

```bash
cd packages/claude-plugin
npm run bundle-scanner
```

This rebuilds the standalone scanner and copies the four `.js`/`.d.ts` artefacts
into `packages/claude-plugin/scanner/`. We bundle rather than depending on the npm
package so the plugin works with no `npm install` step from the user.

## Licence

MIT — see `LICENSE`.
