#!/usr/bin/env node
/**
 * Quell — UserPromptSubmit hook
 *
 * Reads the user's prompt from stdin (Claude Code hook JSON), runs the secret
 * scanner over it, and either:
 *   - exit 0 silent  → clean prompt, passes straight through to Claude
 *   - exit 2 + stderr → secret detected, prompt is BLOCKED (not sent to Claude),
 *                       stderr is shown to the user with the redacted version so
 *                       they can resubmit safely.
 *
 * Critical safety contract: if anything goes wrong (bad stdin, scanner throws,
 * scanner module missing) we MUST fail open — exit 0 silently and let the
 * prompt through. A hook that breaks the user's workflow is worse than a hook
 * that occasionally misses a secret. The user already has the VSCode extension
 * and good habits as defence-in-depth.
 *
 * Why block instead of transparent rewrite: the Claude Code hook API does not
 * support mutating the prompt that goes to the model. The available options
 * are `additionalContext` (added alongside the original — secret still goes
 * through) or `decision: "block"` / exit 2 (prompt erased from context). We
 * pick the second so the secret never reaches Claude. v0.2 will add a vault
 * + restore command so the placeholder version round-trips without losing
 * the real values.
 */

'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const FAIL_OPEN_EXIT = 0;
const BLOCK_EXIT = 2;

function failOpen(reason) {
    if (reason) {
        process.stderr.write(`[Quell] hook fail-open: ${reason}\n`);
    }
    process.exit(FAIL_OPEN_EXIT);
}

/**
 * Fail-open keeps the agent working, but it has a nasty edge: if the bundled
 * scanner is missing or broken, every prompt sails through unscanned and the
 * only trace is a stderr line Claude Code discards on exit 0. The user goes on
 * believing they are protected. That is the worst possible failure mode for a
 * security tool.
 *
 * So an install-integrity failure — as opposed to a transient one — surfaces
 * once per session as visible context. Once, not every prompt: a warning that
 * fires on every turn is a warning people learn to ignore.
 */
function warnBrokenInstallOnce(sessionId, reason) {
    try {
        // Session ids are not secret, but they are not ours to scatter across a
        // world-readable directory either, so the marker is named by digest.
        const key = crypto
            .createHash('sha256')
            .update(String(sessionId || 'nosession'))
            .digest('hex')
            .slice(0, 32);
        const marker = path.join(os.tmpdir(), `quell-install-warned-${key}`);

        // Exclusive create: one atomic syscall that both tests for existence and
        // claims the marker. An existsSync-then-write pair is a race, and in a
        // shared temp directory it is also a symlink-following hazard.
        let fd;
        try {
            fd = fs.openSync(marker, 'wx', 0o600);
        } catch {
            return; // Already warned this session, or we cannot claim it safely.
        }
        try {
            fs.writeSync(fd, String(Date.now()));
        } finally {
            fs.closeSync(fd);
        }

        process.stdout.write(
            '⚠️ Quell is installed but its scanner could not be loaded, so prompts are ' +
            'NOT being checked for secrets. Reason: ' + reason + '. ' +
            'Run `npm run bundle-scanner` in packages/claude-plugin to repair the install. ' +
            'Please tell the user this, once.\n'
        );
    } catch {
        // Never let the warning path itself break the hook.
    }
}

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { raw += chunk; });
process.stdin.on('error', (err) => failOpen(`stdin error: ${err.message}`));

process.stdin.on('end', () => {
    let prompt;
    let sessionId;
    try {
        const input = JSON.parse(raw || '{}');
        prompt = typeof input.prompt === 'string' ? input.prompt : '';
        sessionId = input.session_id;
    } catch (err) {
        return failOpen(`bad stdin JSON: ${err.message}`);
    }

    if (!prompt) {
        return failOpen('empty prompt');
    }

    let SecretScanner, DEFAULT_CONFIG;
    try {
        // Bundled scanner — sibling to hooks/ inside the plugin root.
        const mod = require(path.join(__dirname, '..', 'scanner', 'index.js'));
        SecretScanner = mod.SecretScanner;
        DEFAULT_CONFIG = mod.DEFAULT_CONFIG;
    } catch (err) {
        // A missing scanner is a broken install, not a transient blip — say so
        // rather than silently passing every prompt through unchecked.
        warnBrokenInstallOnce(sessionId, `scanner load failed: ${err.message}`);
        return failOpen(`scanner load failed: ${err.message}`);
    }

    let result;
    try {
        result = SecretScanner.redact(prompt, DEFAULT_CONFIG);
    } catch (err) {
        return failOpen(`scanner threw: ${err.message}`);
    }

    if (!result || !result.secrets || result.secrets.size === 0) {
        // Clean prompt — silent passthrough.
        process.exit(FAIL_OPEN_EXIT);
    }

    // Secrets found — block and tell the user what to do.
    const count = result.secrets.size;
    const types = Array.from(result.detectedTypes || []).join(', ') || 'unknown';
    const message = [
        '',
        '🛡️  Quell blocked your prompt — ' + count + ' secret(s) detected (' + types + ').',
        'Your original prompt was NOT sent to Claude.',
        '',
        'Copy this redacted version and resubmit if you want to proceed:',
        '',
        '─────────────────────────────────────────────────────────────',
        result.redactedText,
        '─────────────────────────────────────────────────────────────',
        '',
        'A future Quell release will add a vault + /quell-restore command so the',
        'placeholders round-trip back to real values automatically.',
        '',
    ].join('\n');

    process.stderr.write(message);
    process.exit(BLOCK_EXIT);
});

// Last-resort safety net: if stdin never closes for some reason, don't hang
// the user's session forever. The hook config's timeout (5s) will kill us
// anyway, but be explicit about what happens at the boundary.
setTimeout(() => failOpen('stdin never closed within 4s'), 4000).unref();
