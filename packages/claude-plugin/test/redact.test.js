#!/usr/bin/env node
/**
 * Smoke test for the UserPromptSubmit hook.
 *
 * Spawns the hook script as a subprocess (the same way Claude Code does),
 * pipes JSON to its stdin, and verifies the exit code + stderr behaviour
 * for three cases:
 *   1. Clean prompt → exit 0, no stderr, no stdout
 *   2. Prompt containing a GitHub PAT → exit 2, stderr contains the redacted
 *      version with a placeholder, the original secret is NOT in stderr,
 *      and the explicit "GitHub Personal Access Token" type is named (proves
 *      the regex path fired, not the entropy fallback).
 *   3. Malformed stdin → exit 0 (fail-open contract).
 *
 * No test framework — Node's built-in child_process and a tiny test() helper
 * matches the standalone-no-deps style of the scanner's test suite.
 */

'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const HOOK = path.join(__dirname, '..', 'hooks', 'redact.js');

function runHook(promptText) {
    return spawnSync('node', [HOOK], {
        input: JSON.stringify({ prompt: promptText }),
        encoding: 'utf8',
    });
}

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('✅ ' + name);
    } catch (err) {
        failed++;
        console.log('❌ ' + name + ': ' + err.message);
    }
}

console.log('🪝  Quell hook smoke tests:\n');

test('passes through a clean prompt (exit 0, empty stdout, empty stderr)', () => {
    const result = runHook('How do I write a Python loop that prints 1 to 10?');
    if (result.status !== 0) {
        throw new Error('expected exit 0, got ' + result.status + '; stderr: ' + result.stderr);
    }
    if (result.stdout && result.stdout.length > 0) {
        throw new Error('expected empty stdout, got: ' + JSON.stringify(result.stdout));
    }
    if (result.stderr && result.stderr.length > 0) {
        throw new Error('expected empty stderr, got: ' + result.stderr);
    }
});

test('blocks a GitHub PAT via the explicit regex (exit 2, redacted stderr, type named)', () => {
    // 36 chars after the ghp_ prefix to match /ghp_[a-zA-Z0-9]{36}/ exactly.
    // Shorter and the entropy pass would catch it under "High Entropy Token"
    // instead — fine for safety, but this test pins the regex path.
    const fixture = 'My GitHub token is ghp_ABCDEFabcdef1234567890abcdef12345678 please use it';
    const original = 'ghp_ABCDEFabcdef1234567890abcdef12345678';

    const result = runHook(fixture);

    if (result.status !== 2) {
        throw new Error('expected exit 2, got ' + result.status + '; stderr: ' + result.stderr);
    }
    if (!result.stderr || result.stderr.length === 0) {
        throw new Error('expected non-empty stderr');
    }
    if (result.stderr.includes(original)) {
        throw new Error('CRITICAL: stderr leaked the original secret value');
    }
    if (!result.stderr.includes('{{SECRET_')) {
        throw new Error('expected stderr to contain a {{SECRET_xxxx}} placeholder');
    }
    if (!result.stderr.includes('Quell blocked')) {
        throw new Error('expected stderr to contain the block notice');
    }
    if (!result.stderr.includes('GitHub Personal Access Token')) {
        throw new Error('expected the explicit "GitHub Personal Access Token" type to be named (regex path), saw entropy fallback or other');
    }
});

test('fails open with exit 0 on malformed stdin JSON', () => {
    const result = spawnSync('node', [HOOK], {
        input: 'this is not json',
        encoding: 'utf8',
    });
    if (result.status !== 0) {
        throw new Error('expected fail-open exit 0, got ' + result.status + '; stderr: ' + result.stderr);
    }
});

test('fails open with exit 0 when prompt field is absent from JSON', () => {
    const result = spawnSync('node', [HOOK], {
        input: JSON.stringify({}),
        encoding: 'utf8',
    });
    if (result.status !== 0) {
        throw new Error('expected fail-open exit 0, got ' + result.status + '; stderr: ' + result.stderr);
    }
    if (!result.stderr || !result.stderr.includes('fail-open')) {
        throw new Error('expected fail-open reason in stderr, got: ' + result.stderr);
    }
});

test('fails open with exit 0 when prompt is an empty string', () => {
    const result = spawnSync('node', [HOOK], {
        input: JSON.stringify({ prompt: '' }),
        encoding: 'utf8',
    });
    if (result.status !== 0) {
        throw new Error('expected fail-open exit 0, got ' + result.status + '; stderr: ' + result.stderr);
    }
    if (!result.stderr || !result.stderr.includes('fail-open')) {
        throw new Error('expected fail-open reason in stderr, got: ' + result.stderr);
    }
});

test('blocks a high-entropy token caught only by entropy analysis (exit 2, type "High Entropy Token")', () => {
    // This string has no known-secret prefix — it is not matched by any regex
    // pattern — but has high Shannon entropy (>4.5) from its mixed-case+digit
    // composition, so it should be caught by the entropy pass only.
    const entropyToken = 'xK9mZ2pQnL5vRjY8wC4dFbG6eT7hN3sA';
    const fixture = 'The internal config value is ' + entropyToken + ' and must not be shared.';

    const result = runHook(fixture);

    if (result.status !== 2) {
        throw new Error('expected exit 2, got ' + result.status + '; stderr: ' + result.stderr);
    }
    if (!result.stderr || !result.stderr.includes('{{SECRET_')) {
        throw new Error('expected a {{SECRET_xxxx}} placeholder in stderr');
    }
    if (result.stderr.includes(entropyToken)) {
        throw new Error('CRITICAL: stderr leaked the high-entropy token');
    }
    if (!result.stderr.includes('High Entropy Token')) {
        throw new Error('expected type "High Entropy Token" in stderr, got: ' + result.stderr);
    }
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
process.exit(failed > 0 ? 1 : 0);
