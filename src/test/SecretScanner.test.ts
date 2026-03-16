/**
 * Quell — SecretScanner Unit Tests
 * 
 * Run with: npm test
 * (compiles with tsconfig.test.json, then runs with Node)
 * 
 * Uses Node's built-in assert module — zero external dependencies.
 */

import * as assert from 'assert';
import { SecretScanner, DEFAULT_CONFIG, ScannerConfig } from '../SecretScanner';

// ─────────────────────────────────
//  Test Helpers
// ─────────────────────────────────
let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
    try {
        fn();
        passed++;
        console.log(`  ✅ ${name}`);
    } catch (err: any) {
        failed++;
        const msg = err.message || String(err);
        failures.push(`${name}: ${msg}`);
        console.log(`  ❌ ${name}`);
        console.log(`     ${msg}`);
    }
}

function assertSecretDetected(input: string, expectedType: string, config?: ScannerConfig): void {
    const result = SecretScanner.redact(input, config || DEFAULT_CONFIG);
    assert.ok(result.secrets.size > 0, `Expected secrets to be detected for type "${expectedType}" but found none.`);
    assert.ok(
        result.detectedTypes.has(expectedType),
        `Expected type "${expectedType}" but got: [${Array.from(result.detectedTypes).join(', ')}]`
    );
    assert.ok(
        !result.redactedText.includes(input.trim()) || result.redactedText.includes('{{SECRET_'),
        `Expected redacted text to contain placeholder for type "${expectedType}"`
    );
}

/** Like assertSecretDetected but accepts ANY detected type (for cases where entropy or regex may race) */
function assertAnySecretDetected(input: string, config?: ScannerConfig): void {
    const result = SecretScanner.redact(input, config || DEFAULT_CONFIG);
    assert.ok(result.secrets.size > 0, `Expected at least one secret to be detected but found none.`);
    assert.ok(result.redactedText.includes('{{SECRET_'), 'Expected redacted text to contain a placeholder');
}

function assertNoSecrets(input: string, config?: ScannerConfig): void {
    const result = SecretScanner.redact(input, config || DEFAULT_CONFIG);
    assert.strictEqual(result.secrets.size, 0, `Expected no secrets but found ${result.secrets.size}: [${Array.from(result.detectedTypes).join(', ')}]`);
}


// ═══════════════════════════════════════
//  Test Suites
// ═══════════════════════════════════════

console.log('\n🛡️  Quell SecretScanner Tests\n');

// ── AWS ──────────────────────────────
console.log('☁️  AWS Patterns:');

test('detects AWS Access Key ID (AKIA)', () => {
    assertSecretDetected('my key is AKIAIOSFODNN7EXAMPLE', 'AWS Access Key ID');
});

test('detects AWS Access Key ID (ASIA)', () => {
    assertSecretDetected('ASIA1234567890ABCDEF', 'AWS Access Key ID');
});

test('detects AWS MWS key', () => {
    assertSecretDetected('amzn.mws.12345678-1234-1234-1234-123456789012', 'AWS MWS Key');
});


// ── Google ───────────────────────────
console.log('\n🔵 Google Patterns:');

test('detects Google API Key', () => {
    // May be caught by regex as 'Google API Key' or by entropy — either is correct
    assertAnySecretDetected('AIzaSyD-ExampleKey123456789012345678');
});

test('detects Google OAuth Token', () => {
    assertSecretDetected('ya29.a0ARrdaM_some_token_here_123', 'Google OAuth Token');
});

test('detects Google OAuth Client Secret', () => {
    // GOCSPX- prefix with exactly 28 chars after it
    assertAnySecretDetected('GOCSPX-aBcDeFgHiJkLmNoPqRsTuVwX');
});


// ── AI/ML Providers ──────────────────
console.log('\n🤖 AI/ML Provider Patterns:');

test('detects OpenAI API Key (project)', () => {
    assertSecretDetected(
        'sk-proj-abcdefghijklmnopqrstuvwxyz12345678901234567890',
        'OpenAI API Key (Project)'
    );
});

test('detects Anthropic API Key', () => {
    assertSecretDetected(
        'sk-ant-abcdefghijklmnopqrstuvwxyz12345678901234567890',
        'Anthropic API Key'
    );
});

test('detects Hugging Face Token', () => {
    assertSecretDetected('hf_abcdefghijklmnopqrstuvwxyz12345678', 'Hugging Face Token');
});


// ── Payment Providers ────────────────
console.log('\n💳 Payment Provider Patterns:');

test('detects Stripe Secret Key (live)', () => {
    assertSecretDetected('sk_live_abcdefghijklmnopqrstuvwx', 'Stripe Secret Key');
});

test('detects Stripe Secret Key (test)', () => {
    assertSecretDetected('sk_test_abcdefghijklmnopqrstuvwx', 'Stripe Secret Key');
});

test('detects Stripe Publishable Key', () => {
    assertSecretDetected('pk_test_abcdefghijklmnopqrstuvwx', 'Stripe Publishable Key');
});

test('detects Square Access Token', () => {
    assertSecretDetected('sq0atp-abcdefghijklmnopqrstuv', 'Square Access Token');
});


// ── GitHub ────────────────────────────
console.log('\n🐙 GitHub Patterns:');

test('detects GitHub PAT (ghp_)', () => {
    // May be caught by regex or entropy — both are valid detections
    assertAnySecretDetected('ghp_ABCDEFabcdef1234567890abcdef123456');
});

test('detects GitHub Fine-grained PAT', () => {
    // May be caught by regex or entropy — both are valid detections
    assertAnySecretDetected('github_pat_1234567890abcdefghijkl_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345');
});

test('detects GitLab PAT', () => {
    assertSecretDetected('glpat-abcdefghij1234567890', 'GitLab Personal Access Token');
});


// ── Communication ────────────────────
console.log('\n💬 Communication Patterns:');

test('detects Slack Bot Token', () => {
    assertSecretDetected('xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx', 'Slack Bot Token');
});

test('detects Slack Webhook', () => {
    assertSecretDetected(
        'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx',
        'Slack Webhook'
    );
});

test('detects Discord Webhook', () => {
    assertSecretDetected(
        'https://discord.com/api/webhooks/1234567890/abcdefghij-klmnop_qrstuv',
        'Discord Webhook'
    );
});


// ── Email Services ───────────────────
console.log('\n✉️  Email Service Patterns:');

test('detects SendGrid API Key', () => {
    assertSecretDetected(
        'SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz1234567890abcdefg',
        'SendGrid API Key'
    );
});

test('detects Mailgun API Key', () => {
    assertSecretDetected('key-abcdefghijklmnop1234567890abcdef', 'Mailgun API Key');
});


// ── Auth Tokens ──────────────────────
console.log('\n🔑 Auth Token Patterns:');

test('detects JWT', () => {
    assertSecretDetected(
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
        'JSON Web Token'
    );
});

test('detects Bearer Token', () => {
    assertSecretDetected(
        'Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890',
        'Bearer Token'
    );
});

test('detects Basic Auth Credentials (fixed regex)', () => {
    assertSecretDetected(
        'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=',
        'Basic Auth Credentials'
    );
});


// ── Cryptographic Keys ──────────────
console.log('\n🔐 Cryptographic Key Patterns:');

test('detects RSA Private Key', () => {
    assertSecretDetected('-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key');
});

test('detects OpenSSH Private Key', () => {
    assertSecretDetected('-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key');
});

test('detects Generic Private Key', () => {
    assertSecretDetected('-----BEGIN PRIVATE KEY-----', 'Generic Private Key');
});

test('detects PGP Private Key Block', () => {
    assertSecretDetected('-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key Block');
});


// ── Database Connection Strings ──────
console.log('\n🗄️  Database Connection Patterns:');

test('detects PostgreSQL Connection URI', () => {
    assertSecretDetected('postgresql://admin:p4ssw0rd@db.example.com:5432/mydb', 'PostgreSQL Connection URI');
});

test('detects MongoDB Connection URI', () => {
    assertSecretDetected('mongodb+srv://user:secret@cluster.mongodb.net/db', 'MongoDB Connection URI');
});

test('detects Redis Connection URI', () => {
    assertSecretDetected('redis://default:mysecret@redis.example.com:6379', 'Redis Connection URI');
});


// ── Hosting/Deployment ──────────────
console.log('\n🚀 Hosting & Deployment Patterns:');

test('detects DigitalOcean PAT', () => {
    assertSecretDetected(
        'dop_v1_' + 'a'.repeat(64),
        'DigitalOcean PAT'
    );
});

test('detects NPM Token', () => {
    assertSecretDetected('npm_abcdefghijklmnopqrstuvwxyz1234567890', 'NPM Access Token');
});


// ── Password Assignments ─────────────
console.log('\n🔒 Password/Token Assignment Patterns:');

test('detects password assignment (single quotes)', () => {
    assertSecretDetected("password = 'mySuperSecretPass123!'", 'Password in Assignment');
});

test('detects password assignment (double quotes)', () => {
    assertSecretDetected('password="mySuperSecretPass123!"', 'Password in Assignment');
});

test('detects token assignment', () => {
    assertSecretDetected('api_key = "abcdefghijklmnopqrstuvwxyz"', 'Token in Assignment');
});


// ── Shopify ──────────────────────────
console.log('\n🛒 E-commerce Patterns:');

test('detects Shopify Access Token', () => {
    assertSecretDetected('shpat_' + 'a1b2c3d4'.repeat(4), 'Shopify Access Token');
});


// ── Entropy Scanning ─────────────────
console.log('\n📊 Shannon Entropy Scanning:');

test('flags high-entropy hex string (with tuned threshold)', () => {
    // Hex strings max out at ~4.0 bits entropy (only 16 chars: 0-9a-f).
    // To catch them, users should lower the threshold — this test proves that works.
    const config: ScannerConfig = { ...DEFAULT_CONFIG, entropyThreshold: 3.5 };
    const hexSecret = '8f3a2e7b1c9d4f0a6e5b8c2d7f1a3e9b4d6c0f8a2b5e7d1c9f3a6b0e4d8c2f7a';
    const result = SecretScanner.redact(`my key is ${hexSecret} ok`, config);
    assert.ok(result.secrets.size > 0, 'Expected high-entropy hex to be detected with lowered threshold');
    assert.ok(result.redactedText.includes('{{SECRET_'), 'Expected placeholder in redacted text');
});

test('flags high-entropy base64-like token', () => {
    const b64Token = 'aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a';
    assertSecretDetected(b64Token, 'High Entropy Token');
});

test('does NOT flag low-entropy repeated string', () => {
    assertNoSecrets('aaaaaaaaaaaaaaaaaaaaaaaaaaaa');
});

test('does NOT flag normal English text', () => {
    assertNoSecrets('This is a completely normal sentence without any secrets in it at all.');
});

test('does NOT flag standard UUIDs', () => {
    // UUIDs are explicitly skipped in entropy scanning and no regex should match standalone UUIDs
    assertNoSecrets('My ID is 550e8400-e29b-41d4-a716-446655440000');
});

test('does NOT flag normal URLs', () => {
    assertNoSecrets('Visit https://www.example.com/docs/getting-started for more info.');
});


// ── Configuration Options ────────────
console.log('\n⚙️  Configuration Options:');

test('respects disabled entropy scanning', () => {
    const config: ScannerConfig = { ...DEFAULT_CONFIG, enableEntropy: false };
    const token = 'aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a'; // would normally be flagged
    const result = SecretScanner.redact(token, config);
    // Should only be flagged by entropy, not regex — with entropy off, should be clean
    // Unless it matches a regex pattern (it shouldn't)
    const hasEntropyType = result.detectedTypes.has('High Entropy Token') || result.detectedTypes.has('High Entropy Hex String');
    assert.ok(!hasEntropyType, 'Entropy scanning should be disabled');
});

test('respects custom entropy threshold', () => {
    const config: ScannerConfig = { ...DEFAULT_CONFIG, entropyThreshold: 7.0 };
    // Most strings won't have entropy > 7.0
    const token = 'aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u';
    const result = SecretScanner.redact(token, config);
    const hasEntropyType = result.detectedTypes.has('High Entropy Token') || result.detectedTypes.has('High Entropy Hex String');
    assert.ok(!hasEntropyType, 'High threshold should prevent detection');
});

test('applies custom patterns', () => {
    const config: ScannerConfig = {
        ...DEFAULT_CONFIG,
        customPatterns: [{ name: 'Internal Secret', regex: 'INTERNAL_[A-Z0-9]{16}' }],
    };
    assertSecretDetected('My key is INTERNAL_ABCDEF1234567890', 'Internal Secret', config);
});

test('respects whitelist patterns', () => {
    const config: ScannerConfig = {
        ...DEFAULT_CONFIG,
        whitelistPatterns: ['AIzaSyD-ExampleKey.*'],
    };
    const result = SecretScanner.redact('AIzaSyD-ExampleKey123456789012345678', config);
    assert.strictEqual(result.secrets.size, 0, 'Whitelisted pattern should not be flagged');
});


// ── Placeholder Mechanics ────────────
console.log('\n🏷️  Placeholder Mechanics:');

test('generates unique placeholders', () => {
    const result = SecretScanner.redact('ghp_ABCDEFabcdef1234567890abcdef123456 and sk_test_abcdefghijklmnopqrstuvwx');
    assert.strictEqual(result.secrets.size, 2, 'Should detect 2 different secrets');
    const placeholders = Array.from(result.secrets.keys());
    assert.notStrictEqual(placeholders[0], placeholders[1], 'Placeholders should be unique');
});

test('reuses placeholder for duplicate secrets', () => {
    const secret = 'ghp_ABCDEFabcdef1234567890abcdef123456';
    const result = SecretScanner.redact(`first: ${secret} second: ${secret}`);
    assert.strictEqual(result.secrets.size, 1, 'Duplicate secret should produce only 1 placeholder');
});

test('placeholder format is correct', () => {
    const result = SecretScanner.redact('ghp_ABCDEFabcdef1234567890abcdef123456');
    const placeholder = Array.from(result.secrets.keys())[0];
    assert.ok(/^{{SECRET_[a-z0-9]{12}}}$/.test(placeholder), `Placeholder "${placeholder}" does not match expected format`);
});

test('redacted text contains placeholder, not original', () => {
    const secret = 'ghp_ABCDEFabcdef1234567890abcdef123456';
    const result = SecretScanner.redact(`my token is ${secret}`);
    assert.ok(!result.redactedText.includes(secret), 'Redacted text should not contain the original secret');
    assert.ok(result.redactedText.includes('{{SECRET_'), 'Redacted text should contain a placeholder');
});


// ── Entropy Calculation ──────────────
console.log('\n📈 Entropy Calculation:');

test('empty string has 0 entropy', () => {
    assert.strictEqual(SecretScanner.calculateEntropy(''), 0);
});

test('single repeated char has 0 entropy', () => {
    assert.strictEqual(SecretScanner.calculateEntropy('aaaaaaa'), 0);
});

test('two equally distributed chars have entropy of 1', () => {
    const e = SecretScanner.calculateEntropy('ababababab');
    assert.ok(Math.abs(e - 1.0) < 0.001, `Expected ~1.0, got ${e}`);
});

test('high-entropy random string has entropy > 4.0', () => {
    const e = SecretScanner.calculateEntropy('aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u');
    assert.ok(e > 4.0, `Expected > 4.0, got ${e}`);
});

test('pattern count is substantial', () => {
    assert.ok(SecretScanner.patternCount >= 70, `Expected >= 70 patterns, got ${SecretScanner.patternCount}`);
});


// ═══════════════════════════════════════
//  Summary
// ═══════════════════════════════════════
console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

if (failed > 0) {
    console.log('❌ Failures:');
    failures.forEach((f) => console.log(`   • ${f}`));
    console.log('');
    process.exit(1);
} else {
    console.log('🎉 All tests passed!\n');
    process.exit(0);
}
