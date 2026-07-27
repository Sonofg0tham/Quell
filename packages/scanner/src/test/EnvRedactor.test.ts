/**
 * Quell — EnvRedactor Unit Tests
 *
 * Run with: npm test
 *
 * These are security regression tests, not feature tests. Every case below
 * corresponds to a way the original line-by-line parser leaked real key
 * material into a chat transcript via the `@quell /context` command.
 *
 * Uses Node's built-in assert module — zero external dependencies.
 */

import * as assert from 'assert';
import { EnvRedactor, ENV_MASK } from '../EnvRedactor';

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

/** The core invariant: this fragment must not survive redaction anywhere in the output. */
function assertNotLeaked(input: string, fragment: string): void {
    const out = EnvRedactor.redact(input);
    assert.ok(
        !out.includes(fragment),
        `Secret material leaked into redacted output.\n  Leaked: ${JSON.stringify(fragment.slice(0, 60))}\n  Output:\n${out}`
    );
}

function assertContains(input: string, expected: string): void {
    const out = EnvRedactor.redact(input);
    assert.ok(out.includes(expected), `Expected output to contain ${JSON.stringify(expected)} but got:\n${out}`);
}

console.log('\n🔐  Quell EnvRedactor Tests\n');

// ── Basic masking ────────────────────
console.log('📄 Basic masking:');

test('masks a simple value but keeps the key name', () => {
    assertContains('DATABASE_URL=postgres://user:pass@host/db', `DATABASE_URL=${ENV_MASK}`);
    assertNotLeaked('DATABASE_URL=postgres://user:pass@host/db', 'pass@host');
});

test('preserves prose comments verbatim', () => {
    assertContains('# this is a comment\nFOO=bar', '# this is a comment');
});

test('masks a commented-out assignment but keeps the key name', () => {
    const input = '# OLD_API_KEY=sk_live_51H8xQ2abcdefghijklmnop\nNEW_API_KEY=x';
    assertNotLeaked(input, 'sk_live_51H8xQ2abcdefghijklmnop');
    assertContains(input, `# OLD_API_KEY=${ENV_MASK}`);
});

test('masks a commented-out assignment with the export prefix', () => {
    assertNotLeaked('#export DB_PASS=hunter2supersecret\n', 'hunter2supersecret');
});

test('does not mangle a comment that merely contains prose', () => {
    assertContains('# set FOO to whatever you like\nFOO=1', '# set FOO to whatever you like');
});

test('preserves blank lines', () => {
    const out = EnvRedactor.redact('A=1\n\nB=2');
    assert.ok(out.includes('\n\n'), 'expected the blank line to survive');
});

test('handles the export prefix', () => {
    assertContains('export SECRET_TOKEN=ghp_ABCDEFabcdef1234567890abcdef123456', `SECRET_TOKEN=${ENV_MASK}`);
    assertNotLeaked('export SECRET_TOKEN=ghp_ABCDEFabcdef1234567890abcdef123456', 'ghp_ABCDEF');
});

test('masks a value containing an equals sign', () => {
    assertNotLeaked('B64=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=', 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo');
});

// ── Multi-line values (the original leak) ──
console.log('\n🔑 Multi-line values:');

const PEM_BODY = 'MIIEpAIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy';
const PEM_BODY2 = 'vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9';

const DOUBLE_QUOTED_PEM = [
    'DB_HOST=localhost',
    'PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----',
    PEM_BODY,
    PEM_BODY2,
    '-----END RSA PRIVATE KEY-----"',
    'API_URL=https://api.example.com',
].join('\n');

test('does not leak a double-quoted multi-line PEM body', () => {
    assertNotLeaked(DOUBLE_QUOTED_PEM, PEM_BODY);
    assertNotLeaked(DOUBLE_QUOTED_PEM, PEM_BODY2);
});

test('resumes parsing after a multi-line value closes', () => {
    assertContains(DOUBLE_QUOTED_PEM, `API_URL=${ENV_MASK}`);
    assertContains(DOUBLE_QUOTED_PEM, `DB_HOST=${ENV_MASK}`);
});

test('does not leak a single-quoted multi-line service account JSON', () => {
    const input = "GOOGLE_CREDS='{\n  \"type\": \"service_account\",\n  \"private_key_id\": \"deadbeefcafe1234567890\"\n}'\nNEXT=1";
    assertNotLeaked(input, 'deadbeefcafe1234567890');
    assertNotLeaked(input, 'service_account');
    assertContains(input, `NEXT=${ENV_MASK}`);
});

test('does not leak a backtick-quoted multi-line value', () => {
    const input = 'CERT=`line one\nSUPERSECRETMATERIAL\nline three`\nAFTER=1';
    assertNotLeaked(input, 'SUPERSECRETMATERIAL');
    assertContains(input, `AFTER=${ENV_MASK}`);
});

test('treats an escaped quote as not closing the value', () => {
    const input = 'K="start \\" still inside\nHIDDENMATERIAL\nreal end"\nAFTER=1';
    assertNotLeaked(input, 'HIDDENMATERIAL');
});

test('single-line quoted value does not open a continuation', () => {
    const input = 'A="fully closed"\nB=plainvalue';
    assertContains(input, `B=${ENV_MASK}`);
});

// ── Base64 continuation lines ────────
console.log('\n🧬 Bare base64 continuation lines:');

const BARE_B64 = 'MIIEpAIBAAKCAQEAy8Dbv8prpJ0kKhlGeJYozo2t60EG8L0561g13R29LvMR5';

test('does not print an unquoted base64 body line as a key name', () => {
    // This line ends with `=` padding, so a naive parser reads the whole blob
    // as a variable name and prints it in clear.
    assertNotLeaked(`CERT=abc\n${BARE_B64}=\n`, BARE_B64);
});

test('withholds the base64 line rather than echoing it', () => {
    assertContains(`CERT=abc\n${BARE_B64}=\n`, 'unparsed line withheld');
});

test('does not leak a double-padded base64 line', () => {
    const blob = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w';
    assertNotLeaked(`X=1\n${blob}==\n`, blob);
});

// ── Unparseable lines ────────────────
console.log('\n🚫 Fail-closed behaviour:');

test('never echoes a line with no equals sign', () => {
    assertNotLeaked('this line is garbage AKIAIOSFODNN7EXAMPLE\n', 'AKIAIOSFODNN7EXAMPLE');
    assertContains('this line is garbage AKIAIOSFODNN7EXAMPLE\n', 'unparsed line withheld');
});

test('never echoes a line starting with a non-identifier character', () => {
    assertNotLeaked('9INVALID=secretvalue123\n', 'secretvalue123');
});

test('handles CRLF line endings', () => {
    const input = 'A=1\r\nB=2\r\n';
    assertContains(input, `A=${ENV_MASK}`);
    assertContains(input, `B=${ENV_MASK}`);
});

test('handles empty input', () => {
    assert.strictEqual(typeof EnvRedactor.redact(''), 'string');
});

// ── looksLikeEnvKey ──────────────────
console.log('\n🏷️  Key-name heuristic:');

test('accepts conventional SCREAMING_SNAKE_CASE names', () => {
    assert.ok(EnvRedactor.looksLikeEnvKey('VITE_PUBLIC_SUPABASE_ANON_KEY'));
    assert.ok(EnvRedactor.looksLikeEnvKey('DATABASE_URL'));
    assert.ok(EnvRedactor.looksLikeEnvKey('GOOGLE_APPLICATION_CREDENTIALS'));
});

test('accepts short camelCase names', () => {
    assert.ok(EnvRedactor.looksLikeEnvKey('apiKey'));
    assert.ok(EnvRedactor.looksLikeEnvKey('myLongCamelCaseVariableName'));
});

test('rejects a long mixed-case alphanumeric blob', () => {
    assert.ok(!EnvRedactor.looksLikeEnvKey(BARE_B64), 'base64 key material must not pass as a key name');
});

test('rejects an absurdly long name', () => {
    assert.ok(!EnvRedactor.looksLikeEnvKey('A'.repeat(65)));
});

// ═══════════════════════════════════════
//  Summary
// ═══════════════════════════════════════

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

if (failed > 0) {
    console.log('Failures:');
    failures.forEach((f) => console.log(`  • ${f}`));
    console.log('');
} else {
    console.log('🎉 All tests passed!\n');
}

process.exit(failed > 0 ? 1 : 0);
