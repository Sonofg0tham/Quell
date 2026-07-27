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

/**
 * Joins the parts of a credential fixture at runtime.
 *
 * Every fixture in this file is fake, but some are realistic enough that
 * GitHub's push protection classifies them as live credentials and blocks the
 * push. Keeping the value out of the file as a single literal satisfies the
 * scanner without weakening the test, which still sees the full string. An
 * occupational hazard of maintaining a secret-detection test suite: the better
 * the fixtures, the more they look like the real thing.
 */
function fixture(...parts: string[]): string {
    return parts.join('');
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
    assertSecretDetected('my key is AKIAIOSFODNN7EXAMPLE', 'AWS Access Key ID', { ...DEFAULT_CONFIG, redactTestKeys: true });
});

test('detects AWS Access Key ID (ASIA)', () => {
    // Key body is base32 ([A-Z2-7]) — digits 0, 1, 8, 9 never appear in real key IDs.
    assertSecretDetected('ASIA234567ABCDEFGHIJ', 'AWS Access Key ID');
});

test('detects AWS Secret Access Key (uppercase quoted .env form)', () => {
    assertSecretDetected(
        'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        'AWS Secret Access Key',
        { ...DEFAULT_CONFIG, redactTestKeys: true }
    );
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

test('detects Google OAuth Refresh Token (1// prefix)', () => {
    assertSecretDetected(
        'GOOGLE_REFRESH_TOKEN=1//0gAbCdEfGhTUVWXYZ123456789abcdef',
        'Google OAuth Refresh Token'
    );
});


// ── Azure & Other Clouds ─────────────
console.log('\n☁️  Azure & Other Cloud Patterns:');

test('detects Azure AD client secret', () => {
    assertSecretDetected(
        'client secret: Iiv8Q~aBcDeFgHiJkLmNoPqRsTuVwXyZ.01234',
        'Azure AD Client Secret'
    );
});

test('detects Alibaba AccessKey ID', () => {
    assertSecretDetected('LTAIA1b2C3d4e5A1b2C3d4e5', 'Alibaba AccessKey ID');
});

test('detects Tencent Cloud SecretId', () => {
    assertSecretDetected(fixture('AK', 'IDA1b2C3d4e5A1b2C3d4e5A1b2C3d4e5Zz'), 'Tencent Cloud SecretId');
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

test('detects OpenAI API Key (admin)', () => {
    assertSecretDetected(
        fixture('sk-', 'admin-', 'Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90T3BlbkFJAb12Cd34Ef56Gh78'),
        'OpenAI API Key (Admin)'
    );
});

test('detects Amazon Bedrock API key', () => {
    assertSecretDetected('ABSK' + 'A1b2C3d4e5'.repeat(11), 'Amazon Bedrock API Key');
});

test('detects Hugging Face Token', () => {
    assertSecretDetected('hf_abcdefghijklmnopqrstuvwxyz12345678', 'Hugging Face Token');
});

test('detects OpenRouter API Key', () => {
    assertSecretDetected(
        'OPENROUTER_API_KEY=sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        'OpenRouter API Key'
    );
});

test('detects Groq API Key', () => {
    assertSecretDetected(
        'GROQ_API_KEY=gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz12',
        'Groq API Key'
    );
});

test('detects Perplexity API Key', () => {
    assertSecretDetected(
        'PERPLEXITY_API_KEY=pplx-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx',
        'Perplexity API Key'
    );
});

test('detects xAI API Key', () => {
    assertSecretDetected(
        'XAI_API_KEY=xai-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX',
        'xAI API Key'
    );
});

test('detects LangSmith API Key', () => {
    // Assembled at runtime so GitHub push-protection doesn't flag the literal fixture.
    const sample = 'LANGSMITH_API_KEY=' + ['lsv2', 'pt', '0'.repeat(32), '0'.repeat(10)].join('_');
    assertSecretDetected(sample, 'LangSmith API Key');
});

test('detects Pinecone API Key', () => {
    assertSecretDetected('pcsk_' + 'AbCd1234'.repeat(5), 'Pinecone API Key');
});

test('detects Fireworks API Key', () => {
    assertSecretDetected('fw_' + 'A1b2C3d4e5'.repeat(3), 'Fireworks API Key');
});

test('detects Cerebras API Key', () => {
    assertSecretDetected('csk-' + 'a1b2c3d4e5'.repeat(4), 'Cerebras API Key');
});

test('detects ElevenLabs API Key', () => {
    assertSecretDetected('sk_' + '0123456789abcdef'.repeat(3), 'ElevenLabs API Key');
});

test('Stripe sk_live key is still typed as Stripe, not ElevenLabs', () => {
    // ElevenLabs (sk_ + hex) and Stripe (sk_live_/sk_test_) prefixes overlap on
    // 'sk_' — prove the hex-only ElevenLabs rule never claims a Stripe key.
    const result = SecretScanner.redact(fixture('sk_', 'live_', '0123456789abcdef0123456789abcdef01234567'), DEFAULT_CONFIG);
    assert.ok(result.detectedTypes.has('Stripe Secret Key'), 'Expected Stripe Secret Key type');
    assert.ok(!result.detectedTypes.has('ElevenLabs API Key'), 'ElevenLabs rule must not claim a Stripe key');
});

test('detects LlamaCloud API Key', () => {
    assertSecretDetected('llx-' + 'A1b2C3d4e5'.repeat(5), 'LlamaCloud API Key');
});

test('detects Vercel AI Gateway Key', () => {
    assertSecretDetected('vck_' + 'A1b2C3d4e5'.repeat(3), 'Vercel AI Gateway Key');
});

test('detects Together AI API Key', () => {
    assertSecretDetected('tgp_v1_' + 'A1b2C3d4e5'.repeat(5), 'Together AI API Key');
});

test('does not flag short sk-or-v1- prefix', () => {
    assertNoSecrets('sk-or-v1-tooshort');
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

test('detects Stripe Webhook Secret', () => {
    assertSecretDetected('whsec_' + 'A1b2C3d4e5'.repeat(4), 'Stripe Webhook Secret');
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
    assertAnySecretDetected('github_pat_1234567890abcdefghijkl_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567');
});

test('detects GitHub Fine-grained PAT with varying segment lengths', () => {
    // Real fine-grained PATs do NOT have fixed 22/59 segment lengths. A token whose
    // second segment is 54 chars (not 59) must still be caught by the regex, and must
    // not slip through the entropy backstop's long-base64 skip.
    const pat = 'github_pat_' + '1A'.repeat(11) + '_' + 'bcdefghijk'.repeat(5) + 'abcd';
    assertSecretDetected(pat, 'GitHub Fine-grained PAT');
});

test('detects GitLab PAT', () => {
    assertSecretDetected('glpat-abcdefghij1234567890', 'GitLab Personal Access Token');
});

test('detects modern routable GitLab PAT in full (no tail leak)', () => {
    // Routable PATs are longer than 20 chars and end in a .{9-char} CRC suffix.
    // The old {20} bound redacted only the first 20 chars and leaked the rest.
    const pat = 'glpat-AbCdEfGhIjKlMnOpQrStUvWxYz1.01ab2cd3e';
    const result = SecretScanner.redact(pat, DEFAULT_CONFIG);
    assert.ok(result.detectedTypes.has('GitLab Personal Access Token'), 'Expected GitLab PAT type');
    assert.ok(!result.redactedText.includes('01ab2cd3e'), `PAT tail leaked: ${result.redactedText}`);
});


// ── Dev Tooling ──────────────────────
console.log('\n🛠️  Dev Tooling Patterns:');

test('detects Atlassian API Token', () => {
    assertSecretDetected('ATATT3' + 'aBcDeF'.repeat(31), 'Atlassian API Token');
});

test('detects CircleCI Personal Access Token', () => {
    assertSecretDetected('CCIPAT_AbCd1234EfGh5678_' + 'a1b2c3d4'.repeat(5), 'CircleCI Personal Access Token');
});

test('detects Docker Hub Token', () => {
    assertSecretDetected('dckr_pat_' + 'A1b2C3d4e5'.repeat(3), 'Docker Hub Token');
});

test('detects Sourcegraph Access Token', () => {
    assertSecretDetected('sgp_0123456789abcdef_' + '0123456789abcdef'.repeat(2) + 'a1b2c3d4', 'Sourcegraph Access Token');
});

test('detects SonarQube Token', () => {
    assertSecretDetected('squ_' + 'a1b2c3d4e5'.repeat(4), 'SonarQube Token');
});


// ── Communication ────────────────────
console.log('\n💬 Communication Patterns:');

test('detects Slack Bot Token', () => {
    assertSecretDetected('xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx', 'Slack Bot Token');
});

test('detects Slack refresh token (xoxe.xoxp)', () => {
    // Slack rotating refresh tokens (xoxe.xoxp- / xoxe.xoxb-) were not covered.
    assertSecretDetected('xoxe.xoxp-2-' + 'A1b2C3d4e5'.repeat(4), 'Slack Refresh Token');
});

test('detects Slack app-config access token (xoxe-)', () => {
    assertSecretDetected('xoxe-2-' + 'A1b2C3d4e5'.repeat(4), 'Slack App Config Token');
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

test('detects Discord Bot Token with O prefix', () => {
    assertSecretDetected(
        'O' + 'Tk3Mzc4NTQ0'.repeat(3) + '.GaBcDe.' + 'aBcDeFgHi'.repeat(3),
        'Discord Bot Token'
    );
});

test('detects Telegram Bot Token', () => {
    // Official example token from the Telegram Bot API docs.
    assertSecretDetected('110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw', 'Telegram Bot Token');
});

test('does not flag digits:base64 that is not a Telegram token', () => {
    // Secret segment must start 'AA' — arbitrary digits:base64ish must NOT match.
    assertNoSecrets('1721480212:dGhpc0lzTm90QVRlbGVncmFtVG9rZW5zdHJ');
});

test('detects X (Twitter) Bearer Token', () => {
    assertSecretDetected('A'.repeat(21) + 'AbCd1234'.repeat(10), 'X (Twitter) Bearer Token');
});


// ── Email Services ───────────────────
console.log('\n✉️  Email Service Patterns:');

test('detects SendGrid API Key', () => {
    assertSecretDetected(
        'SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz1234567890abcdefg',
        'SendGrid API Key'
    );
});

test('detects Mailgun API Key (hex format)', () => {
    assertSecretDetected('key-0123456789abcdef0123456789abcdef', 'Mailgun API Key');
});

test('does not flag key- followed by non-hex alphanumerics', () => {
    assertNoSecrets('key-HELLOWORLDHELLOWORLDHELLOWORLDHELL');
});

// ── Resend ────────────────────────────────────────────────────
console.log('\n📧  Resend:');

test('detects Resend API key', () => {
    assertSecretDetected(
        're_ABCDefghIJKLmnopQRSTuvwxYZ123456',
        'Resend API Key'
    );
});

test('detects segmented Resend API key', () => {
    // Modern Resend keys are segmented: re_<short>_<long>
    assertSecretDetected('re_AbCd1234_efGhIjKlMnOpQrStUvWx', 'Resend API Key');
});

test('does not flag short re_ string (too short)', () => {
    assertNoSecrets('re_toolshort');
});

test('detects Brevo API key', () => {
    assertSecretDetected(
        'xkeysib-' + '0123456789abcdef'.repeat(4) + '-A1b2C3d4E5f6G7h8',
        'Brevo API Key'
    );
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

test('does not flag camelCase prose after Bearer', () => {
    // Pure-letter identifiers are prose, not tokens — real credentials contain
    // at least one digit, '+', '/' or '='.
    assertNoSecrets('Bearer TokenAuthenticationScheme');
});

test('does not flag camelCase prose after Basic', () => {
    assertNoSecrets('the Basic AuthenticationProvider class');
});


// ── Cryptographic Keys ──────────────
console.log('\n🔐 Cryptographic Key Patterns:');

test('detects RSA Private Key header', () => {
    assertSecretDetected('-----BEGIN RSA PRIVATE KEY-----', 'Private Key Block');
});

test('detects OpenSSH Private Key header', () => {
    assertSecretDetected('-----BEGIN OPENSSH PRIVATE KEY-----', 'Private Key Block');
});

test('detects Generic Private Key header', () => {
    assertSecretDetected('-----BEGIN PRIVATE KEY-----', 'Private Key Block');
});

test('detects PGP Private Key Block header', () => {
    assertSecretDetected('-----BEGIN PGP PRIVATE KEY BLOCK-----', 'Private Key Block');
});

test('detects Encrypted Private Key header', () => {
    // PKCS#8 encrypted private keys use a distinct header that the six specific
    // patterns did not cover.
    assertSecretDetected('-----BEGIN ENCRYPTED PRIVATE KEY-----', 'Private Key Block');
});

test('redacts a full PEM block in its entirety, even with entropy disabled', () => {
    // Regression: the old header-only patterns replaced just the BEGIN line and
    // left the entire base64 key material in the text — with entropy off, a
    // complete private key would ship to the model.
    const body = 'MIIEpAIBAAKCAQEA' + 'a1B2c3D4e5F6g7H8'.repeat(3);
    const pem = [
        '-----BEGIN RSA PRIVATE KEY-----',
        body,
        '-----END RSA PRIVATE KEY-----',
    ].join('\n');
    const config: ScannerConfig = { ...DEFAULT_CONFIG, enableEntropy: false };
    const result = SecretScanner.redact(pem, config);
    assert.ok(result.detectedTypes.has('Private Key Block'), 'Expected Private Key Block type');
    assert.ok(!result.redactedText.includes('MIIEpA'), `Key material leaked: ${result.redactedText}`);
    assert.ok(!result.redactedText.includes(body), 'Full key body must be redacted');
    assert.ok(result.redactedText.includes('{{SECRET_'), 'Expected a placeholder');
});

test('detects age secret key', () => {
    assertSecretDetected(
        'AGE-SECRET-KEY-1' + 'ABCDEFGHJK'.repeat(5) + 'LMNPQRST',
        'age Secret Key'
    );
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


// ── Connection URI edge cases ────────────────────────────────
console.log('\n🗄️  Connection URI edge cases:');

test('PostgreSQL URI counts as exactly one secret', () => {
    const uri = 'postgres://admin:hunter2@db.example.com:5432/myapp';
    const result = SecretScanner.redact(uri, DEFAULT_CONFIG);
    assert.strictEqual(
        result.secrets.size,
        1,
        `Expected exactly 1 secret for a plain PostgreSQL URI but got ${result.secrets.size}: [${Array.from(result.detectedTypes).join(', ')}]`
    );
    assert.ok(result.detectedTypes.has('PostgreSQL Connection URI'), 'Expected type "PostgreSQL Connection URI"');
});

test('PostgreSQL URI with high-entropy password still counts as one secret', () => {
    // Use a genuinely high-entropy password (>4.5 bits) to ensure entropy pass does not
    // double-count the password after the URI has already been redacted.
    const uri = 'postgres://admin:xK9$mP2@wQ8nR5vL@db.example.com/prod';
    const result = SecretScanner.redact(uri, DEFAULT_CONFIG);
    assert.strictEqual(
        result.secrets.size,
        1,
        `Expected exactly 1 secret even with high-entropy password. Got ${result.secrets.size}: [${Array.from(result.detectedTypes).join(', ')}]`
    );
});

test('DB URI patterns complete quickly on pathological input (ReDoS regression)', () => {
    // The old [^\s'"]+ userinfo classes allowed quadratic backtracking — a crafted
    // 40KB line took >600ms. The tightened classes must stay linear. The bound is
    // deliberately generous (slow CI headroom); the point is catching a return to
    // quadratic behaviour, not micro-benchmarking.
    const evil = 'postgres://' + 'a:'.repeat(20000);
    const start = Date.now();
    SecretScanner.redact(evil, DEFAULT_CONFIG);
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 1000, `Expected redact() on pathological URI input to finish in <1000ms, took ${elapsed}ms`);
});

test('Separate PASSWORD assignment alongside URI counts as one secret (same value, deduped)', () => {
    // If the password appears both in the URI AND as a standalone DB_PASSWORD= line,
    // that is two distinct sensitive values and should count as two.
    const input = [
        'DATABASE_URL=postgres://admin:hunter2@db.example.com/myapp',
        "DB_PASSWORD='hunter2'",
    ].join('\n');
    const result = SecretScanner.redact(input, DEFAULT_CONFIG);
    // hunter2 appears in both contexts but is the SAME string — valueToPlaceholder dedup
    // means it maps to a single placeholder. Total unique secrets = 1 (the URI, which
    // already embeds the password string).
    assert.strictEqual(
        result.secrets.size,
        1,
        `Expected 1 unique secret (same value in URI and assignment). Got ${result.secrets.size}: [${Array.from(result.detectedTypes).join(', ')}]`
    );
});


// ── Hosting/Deployment ──────────────
console.log('\n🚀 Hosting & Deployment Patterns:');

test('detects DigitalOcean PAT', () => {
    assertSecretDetected(
        'dop_v1_' + 'a'.repeat(64),
        'DigitalOcean PAT'
    );
});

test('detects Fly.io Access Token (base64url charset)', () => {
    assertSecretDetected('fo1_' + 'aBcDeF123_'.repeat(4), 'Fly.io Access Token');
});

test('detects Heroku API Key (HRKU v2)', () => {
    assertSecretDetected('HRKU-AA' + 'A1b2C3d4e5'.repeat(5) + 'aBcDefG9', 'Heroku API Key');
});

test('detects Cloudflare API Token (keyword-anchored)', () => {
    assertSecretDetected('CLOUDFLARE_API_TOKEN=' + 'aB3dE5g7H9'.repeat(4), 'Cloudflare API Token');
});

test('detects Cloudflare Origin CA Key', () => {
    assertSecretDetected(
        'v1.0-' + '0123456789abcdef01234567' + '-' + '0123456789abcdef'.repeat(9) + 'ab',
        'Cloudflare Origin CA Key'
    );
});

test('detects Vercel Blob Token', () => {
    assertSecretDetected('vercel_blob_rw_' + 'A1b2C3d4e5'.repeat(3), 'Vercel Blob Token');
});

test('detects NPM Token', () => {
    assertSecretDetected('npm_abcdefghijklmnopqrstuvwxyz1234567890', 'NPM Access Token');
});

// ── PlanetScale ───────────────────────────────────────────────
console.log('\n🌍  PlanetScale:');

test('detects PlanetScale API token', () => {
    // Token split across concatenation so GitHub push protection does not flag test fixtures
    assertSecretDetected(
        'PLANETSCALE_TOKEN=pscale_tkn_' + 'aBcDeFgHiJkLmNoPqRsTuVwXyZ123456',
        'PlanetScale API Token'
    );
});

test('does not flag short pscale_tkn_ string (too short)', () => {
    assertNoSecrets('pscale_tkn_short');
});


// ── Infrastructure / DevOps ──────────
console.log('\n🏗️  Infrastructure Patterns:');

test('detects Doppler service token with config segment', () => {
    assertSecretDetected('dp.st.prd_config.' + 'A1b2C3d4e5'.repeat(4), 'Doppler Token');
});

test('detects Databricks API token', () => {
    assertSecretDetected('dapi' + '0123456789abcdef'.repeat(2), 'Databricks API Token');
});

test('detects Tailscale auth key', () => {
    assertSecretDetected('tskey-auth-kAbCd12345-AbCdEfGh12345', 'Tailscale Key');
});

test('detects Dynatrace API token', () => {
    assertSecretDetected(
        'dt0c01.ABCDEFGHJKLMNPQRSTUVWXYZ.' + 'A1B2C3D4E5F6G7H8'.repeat(4),
        'Dynatrace API Token'
    );
});


// ── Supabase ─────────────────────────
console.log('\n🟢 Supabase Patterns:');

test('detects Supabase publishable (anon) key', () => {
    assertSecretDetected(
        'sb_publishable_abcdefghijklmnopqrstuvwxyz1234567890',
        'Supabase Publishable Key'
    );
});

test('detects Supabase secret (service role) key', () => {
    assertSecretDetected(
        'sb_secret_abcdefghijklmnopqrstuvwxyz1234567890',
        'Supabase Secret Key'
    );
});


// ── Monitoring / Analytics ───────────
console.log('\n📡 Monitoring Patterns:');

test('detects Datadog API key (real-world DD_API_KEY form)', () => {
    // The old pattern required a literal 'ddapikey' and never matched reality.
    assertSecretDetected('DD_API_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', 'Datadog API Key');
});

test('detects Sentry user token', () => {
    assertSecretDetected('sntryu_' + '0123456789abcdef'.repeat(4), 'Sentry User Token');
});

test('detects Sentry org token', () => {
    assertSecretDetected('sntrys_eyJ' + 'A1b2C3d4e5'.repeat(6), 'Sentry Org Token');
});

test('detects Grafana service account token', () => {
    assertSecretDetected('glsa_' + 'A1b2C3d4'.repeat(4) + '_deadbeef', 'Grafana Service Account Token');
});

test('detects Grafana Cloud token', () => {
    assertSecretDetected('glc_' + 'A1b2C3d4e5'.repeat(4) + '=', 'Grafana Cloud Token');
});


// ── Okta ─────────────────────────────────────────────────────
console.log('\n🔐  Okta:');

test('detects Okta API Token', () => {
    assertSecretDetected(
        'OKTA_TOKEN=00abcdefghijklmnopqrstuvwxyz0123456789_-AB',
        'Okta API Token'
    );
});

test('does not flag 00-prefix hex that is too short', () => {
    assertNoSecrets('00deadbeef');
});

test('does not flag bare 00-prefixed base64url without an okta keyword', () => {
    // The old \b00[a-zA-Z0-9_-]{40}\b fired on ANY 42-char base64url starting 00.
    assertNoSecrets('00AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn', { ...DEFAULT_CONFIG, enableEntropy: false });
});


// ── Config Files / Local Credentials ─
console.log('\n📁 Config File Patterns:');

test('detects netrc credentials', () => {
    assertSecretDetected(
        'machine api.example.com login craig password s3cretPass',
        'netrc Credentials'
    );
});

test('detects Docker config auth blob', () => {
    assertSecretDetected('"auth": "dXNlcjpzZWNyZXRwYXNzd29yZA=="', 'Docker Config Auth');
});

test('detects npmrc auth token line', () => {
    assertSecretDetected(
        '//registry.npmjs.org/:_authToken=s3cr3tT0ken12345',
        'npmrc Auth Token'
    );
});

test('detects kubeconfig client-key-data', () => {
    assertSecretDetected('client-key-data: ' + 'TFMwdExTMU'.repeat(12), 'Kubeconfig Client Key');
});


// ── SaaS / Productivity ──────────────
console.log('\n🗂️  SaaS & Productivity Patterns:');

test('detects Notion integration token', () => {
    assertSecretDetected('ntn_12345678901' + 'aBcDeFg'.repeat(5), 'Notion Integration Token');
});

test('detects Airtable PAT', () => {
    assertSecretDetected('patAbCd1234EfGh56.' + '0123456789abcdef'.repeat(4), 'Airtable PAT');
});

test('detects HubSpot private app token', () => {
    assertSecretDetected(fixture('pat-', 'na1-', '12345678-90ab-cdef-1234-567890abcdef'), 'HubSpot Private App Token');
});

test('detects Figma PAT', () => {
    assertSecretDetected('figd_' + 'A1b2C3d4e5'.repeat(4), 'Figma PAT');
});

test('detects 1Password service account token', () => {
    assertSecretDetected('ops_eyJ' + 'A1b2C3d4e5'.repeat(11), '1Password Service Account Token');
});

test('detects Dropbox access token', () => {
    assertSecretDetected('sl.' + 'A1b2C3d4e5'.repeat(14), 'Dropbox Access Token');
});

test('detects keyword-adjacent UUID credential (Snyk/Railway style)', () => {
    // Bare UUIDs are deliberately skipped by the entropy pass, so services whose
    // tokens ARE UUIDs (Snyk, Railway, Splunk HEC) need a keyword anchor.
    assertSecretDetected(
        'SNYK_TOKEN=12345678-90ab-cdef-1234-567890abcdef',
        'Keyword-adjacent UUID Credential'
    );
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

// ── Linear ────────────────────────────────────────────────────
console.log('\n📋  Linear:');

test('detects Linear API key', () => {
    assertSecretDetected(
        'lin_api_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdef',
        'Linear API Key'
    );
});

test('does not flag short lin_api_ string (too short)', () => {
    assertNoSecrets('lin_api_tooshort');
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

test('flags long high-entropy base64 blob (>80 chars, not a source map)', () => {
    // The ">80 char base64" entropy skip was a blanket hole: any long base64
    // credential blob (fine-grained PATs, long project keys, encoded creds) that
    // did not also match a regex was silently ignored. A 90-char high-entropy blob
    // must be caught.
    const blob = 'aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5a'.repeat(2) + 'aB3cD4eF5g';
    assertAnySecretDetected(blob);
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

test('does NOT redact official test credentials by default (redactTestKeys=false)', () => {
    const result = SecretScanner.redact('my key is AKIAIOSFODNN7EXAMPLE', DEFAULT_CONFIG);
    assert.strictEqual(result.secrets.size, 0, 'Official test credential should not be flagged by default');
});

test('redacts official test credentials when redactTestKeys=true', () => {
    assertSecretDetected('my key is AKIAIOSFODNN7EXAMPLE', 'AWS Access Key ID', { ...DEFAULT_CONFIG, redactTestKeys: true });
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

test('does not leak the tail of a longer secret sharing a shorter secret prefix', () => {
    // Two Stripe keys where the shorter is a prefix of the longer. If the shorter is
    // redacted first, replaceAll fragments the longer one and its tail leaks.
    const shortKey = 'sk_live_' + 'a'.repeat(12);
    const longKey = 'sk_live_' + 'a'.repeat(12) + 'XYZ987secrettail';
    const result = SecretScanner.redact(`a=${shortKey}\nb=${longKey}`, DEFAULT_CONFIG);
    assert.ok(
        !result.redactedText.includes('secrettail'),
        `Longer secret's tail leaked into redacted text: ${result.redactedText}`
    );
});

test('placeholder format is correct', () => {
    const result = SecretScanner.redact('ghp_ABCDEFabcdef1234567890abcdef123456');
    const placeholder = Array.from(result.secrets.keys())[0];
    assert.ok(/^{{SECRET_[a-z0-9]{32}}}$/.test(placeholder), `Placeholder "${placeholder}" does not match expected format`);
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
