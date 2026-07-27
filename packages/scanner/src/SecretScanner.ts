import * as crypto from 'crypto';

// ─────────────────────────────────────────────
// Configuration Interface (decoupled from VS Code
// so SecretScanner remains testable standalone)
// ─────────────────────────────────────────────
export interface ScannerConfig {
    enableEntropy: boolean;
    entropyThreshold: number;
    minimumTokenLength: number;
    customPatterns: Array<{ name: string; regex: string }>;
    whitelistPatterns: string[];
    /** When true, officially-published test/demo credentials (e.g. AKIAIOSFODNN7EXAMPLE) are redacted like any other secret. When false (default), they are treated as safe example values and left in place. */
    redactTestKeys: boolean;
}

export const DEFAULT_CONFIG: ScannerConfig = {
    enableEntropy: true,
    entropyThreshold: 4.5,
    minimumTokenLength: 20,
    customPatterns: [],
    whitelistPatterns: [],
    redactTestKeys: false,
};

export interface RedactResult {
    redactedText: string;
    secrets: Map<string, string>;
    detectedTypes: Set<string>;
}

// ─────────────────────────────────────────────
// SecretScanner — fully offline, zero network
// ─────────────────────────────────────────────
export class SecretScanner {

    // ═════════════════════════════════════════
    //  Regex Pattern Library (110+ patterns)
    // ═════════════════════════════════════════
    private static readonly PATTERNS: Array<{ name: string; regex: RegExp }> = [

        // ── Cloud Providers ──────────────────
        { name: 'AWS Access Key ID', regex: /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA|ASIA)[A-Z2-7]{16}\b/ },
        { name: 'AWS Secret Access Key', regex: /(?:aws_secret_access_key|aws_secret_key|secret_key|SecretAccessKey)['"]?\s*[=:]\s*['"]?[A-Za-z0-9\/+=]{40}(?![A-Za-z0-9\/+=])/i },
        { name: 'AWS MWS Key', regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ },
        { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
        { name: 'Google OAuth Token', regex: /ya29\.[0-9A-Za-z\-_]+/ },
        { name: 'Google OAuth Refresh Token', regex: /\b1\/\/[0-9A-Za-z_-]{25,}/ },
        { name: 'Google Cloud Service Acct', regex: /"type"\s*:\s*"service_account"/ },
        { name: 'Google OAuth Client Secret', regex: /GOCSPX-[a-zA-Z0-9\-_]{28}/ },
        { name: 'Azure Storage Account Key', regex: /AccountKey=[A-Za-z0-9+\/=]{88}/ },
        { name: 'Azure SAS Token', regex: /[?&]sig=[A-Za-z0-9%+\/=]{40,}/ },
        { name: 'Azure AD Client Secret', regex: /(?:^|[\s'"`>=:(,])[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}(?![a-zA-Z0-9_~.-])/ },
        { name: 'Alibaba AccessKey ID', regex: /\bLTAI[A-Za-z0-9]{20}\b/ },
        { name: 'Tencent Cloud SecretId', regex: /\bAKID[A-Za-z0-9]{32}\b/ },

        // ── AI / ML Providers ────────────────
        // Note: Google Gemini keys (AIzaSy...) are a strict subset of the Google API Key
        // pattern above and are already covered by it.
        { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}/ },
        { name: 'OpenAI API Key (Project)', regex: /sk-proj-[a-zA-Z0-9\-_]{40,}/ },
        { name: 'OpenAI API Key (Svc)', regex: /sk-svcacct-[a-zA-Z0-9\-_]{40,}/ },
        { name: 'OpenAI API Key (Admin)', regex: /sk-admin-[a-zA-Z0-9\-_]{40,}/ },
        { name: 'Anthropic API Key', regex: /sk-ant-[a-zA-Z0-9\-_]{40,}/ },
        { name: 'Amazon Bedrock API Key', regex: /\bABSK[A-Za-z0-9+\/]{109,269}={0,2}/ },
        { name: 'Hugging Face Token', regex: /hf_[a-zA-Z0-9]{34}/ },
        { name: 'Replicate API Token', regex: /r8_[a-zA-Z0-9]{37}/ },
        { name: 'OpenRouter API Key', regex: /sk-or-v1-[a-f0-9]{64}/ },
        { name: 'Groq API Key', regex: /gsk_[A-Za-z0-9]{52}/ },
        { name: 'Perplexity API Key', regex: /pplx-[A-Za-z0-9]{48}/ },
        { name: 'xAI API Key', regex: /xai-[A-Za-z0-9]{60,120}/ },
        { name: 'LangSmith API Key', regex: /lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}/ },
        { name: 'Pinecone API Key', regex: /\bpcsk_[A-Za-z0-9_]{30,}\b/ },
        { name: 'Fireworks API Key', regex: /\bfw_[a-zA-Z0-9]{24,}\b/ },
        { name: 'Cerebras API Key', regex: /\bcsk-[a-z0-9]{30,64}\b/ },
        // ElevenLabs keys are hex-only after sk_ — cannot collide with Stripe's
        // sk_live_/sk_test_/sk_prod_ because 'l', 't', 'p' etc. are outside [a-f0-9].
        { name: 'ElevenLabs API Key', regex: /\bsk_[a-f0-9]{40,64}\b/ },
        { name: 'LlamaCloud API Key', regex: /\bllx-[A-Za-z0-9_-]{40,}\b/ },
        { name: 'Vercel AI Gateway Key', regex: /\bvck_[A-Za-z0-9]{20,}\b/ },
        { name: 'Together AI API Key', regex: /\btgp_v1_[A-Za-z0-9_-]{40,}\b/ },

        // ── Payment Providers ────────────────
        { name: 'Stripe Secret Key', regex: /sk_(live|test|prod)_[0-9a-zA-Z_]{10,99}/ },
        { name: 'Stripe Restricted Key', regex: /rk_(live|test|prod)_[0-9a-zA-Z_]{10,99}/ },
        { name: 'Stripe Publishable Key', regex: /pk_(live|test|prod)_[0-9a-zA-Z_]{10,99}/ },
        { name: 'Stripe Webhook Secret', regex: /\bwhsec_[A-Za-z0-9]{32,64}\b/ },
        { name: 'Square Access Token', regex: /sq0atp-[0-9A-Za-z\-_]{10,40}/ },
        { name: 'Square OAuth Secret', regex: /sq0csp-[0-9A-Za-z\-_]{20,50}/ },
        { name: 'PayPal Braintree Token', regex: /access_token\$(production|sandbox)\$[0-9a-zA-Z_$]{10,}/ },

        // ── Version Control & Dev ────────────
        { name: 'GitHub Personal Access Token', regex: /ghp_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub OAuth Token', regex: /gho_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub App Token', regex: /ghu_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub App Server Token', regex: /ghs_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub App Refresh Token', regex: /ghr_[a-zA-Z0-9]{36}/ },
        // Fine-grained PATs do not have fixed segment lengths in practice, so match the
        // prefix plus a tolerant run of [A-Za-z0-9_] (the underscore separator is included).
        { name: 'GitHub Fine-grained PAT', regex: /github_pat_[A-Za-z0-9_]{60,}/ },
        // Modern routable GitLab PATs are longer than 20 chars and may carry a
        // .{9-char} CRC suffix — {20,} prevents redacting only the first 20 chars.
        { name: 'GitLab Personal Access Token', regex: /glpat-[0-9A-Za-z_-]{20,}(?:\.[0-9a-z]{9})?/ },
        { name: 'GitLab Pipeline Trigger Token', regex: /glptt-[0-9a-f]{40}/ },
        { name: 'GitLab Runner Token', regex: /glrt-[0-9A-Za-z\-_]{20,}/ },
        { name: 'Bitbucket App Password', regex: /ATBB[a-zA-Z0-9]{32}/ },
        { name: 'Atlassian API Token', regex: /\bATATT3[A-Za-z0-9_\-=]{180,192}\b/ },
        { name: 'CircleCI Personal Access Token', regex: /\bCCIPAT_[A-Za-z0-9]{15,30}_[a-f0-9]{40}\b/ },
        { name: 'Docker Hub Token', regex: /\bdckr_(?:pat|oat)_[A-Za-z0-9_-]{20,}\b/ },
        { name: 'Sourcegraph Access Token', regex: /\bsgp_(?:[a-fA-F0-9]{16}_)?[a-fA-F0-9]{40}\b/ },
        { name: 'SonarQube Token', regex: /\bsq[upa]_[a-f0-9]{40}\b/ },

        // ── Communication ────────────────────
        { name: 'Slack Bot Token', regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/ },
        { name: 'Slack User Token', regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/ },
        { name: 'Slack App Token', regex: /xapp-[0-9]{1}-[A-Z0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{64}/ },
        { name: 'Slack Refresh Token', regex: /xoxe\.xox[bp]-\d+-[A-Za-z0-9]{30,}/ },
        { name: 'Slack App Config Token', regex: /xoxe-\d+-[A-Za-z0-9]{30,}/ },
        { name: 'Slack Webhook', regex: /(?<![\w.-])https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24}/ },
        { name: 'Discord Bot Token', regex: /\b[MNO][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/ },
        { name: 'Discord Webhook', regex: /(?<![\w.-])https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/ },
        // Real bot IDs are 5-16 digits and the secret segment always starts 'AA'.
        { name: 'Telegram Bot Token', regex: /\b\d{5,16}:AA[A-Za-z0-9_-]{32,34}(?![A-Za-z0-9_-])/ },
        { name: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/ },
        { name: 'Twilio Account SID', regex: /AC[a-z0-9]{32}/ },
        { name: 'X (Twitter) Bearer Token', regex: /\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{60,110}\b/ },

        // ── Email Services ───────────────────
        { name: 'SendGrid API Key', regex: /SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/ },
        { name: 'Mailgun API Key', regex: /\bkey-[0-9a-f]{32}\b/ },
        { name: 'Mailchimp API Key', regex: /\b[0-9a-f]{32}-us\d{1,2}/ },
        { name: 'Resend API Key', regex: /\bre_[A-Za-z0-9]{6,12}_[A-Za-z0-9]{20,}\b|\bre_[A-Za-z0-9]{32,}\b/ },
        { name: 'Brevo API Key', regex: /\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b/ },

        // ── Hosting & Deployment ─────────────
        { name: 'Vercel Access Token', regex: /vercel_[a-zA-Z0-9]{24,}/ },
        { name: 'Vercel Blob Token', regex: /\bvercel_blob_rw_[A-Za-z0-9_]{30,}\b/ },
        { name: 'Netlify Access Token', regex: /nfp_[a-zA-Z0-9]{40}/ },
        { name: 'DigitalOcean PAT', regex: /dop_v1_[a-f0-9]{64}/ },
        { name: 'DigitalOcean OAuth Token', regex: /doo_v1_[a-f0-9]{64}/ },
        { name: 'DigitalOcean Refresh Token', regex: /dor_v1_[a-f0-9]{64}/ },
        { name: 'Render API Key', regex: /rnd_[a-zA-Z0-9]{20,40}/ },
        { name: 'Railway API Token', regex: /railway_[a-zA-Z0-9]{32,}/ },
        { name: 'PlanetScale API Token', regex: /pscale_tkn_[a-zA-Z0-9_]{32,}/ },
        { name: 'Fly.io Access Token', regex: /\bfo1_[A-Za-z0-9_-]{40,}/ },
        { name: 'Heroku API Key', regex: /\bHRKU-AA[0-9a-zA-Z_-]{58}\b/ },
        { name: 'Cloudflare API Token', regex: /cloudflare[\w.-]{0,20}['"]?\s*[=:]\s*['"]?[A-Za-z0-9_-]{40}(?![A-Za-z0-9_-])/i },
        { name: 'Cloudflare Origin CA Key', regex: /\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b/ },

        // ── Package Registries ───────────────
        { name: 'NPM Access Token', regex: /npm_[a-zA-Z0-9]{36}/ },
        { name: 'PyPI API Token', regex: /pypi-[a-zA-Z0-9\-_]{50,}/ },
        { name: 'NuGet API Key', regex: /oy2[a-z0-9]{43}/ },
        { name: 'RubyGems API Key', regex: /rubygems_[a-f0-9]{48}/ },

        // ── Auth / Tokens ────────────────────
        { name: 'JSON Web Token', regex: /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_.+\/=]+/ },
        // Lookaheads require at least one digit / '+' / '/' / '=' so camelCase prose
        // like "Bearer TokenAuthenticationScheme" is not redacted.
        { name: 'Bearer Token', regex: /Bearer\s+(?=[A-Za-z0-9\-._~+\/]*[\d+\/=])[A-Za-z0-9\-._~+\/]{20,}=*/i },
        { name: 'Basic Auth Credentials', regex: /Basic\s+(?=[A-Za-z0-9+\/]*[\d+\/=])[A-Za-z0-9+\/]{16,}={0,2}/i },
        { name: 'OAuth Client Secret', regex: /client_secret[=:]\s*['"]?[a-zA-Z0-9\-_]{20,}['"]?/i },

        // ── Cryptographic Keys ───────────────
        // Matches the full PEM block (header + body + footer) so the key material is
        // redacted in its entirety, not just the header. The trailing group is
        // optional so a header-only fragment still matches.
        { name: 'Private Key Block', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{0,8192}?-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----)?/ },
        { name: 'age Secret Key', regex: /\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b/ },

        // ── Database Connection Strings ──────
        // Userinfo classes exclude ':' and '@' — the old [^\s'"]+ classes allowed
        // quadratic backtracking (ReDoS) on long crafted inputs.
        { name: 'PostgreSQL Connection URI', regex: /postgres(?:ql)?:\/\/[^\s'":@]+:[^\s'"@]+@[^\s'"]+/ },
        { name: 'MySQL Connection URI', regex: /mysql:\/\/[^\s'":@]+:[^\s'"@]+@[^\s'"]+/ },
        { name: 'MongoDB Connection URI', regex: /mongodb(?:\+srv)?:\/\/[^\s'":@]+:[^\s'"@]+@[^\s'"]+/ },
        { name: 'Redis Connection URI', regex: /redis(?:s)?:\/\/[^\s'":@]+:[^\s'"@]+@[^\s'"]+/ },
        { name: 'AMQP Connection URI', regex: /amqps?:\/\/[^\s'":@]+:[^\s'"@]+@[^\s'"]+/ },

        // ── Infrastructure / DevOps ──────────
        { name: 'Hashicorp Vault Token', regex: /hvs\.[a-zA-Z0-9\-_]{24,}/ },
        { name: 'Terraform Cloud Token', regex: /\b[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{60,}/ },
        { name: 'Doppler Token', regex: /\bdp\.(?:ct|pt|st|sa)\.(?:[a-z0-9\-_]{2,32}\.)?[a-zA-Z0-9]{40,44}\b/ },
        { name: 'Databricks API Token', regex: /\bdapi[a-f0-9]{32}(?:-\d)?\b/ },
        { name: 'Tailscale Key', regex: /\btskey-(?:auth|api|client)-[A-Za-z0-9]{10,}-[A-Za-z0-9]{10,}\b/ },
        { name: 'Dynatrace API Token', regex: /\bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b/i },

        // ── E-commerce ───────────────────────
        { name: 'Shopify Access Token', regex: /shpat_[a-fA-F0-9]{32}/ },
        { name: 'Shopify Custom App Token', regex: /shpca_[a-fA-F0-9]{32}/ },
        { name: 'Shopify Private App Token', regex: /shppa_[a-fA-F0-9]{32}/ },
        { name: 'Shopify Shared Secret', regex: /shpss_[a-fA-F0-9]{32}/ },

        // ── Monitoring / Analytics ───────────
        { name: 'Datadog API Key', regex: /(?:datadog|dd)[_-]?(?:api|app(?:lication)?)[_-]?key['"]?\s*[=:]\s*['"]?[a-f0-9]{32,40}(?![a-f0-9])/i },
        { name: 'Sentry DSN', regex: /https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io\/\d+/ },
        { name: 'Sentry User Token', regex: /\bsntryu_[a-f0-9]{64}\b/ },
        { name: 'Sentry Org Token', regex: /\bsntrys_eyJ[A-Za-z0-9+\/=_]{50,}/ },
        { name: 'New Relic API Key', regex: /NRAK-[A-Z0-9]{27}/ },
        { name: 'Grafana Service Account Token', regex: /\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b/ },
        { name: 'Grafana Cloud Token', regex: /\bglc_[A-Za-z0-9+\/]{32,200}={0,3}/ },

        // ── Supabase ─────────────────────────
        // sbp_ is a personal/management API token, NOT the service_role key
        // (which is a JWT and already caught by the JSON Web Token rule).
        { name: 'Supabase Access Token', regex: /sbp_[a-f0-9]{40}/ },
        { name: 'Supabase Publishable Key', regex: /sb_publishable_[a-zA-Z0-9_]{20,}/ },
        { name: 'Supabase Secret Key', regex: /sb_secret_[a-zA-Z0-9_]{20,}/ },

        // ── Config Files / Local Credentials ─
        { name: 'netrc Credentials', regex: /machine\s+\S+\s+login\s+\S+\s+password\s+\S+/i },
        { name: 'Docker Config Auth', regex: /"auth"\s*:\s*"[A-Za-z0-9+\/=]{20,}"/ },
        { name: 'npmrc Auth Token', regex: /\/\/[^\s'"]+\/:_authToken=\S+/ },
        { name: 'Kubeconfig Client Key', regex: /client-key-data:\s*[A-Za-z0-9+\/=]{100,}/ },

        // ── Misc / Generic ───────────────────
        { name: 'Linear API Key', regex: /lin_api_[a-zA-Z0-9_]{40,}/ },
        { name: 'Postman API Key', regex: /PMAK-[a-f0-9]{24}-[a-f0-9]{34}/ },
        { name: 'Okta API Token', regex: /okta[\w.-]{0,20}['"]?\s*[=:]\s*['"]?00[a-zA-Z0-9_-]{40}(?![a-zA-Z0-9_-])/i },
        { name: 'Notion Integration Token', regex: /\bntn_[0-9]{11}[A-Za-z0-9]{35}\b/ },
        { name: 'Airtable PAT', regex: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/ },
        { name: 'HubSpot Private App Token', regex: /\bpat-(?:na|eu|ap)\d+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/ },
        { name: 'Figma PAT', regex: /\bfigd_[A-Za-z0-9_-]{35,50}\b/ },
        { name: '1Password Service Account Token', regex: /\bops_eyJ[A-Za-z0-9+\/=_-]{100,}/ },
        { name: 'Dropbox Access Token', regex: /\bsl\.[A-Za-z0-9_-]{130,152}\b/ },
        // Covers Railway, Snyk, Splunk HEC and other services whose tokens are bare
        // UUIDs — the entropy pass deliberately skips UUIDs, so keyword-anchor them.
        { name: 'Keyword-adjacent UUID Credential', regex: /(?:api[_-]?key|token|secret|password)['"]?\s*[=:]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])/i },
        { name: 'Password in Assignment', regex: /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"\n\r]{8,64}['"]/i },
        { name: 'Token in Assignment', regex: /(?:token|api_key|apikey|access_key|auth_token|secret_key)\s*[=:]\s*['"][^'"\n\r]{16,100}['"]/i },
    ];

    // Pre-compiled global versions of PATTERNS — created once at class load time.
    // Preserves original flags (e.g. 'i') and adds 'g' so text.match() returns all hits.
    private static readonly GLOBAL_PATTERNS: Array<{ name: string; regex: RegExp }> =
        SecretScanner.PATTERNS.map(p => ({
            name: p.name,
            regex: new RegExp(p.regex.source, p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g'),
        }));

    // ═════════════════════════════════════════
    //  Public API
    // ═════════════════════════════════════════

    /**
     * Scans text for secrets using regex patterns + Shannon entropy.
     * Returns redacted text with placeholders, a secret map, and detected types.
     * 
     * @param text   - Raw input to scan (prompt, file content, etc.)
     * @param config - Optional scanner config (defaults to DEFAULT_CONFIG)
     */
    public static redact(text: string, config: ScannerConfig = DEFAULT_CONFIG): RedactResult {
        let redactedText = text;
        const secrets = new Map<string, string>();
        const detectedTypes = new Set<string>();
        // O(1) reverse-lookup map: secretValue → placeholder (avoids O(N) scan on every secret)
        const valueToPlaceholder = new Map<string, string>();

        // Build whitelist regex set
        const whitelistRegexps = config.whitelistPatterns
            .map((p) => { try { return new RegExp(p); } catch { return null; } })
            .filter((r): r is RegExp => r !== null);

        const isWhitelisted = (value: string): boolean => {
            return whitelistRegexps.some((re) => re.test(value));
        };

        // Obvious placeholder values to skip for Password/Token in Assignment matches.
        // These produce noisy false positives in docs, READMEs, and example configs.
        const PLACEHOLDER_VALUES = new Set([
            'changeme', 'password', 'your_password', 'your_password_here',
            'placeholder', 'your_secret', 'your_secret_here',
            'your_api_key', 'your_api_key_here', 'your_token', 'your_token_here',
        ]);

        // Officially-published test/demo credentials. Safe to include in READMEs and
        // examples. Skipped unless config.redactTestKeys is true.
        const TEST_CREDENTIALS = new Set([
            'AKIAIOSFODNN7EXAMPLE',                          // AWS Access Key ID
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',    // AWS Secret Access Key
            'ASIAIOSFODNN7EXAMPLE',                          // AWS STS key
            'sk-ant-api03-EXAMPLE',                          // Anthropic (pattern prefix)
            'ghp_EXAMPLE',                                   // GitHub PAT prefix
            'glpat-EXAMPLE',                                 // GitLab PAT prefix
        ]);

        const isPlaceholderAssignment = (typeName: string, match: string): boolean => {
            if (typeName !== 'Password in Assignment' && typeName !== 'Token in Assignment') {
                return false;
            }
            // Extract the quoted value from e.g. password="changeme"
            const m = match.match(/['"]([^'"]+)['"]/);
            if (!m) { return false; }
            return PLACEHOLDER_VALUES.has(m[1].toLowerCase());
        };

        const isTestCredential = (secretValue: string): boolean => {
            if (config.redactTestKeys) { return false; }
            return TEST_CREDENTIALS.has(secretValue);
        };

        const replaceSecret = (secretValue: string, typeName: string): void => {
            if (isWhitelisted(secretValue)) { return; }
            if (isPlaceholderAssignment(typeName, secretValue)) { return; }
            if (isTestCredential(secretValue)) { return; }

            // Check if this exact secret value was already captured (O(1) via reverse map)
            let placeholder = valueToPlaceholder.get(secretValue) || '';

            if (!placeholder) {
                const uuid = crypto.randomUUID().replace(/-/g, '');
                placeholder = `{{SECRET_${uuid}}}`;
                secrets.set(placeholder, secretValue);
                valueToPlaceholder.set(secretValue, placeholder);
                detectedTypes.add(typeName);
            }

            // Use replaceAll with callback to avoid special replacement patterns ($&, $1, etc.)
            redactedText = redactedText.replaceAll(secretValue, () => placeholder);
        };

        // ── Steps 1 & 2: collect built-in + custom regex matches, then redact ──
        // Redact longer values BEFORE shorter ones so a short secret that is a substring
        // of a longer secret cannot fragment it and leak the longer secret's tail.
        const regexCandidates: Array<{ value: string; type: string }> = [];

        for (const pattern of this.GLOBAL_PATTERNS) {
            const matches = text.match(pattern.regex);
            if (matches) {
                for (const match of new Set(matches)) {
                    regexCandidates.push({ value: match, type: pattern.name });
                }
            }
        }

        for (const custom of config.customPatterns) {
            try {
                const customRegex = new RegExp(custom.regex, 'g');
                const matches = text.match(customRegex);
                if (matches) {
                    for (const match of new Set(matches)) {
                        regexCandidates.push({ value: match, type: custom.name });
                    }
                }
            } catch {
                // Silently skip invalid user-defined patterns
            }
        }

        // Stable sort by descending length keeps pattern order for equal-length values,
        // so type attribution for duplicates is unchanged.
        regexCandidates.sort((a, b) => b.value.length - a.value.length);
        for (const candidate of regexCandidates) {
            replaceSecret(candidate.value, candidate.type);
        }

        // ── Step 3: Shannon Entropy Scan ──
        if (config.enableEntropy) {
            // Tokenize the *current* redacted text (after regex replacements)
            const tokens = redactedText.split(/[\s="',`:;()\[\]{}<>|]+/);
            for (const token of tokens) {
                // Skip already-redacted placeholders
                if (token.startsWith('{{SECRET_') && token.endsWith('}}')) { continue; }

                // Skip standard UUIDs (not usually sensitive on their own)
                if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) { continue; }

                // Skip tokens that look like normal words (all lowercase, no digits/symbols mix)
                if (/^[a-z]+$/i.test(token)) { continue; }

                // Skip URLs / file paths that aren't connection strings
                if (/^https?:\/\//.test(token) && !/:\/\/[^:@\s]{1,512}:[^@\s]{1,512}@/.test(token)) { continue; }

                // Skip npm / yarn integrity hashes (sha256-, sha384-, sha512-)
                if (/^sha[0-9]+-/i.test(token)) { continue; }

                // Skip registry URL fragments (e.g. //registry.npmjs.org/...)
                if (/^(\/\/)?registry\.npmjs\.org\//i.test(token)) { continue; }
                if (/^(\/\/)?registry\.yarnpkg\.com\//i.test(token)) { continue; }

                // Skip URL fragments that are clearly partial paths (start with //)
                if (/^\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\//i.test(token)) { continue; }

                // Skip tokens that look like package tarball URLs (contain .tgz)
                if (/\.tgz$/i.test(token)) { continue; }

                // Skip government / documentation URLs and regulatory reference IDs
                if (/^(https?:\/\/)?(www\.)?[a-z0-9.-]+\.(gov|edu|mil)\//i.test(token)) { continue; }

                // Skip tokens that are mostly path-like (contain multiple / and shell-like chars)
                if ((token.match(/\//g) || []).length >= 2 && /^[a-zA-Z0-9@.\-_/$*~]+$/.test(token)) { continue; }

                // Skip code identifiers: dotted property access (e.g. SCORE_WEIGHTS.emergencyContacts)
                if (/^[a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$][a-zA-Z0-9_$]*/.test(token)) { continue; }

                // Skip SCREAMING_SNAKE_CASE identifiers (e.g. VITE_SUPABASE_ANON_KEY)
                if (/^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$/.test(token)) { continue; }

                // Skip environment variable references (import.meta.env.*, process.env.*)
                if (/^(import\.meta\.env|process\.env)\./i.test(token)) { continue; }

                // Skip well-known character set definitions (base32, base36, hex alphabets)
                if (/^[A-Z0-9]{20,36}$/.test(token) && /^[A-Z2-7]+$|^[0-9A-Z]+$|^[0-9A-F]+$/i.test(token)) { continue; }

                // Skip base64 blobs — likely source maps / webpack output, not secrets.
                // Only skip genuinely huge tokens (>1500 chars): real secrets are virtually
                // never a single token that long, but build artefacts routinely are. Never
                // skip tokens that carry a known secret prefix, so a long credential blob
                // can't hide behind this rule (the old >80 threshold was a blanket hole).
                if (!/^(github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|xox|sk-|glpat-|npm_)/.test(token)) {
                    if (token.length > 1500 && /^[A-Za-z0-9+/=_-]+$/.test(token)) { continue; }
                }

                // Skip webpack module identifiers (e.g. __WEBPACK_IMPORTED_MODULE_)
                if (/__WEBPACK_/.test(token) || /__esModule/.test(token)) { continue; }

                // Skip URL-encoded strings (e.g. C%3A%5CUsers%5C...)
                if (/%[0-9A-Fa-f]{2}/.test(token) && (token.match(/%/g) || []).length >= 3) { continue; }

                // Skip minified CSS/JS fragments (contain lots of escaped sequences)
                if (/\\n|\\t|\\r/.test(token) && token.length > 30) { continue; }

                if (token.length >= config.minimumTokenLength) {
                    const entropy = this.calculateEntropy(token);
                    if (entropy > config.entropyThreshold) {
                        replaceSecret(token, 'High Entropy Token');
                    }
                }
            }
        }

        return { redactedText, secrets, detectedTypes };
    }

    /**
     * Returns the total number of built-in regex patterns.
     * Useful for diagnostics / UI display.
     */
    public static get patternCount(): number {
        return this.PATTERNS.length;
    }


    // ═══════════════════════════════════
    //  Entropy Calculation
    // ═══════════════════════════════════

    // Pre-allocated static array for fast entropy calculations, avoiding allocations on every call.
    private static readonly ENTROPY_FREQUENCIES = new Int32Array(256);

    /**
     * Calculates Shannon entropy of a string.
     * Higher entropy → more random → more likely to be a secret.
     * Typical prose: 2-3 bits. API keys: 4.5-6 bits.
     */
    public static calculateEntropy(str: string): number {
        const len = str.length;
        if (len === 0) { return 0; }

        // Fast path: use a pre-allocated fixed Int32Array for ASCII character frequencies.
        // This is significantly faster than creating a new Int32Array or Map on every call.
        const frequencies = SecretScanner.ENTROPY_FREQUENCIES;

        for (let i = 0; i < len; i++) {
            const code = str.charCodeAt(i);
            if (code > 255) {
                // Non-ASCII character — zero out the array we modified and fall back to the Map-based implementation.
                for (let j = 0; j < i; j++) {
                    frequencies[str.charCodeAt(j)] = 0;
                }
                return SecretScanner._calculateEntropyFallback(str);
            }
            frequencies[code]++;
        }

        let entropy = 0;
        for (let i = 0; i < len; i++) {
            const code = str.charCodeAt(i);
            const count = frequencies[code];
            if (count > 0) {
                const p = count / len;
                entropy -= p * Math.log2(p);
                // Lazily reset the modified index to zero for the next calculation
                frequencies[code] = 0;
            }
        }

        return entropy;
    }

    private static _calculateEntropyFallback(str: string): number {
        const len = str.length;
        const frequencies = new Map<string, number>();
        for (let i = 0; i < len; i++) {
            const char = str[i];
            frequencies.set(char, (frequencies.get(char) || 0) + 1);
        }

        let entropy = 0;
        for (const [, count] of frequencies) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }

        return entropy;
    }
}
