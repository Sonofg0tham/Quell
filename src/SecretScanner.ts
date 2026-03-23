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
}

export const DEFAULT_CONFIG: ScannerConfig = {
    enableEntropy: true,
    entropyThreshold: 4.5,
    minimumTokenLength: 20,
    customPatterns: [],
    whitelistPatterns: [],
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
    //  Regex Pattern Library (75+ patterns)
    // ═════════════════════════════════════════
    private static readonly PATTERNS: Array<{ name: string; regex: RegExp }> = [

        // ── Cloud Providers ──────────────────
        { name: 'AWS Access Key ID', regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/ },
        { name: 'AWS Secret Access Key', regex: /(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*[A-Za-z0-9\/+=]{40}/ },
        { name: 'AWS MWS Key', regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ },
        { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
        { name: 'Google OAuth Token', regex: /ya29\.[0-9A-Za-z\-_]+/ },
        { name: 'Google Cloud Service Acct', regex: /"type"\s*:\s*"service_account"/ },
        { name: 'Google OAuth Client Secret', regex: /GOCSPX-[a-zA-Z0-9\-_]{28}/ },
        { name: 'Azure Storage Account Key', regex: /AccountKey=[A-Za-z0-9+\/=]{88}/ },
        { name: 'Azure SAS Token', regex: /[?&]sig=[A-Za-z0-9%+\/=]{40,}/ },

        // ── AI / ML Providers ────────────────
        { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}/ },
        { name: 'OpenAI API Key (Project)', regex: /sk-proj-[a-zA-Z0-9\-_]{40,}/ },
        { name: 'OpenAI API Key (Svc)', regex: /sk-svcacct-[a-zA-Z0-9\-_]{40,}/ },
        { name: 'Anthropic API Key', regex: /sk-ant-[a-zA-Z0-9\-_]{40,}/ },
        { name: 'Hugging Face Token', regex: /hf_[a-zA-Z0-9]{34}/ },
        { name: 'Cohere API Key', regex: /co-[a-zA-Z0-9]{40}/ },
        { name: 'Replicate API Token', regex: /r8_[a-zA-Z0-9]{37}/ },
        { name: 'Google Gemini API Key', regex: /AIzaSy[0-9A-Za-z\-_]{33}/ },

        // ── Payment Providers ────────────────
        { name: 'Stripe Secret Key', regex: /sk_(live|test)_[0-9a-zA-Z_]{10,99}/ },
        { name: 'Stripe Restricted Key', regex: /rk_(live|test)_[0-9a-zA-Z_]{10,99}/ },
        { name: 'Stripe Publishable Key', regex: /pk_(live|test)_[0-9a-zA-Z_]{10,99}/ },
        { name: 'Square Access Token', regex: /sq0atp-[0-9A-Za-z\-_]{10,40}/ },
        { name: 'Square OAuth Secret', regex: /sq0csp-[0-9A-Za-z\-_]{20,50}/ },
        { name: 'PayPal Braintree Token', regex: /access_token\$(production|sandbox)\$[0-9a-zA-Z_$]{10,}/ },

        // ── Version Control & Dev ────────────
        { name: 'GitHub Personal Access Token', regex: /ghp_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub OAuth Token', regex: /gho_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub App Token', regex: /ghu_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub App Server Token', regex: /ghs_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub App Refresh Token', regex: /ghr_[a-zA-Z0-9]{36}/ },
        { name: 'GitHub Fine-grained PAT', regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/ },
        { name: 'GitLab Personal Access Token', regex: /glpat-[0-9A-Za-z\-_]{20}/ },
        { name: 'GitLab Pipeline Trigger Token', regex: /glptt-[0-9a-f]{40}/ },
        { name: 'GitLab Runner Token', regex: /glrt-[0-9A-Za-z\-_]{20}/ },
        { name: 'Bitbucket App Password', regex: /ATBB[a-zA-Z0-9]{32}/ },

        // ── Communication ────────────────────
        { name: 'Slack Bot Token', regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/ },
        { name: 'Slack User Token', regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/ },
        { name: 'Slack App Token', regex: /xapp-[0-9]{1}-[A-Z0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{64}/ },
        { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24}/ },
        { name: 'Discord Bot Token', regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/ },
        { name: 'Discord Webhook', regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/ },
        { name: 'Telegram Bot Token', regex: /\d{8,10}:[A-Za-z0-9_-]{35}/ },
        { name: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/ },
        { name: 'Twilio Account SID', regex: /AC[a-z0-9]{32}/ },

        // ── Email Services ───────────────────
        { name: 'SendGrid API Key', regex: /SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/ },
        { name: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/ },
        { name: 'Mailchimp API Key', regex: /\b[0-9a-f]{32}-us\d{1,2}/ },

        // ── Hosting & Deployment ─────────────
        { name: 'Heroku API Key', regex: /[hH]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/ },
        { name: 'Vercel Access Token', regex: /vercel_[a-zA-Z0-9]{24,}/ },
        { name: 'Netlify Access Token', regex: /nfp_[a-zA-Z0-9]{40}/ },
        { name: 'DigitalOcean PAT', regex: /dop_v1_[a-f0-9]{64}/ },
        { name: 'DigitalOcean OAuth Token', regex: /doo_v1_[a-f0-9]{64}/ },
        { name: 'DigitalOcean Refresh Token', regex: /dor_v1_[a-f0-9]{64}/ },
        { name: 'Render API Key', regex: /rnd_[a-zA-Z0-9]{32}/ },
        { name: 'Railway API Token', regex: /railway_[a-zA-Z0-9]{32,}/ },
        { name: 'Fly.io Access Token', regex: /fo1_[a-zA-Z0-9]{40,}/ },

        // ── Package Registries ───────────────
        { name: 'NPM Access Token', regex: /npm_[a-zA-Z0-9]{36}/ },
        { name: 'PyPI API Token', regex: /pypi-[a-zA-Z0-9\-_]{50,}/ },
        { name: 'NuGet API Key', regex: /oy2[a-z0-9]{43}/ },
        { name: 'RubyGems API Key', regex: /rubygems_[a-f0-9]{48}/ },

        // ── Auth / Tokens ────────────────────
        { name: 'JSON Web Token', regex: /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_.+\/=]+/ },
        { name: 'Bearer Token', regex: /Bearer\s+[a-zA-Z0-9\-._~+\/]{20,}/i },
        { name: 'Basic Auth Credentials', regex: /Basic\s+[a-zA-Z0-9+\/=]{20,}/i },
        { name: 'OAuth Client Secret', regex: /client_secret[=:]\s*['"]?[a-zA-Z0-9\-_]{20,}['"]?/ },

        // ── Cryptographic Keys ───────────────
        { name: 'RSA Private Key', regex: /-----BEGIN RSA PRIVATE KEY-----/ },
        { name: 'EC Private Key', regex: /-----BEGIN EC PRIVATE KEY-----/ },
        { name: 'DSA Private Key', regex: /-----BEGIN DSA PRIVATE KEY-----/ },
        { name: 'OpenSSH Private Key', regex: /-----BEGIN OPENSSH PRIVATE KEY-----/ },
        { name: 'PGP Private Key Block', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/ },
        { name: 'Generic Private Key', regex: /-----BEGIN PRIVATE KEY-----/ },

        // ── Database Connection Strings ──────
        { name: 'PostgreSQL Connection URI', regex: /postgres(?:ql)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/ },
        { name: 'MySQL Connection URI', regex: /mysql:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/ },
        { name: 'MongoDB Connection URI', regex: /mongodb(?:\+srv)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/ },
        { name: 'Redis Connection URI', regex: /redis(?:s)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/ },
        { name: 'AMQP Connection URI', regex: /amqps?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/ },

        // ── Infrastructure / DevOps ──────────
        { name: 'Hashicorp Vault Token', regex: /hvs\.[a-zA-Z0-9\-_]{24,}/ },
        { name: 'Terraform Cloud Token', regex: /\b[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{60,}/ },
        { name: 'Doppler Token', regex: /dp\.st\.[a-zA-Z0-9\-_]{40,}/ },

        // ── E-commerce ───────────────────────
        { name: 'Shopify Access Token', regex: /shpat_[a-fA-F0-9]{32}/ },
        { name: 'Shopify Custom App Token', regex: /shpca_[a-fA-F0-9]{32}/ },
        { name: 'Shopify Private App Token', regex: /shppa_[a-fA-F0-9]{32}/ },
        { name: 'Shopify Shared Secret', regex: /shpss_[a-fA-F0-9]{32}/ },

        // ── Monitoring / Analytics ───────────
        { name: 'Datadog API Key', regex: /dd(?:api|app)key[=:]\s*['"]?[a-f0-9]{32,40}['"]?/i },
        { name: 'Sentry DSN', regex: /https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io\/\d+/ },
        { name: 'New Relic API Key', regex: /NRAK-[A-Z0-9]{27}/ },
        { name: 'Segment Write Key', regex: /sk_[a-zA-Z0-9]{32}/ }, // Also catches some Stripe, matched later

        // ── Supabase / Firebase ──────────────
        { name: 'Supabase Service Role Key', regex: /sbp_[a-f0-9]{40}/ },
        { name: 'Firebase Cloud Messaging', regex: /AAAA[a-zA-Z0-9\-_]{7,}:[a-zA-Z0-9\-_]{140,}/ },

        // ── Misc / Generic ───────────────────
        { name: 'Postman API Key', regex: /PMAK-[a-f0-9]{24}-[a-f0-9]{34}/ },
        { name: 'Okta API Token', regex: /00[a-zA-Z0-9\-_]{40}/ },
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

        // Build whitelist regex set
        const whitelistRegexps = config.whitelistPatterns
            .map((p) => { try { return new RegExp(p); } catch { return null; } })
            .filter((r): r is RegExp => r !== null);

        const isWhitelisted = (value: string): boolean => {
            return whitelistRegexps.some((re) => re.test(value));
        };

        const replaceSecret = (secretValue: string, typeName: string): void => {
            if (isWhitelisted(secretValue)) { return; }

            // Check if this exact secret value was already captured
            let placeholder = '';
            for (const [key, value] of secrets.entries()) {
                if (value === secretValue) {
                    placeholder = key;
                    break;
                }
            }

            if (!placeholder) {
                const uuid = crypto.randomUUID().replace(/-/g, '').substring(0, 12);
                placeholder = `{{SECRET_${uuid}}}`;
                secrets.set(placeholder, secretValue);
                detectedTypes.add(typeName);
            }

            // Use split/join for global replacement (safe for special regex chars in secrets)
            redactedText = redactedText.split(secretValue).join(placeholder);
        };

        // ── Step 1: Built-in Regex Patterns ──
        for (const pattern of this.GLOBAL_PATTERNS) {
            const matches = text.match(pattern.regex);
            if (matches) {
                const uniqueMatches = [...new Set(matches)];
                uniqueMatches.forEach((match) => replaceSecret(match, pattern.name));
            }
        }

        // ── Step 2: User-defined Custom Patterns ──
        for (const custom of config.customPatterns) {
            try {
                const customRegex = new RegExp(custom.regex, 'g');
                const matches = text.match(customRegex);
                if (matches) {
                    const uniqueMatches = [...new Set(matches)];
                    uniqueMatches.forEach((match) => replaceSecret(match, custom.name));
                }
            } catch {
                // Silently skip invalid user-defined patterns
            }
        }

        // ── Step 3: Shannon Entropy Scan ──
        if (config.enableEntropy) {
            // Tokenize the *current* redacted text (after regex replacements)
            const tokens = redactedText.split(/[\s="',`:;()\[\]{}]+/);
            for (const token of tokens) {
                // Skip already-redacted placeholders
                if (token.startsWith('{{SECRET_') && token.endsWith('}}')) { continue; }

                // Skip standard UUIDs (not usually sensitive on their own)
                if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) { continue; }

                // Skip tokens that look like normal words (all lowercase, no digits/symbols mix)
                if (/^[a-z]+$/i.test(token)) { continue; }

                // Skip URLs / file paths that aren't connection strings
                if (/^https?:\/\//.test(token) && !/:\/\/[^:]+:[^@]+@/.test(token)) { continue; }

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

                // Skip camelCase / PascalCase identifiers that are purely alphabetic (no digits).
                // Base64-like secrets almost always contain digits, so tokens with digits are NOT skipped.
                if (/^[a-zA-Z]+$/.test(token) && /[a-z]/.test(token) && /[A-Z]/.test(token)) { continue; }

                // Skip environment variable references (import.meta.env.*, process.env.*)
                if (/^(import\.meta\.env|process\.env)\./i.test(token)) { continue; }

                // Skip well-known character set definitions (base32, base36, hex alphabets)
                if (/^[A-Z0-9]{20,36}$/.test(token) && /^[A-Z2-7]+$|^[0-9A-Z]+$|^[0-9A-F]+$/i.test(token)) { continue; }

                // Skip base64 blobs (>80 chars) — likely source maps, webpack output, not secrets
                if (token.length > 80 && /^[A-Za-z0-9+/=_-]+$/.test(token)) { continue; }

                // Skip webpack module identifiers (e.g. __WEBPACK_IMPORTED_MODULE_)
                if (/__WEBPACK_/.test(token) || /__esModule/.test(token)) { continue; }

                // Skip URL-encoded strings (e.g. C%3A%5CUsers%5C...)
                if (/%[0-9A-Fa-f]{2}/.test(token) && (token.match(/%/g) || []).length >= 3) { continue; }

                // Skip minified CSS/JS fragments (contain lots of escaped sequences)
                if (/\\n|\\t|\\r/.test(token) && token.length > 30) { continue; }

                if (token.length >= config.minimumTokenLength) {
                    const entropy = this.calculateEntropy(token);
                    if (entropy > config.entropyThreshold) {
                        const type = /^[0-9a-fA-F]+$/.test(token)
                            ? 'High Entropy Hex String'
                            : 'High Entropy Token';
                        replaceSecret(token, type);
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

    // Pre-allocated typed array to avoid GC overhead during frequent token scanning.
    // Lazily reset using the actual string characters instead of zeroing all 256 buckets.
    private static readonly _freqArray = new Int32Array(256);

    /**
     * Calculates Shannon entropy of a string.
     * Higher entropy → more random → more likely to be a secret.
     * Typical prose: 2-3 bits. API keys: 4.5-6 bits.
     */
    public static calculateEntropy(str: string): number {
        const len = str.length;
        if (len === 0) { return 0; }

        // Fast path: use a shared Int32Array for ASCII character frequencies
        // to avoid allocating a new array for every single token.
        const frequencies = SecretScanner._freqArray;

        for (let i = 0; i < len; i++) {
            const code = str.charCodeAt(i);
            if (code > 255) {
                // Non-ASCII character — zero out the array we modified so far,
                // then fall back to the Map-based implementation.
                for (let j = 0; j < i; j++) {
                    frequencies[str.charCodeAt(j)] = 0;
                }
                return SecretScanner._calculateEntropyFallback(str);
            }
            frequencies[code]++;
        }

        let entropy = 0;
        // Instead of looping 0-255, loop over the string to calculate entropy
        // and zero out the counts at the same time. This avoids double passes
        // over the full 256 array and perfectly resets state.
        for (let i = 0; i < len; i++) {
            const code = str.charCodeAt(i);
            const count = frequencies[code];
            if (count > 0) {
                const p = count / len;
                entropy -= p * Math.log2(p);
                // Zero it out so it's clean for the next token
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
