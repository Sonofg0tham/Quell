"use strict";
// ─────────────────────────────────────────────
//  EnvRedactor — masks values in .env content
//
//  Split out of the VS Code layer because it is pure text processing, and
//  because it guards the single most sensitive path in the product: the feature
//  that shares your configuration with a model. Living here means it is covered
//  by the standalone test suite that runs in CI.
//
//  The design rule is fail-closed. A line this parser does not fully understand
//  is withheld, never echoed. Printing an unparsed line is how a private key
//  ends up in a chat transcript.
// ─────────────────────────────────────────────
Object.defineProperty(exports, "__esModule", { value: true });
exports.EnvRedactor = exports.ENV_MASK = void 0;
/** The marker substituted for every value. */
exports.ENV_MASK = '<HIDDEN_BY_QUELL>';
class EnvRedactor {
    /**
     * Masks the values in a single .env file's content, preserving key names,
     * blank lines and comments so the shape of the configuration survives.
     *
     * Handles the cases a naive `indexOf('=')` split gets dangerously wrong:
     *
     *  - **Quoted multi-line values.** dotenv allows `KEY="line1\nline2"`, which
     *    is exactly how people paste PEM private keys and service-account JSON
     *    into a .env. Every continuation line must be swallowed, not echoed.
     *  - **Bare base64 continuation lines.** A PEM body line like
     *    `MIIEpAIB...5=` contains an `=`, so a naive parser treats the whole
     *    block of key material as a "key name" and prints it in clear.
     *  - **Unparseable lines.** Withheld. A line we cannot prove is safe is not
     *    a line we print.
     */
    static redact(fileContent) {
        const lines = fileContent.split(/\r?\n/);
        let out = '';
        // Set while inside an unterminated quoted value; holds the quote char.
        let openQuote = null;
        for (const line of lines) {
            // ── Inside a multi-line quoted value: emit nothing, look for the end ──
            if (openQuote) {
                if (this.closesQuote(line, openQuote)) {
                    openQuote = null;
                }
                continue;
            }
            const trimmed = line.trim();
            if (!trimmed) {
                out += line + '\n';
                continue;
            }
            // Comments carry structure, so they are preserved — but a commented-out
            // assignment is one of the most common places a real credential sits
            // in a .env ("# OLD_API_KEY=sk_live_..."). Keep the prose, mask the value.
            if (trimmed.startsWith('#')) {
                out += this.maskCommentedAssignment(line) + '\n';
                continue;
            }
            const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$/.exec(trimmed);
            if (!match || !this.looksLikeEnvKey(match[1])) {
                out += `# ${exports.ENV_MASK} (unparsed line withheld)\n`;
                continue;
            }
            const key = match[1];
            const value = match[2].trim();
            // A value that opens a quote without closing it continues onto the next line.
            const quote = value.charAt(0);
            if ((quote === '"' || quote === "'" || quote === '`') && !this.closesQuote(value.slice(1), quote)) {
                openQuote = quote;
            }
            out += `${key}=${exports.ENV_MASK}\n`;
        }
        return out;
    }
    /**
     * Masks the value of an assignment that appears inside a comment, leaving
     * the comment marker and key name intact. Ordinary prose comments are
     * returned unchanged.
     */
    static maskCommentedAssignment(line) {
        const match = /^(\s*#+\s*)((?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(\S.*)$/.exec(line);
        if (!match) {
            return line;
        }
        const key = match[2].replace(/^export\s+/, '');
        if (!this.looksLikeEnvKey(key)) {
            return `# ${exports.ENV_MASK} (unparsed comment withheld)`;
        }
        return `${match[1]}${match[2]}=${exports.ENV_MASK}`;
    }
    /**
     * True when a captured name is plausibly an environment variable name
     * rather than key material that happens to contain an `=`.
     *
     * An unquoted PEM body line such as `MIIEpAIBAAKCAQEAy8Db...5=` parses as
     * `KEY=` with an empty value, so without this check the entire base64 blob
     * prints as if it were a variable name. Base64 is long and mixes case with
     * digits; real env names are short and conventionally ALL_CAPS or snake_case.
     */
    static looksLikeEnvKey(key) {
        if (key.length > 64) {
            return false;
        }
        const long = key.length >= 20;
        const mixedAlnum = /[a-z]/.test(key) && /[A-Z]/.test(key) && /[0-9]/.test(key);
        return !(long && mixedAlnum);
    }
    /** True when `s` contains an unescaped occurrence of `quote`. */
    static closesQuote(s, quote) {
        for (let i = 0; i < s.length; i++) {
            if (s[i] === '\\') {
                i++;
                continue;
            }
            if (s[i] === quote) {
                return true;
            }
        }
        return false;
    }
}
exports.EnvRedactor = EnvRedactor;
//# sourceMappingURL=EnvRedactor.js.map