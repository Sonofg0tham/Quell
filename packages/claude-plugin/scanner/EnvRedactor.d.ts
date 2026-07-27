/** The marker substituted for every value. */
export declare const ENV_MASK = "<HIDDEN_BY_QUELL>";
export declare class EnvRedactor {
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
    static redact(fileContent: string): string;
    /**
     * Masks the value of an assignment that appears inside a comment, leaving
     * the comment marker and key name intact. Ordinary prose comments are
     * returned unchanged.
     */
    private static maskCommentedAssignment;
    /**
     * True when a captured name is plausibly an environment variable name
     * rather than key material that happens to contain an `=`.
     *
     * An unquoted PEM body line such as `MIIEpAIBAAKCAQEAy8Db...5=` parses as
     * `KEY=` with an empty value, so without this check the entire base64 blob
     * prints as if it were a variable name. Base64 is long and mixes case with
     * digits; real env names are short and conventionally ALL_CAPS or snake_case.
     */
    static looksLikeEnvKey(key: string): boolean;
    /** True when `s` contains an unescaped occurrence of `quote`. */
    private static closesQuote;
}
//# sourceMappingURL=EnvRedactor.d.ts.map