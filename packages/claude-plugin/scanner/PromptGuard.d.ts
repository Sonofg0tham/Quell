export type InjectionSeverity = 'critical' | 'high' | 'medium' | 'low';
export interface InjectionFinding {
    /** Human-readable detector name, e.g. 'Unicode Tag Smuggling' */
    type: string;
    severity: InjectionSeverity;
    /** UTF-16 offset into the scanned text (directly usable for editor ranges) */
    index: number;
    /** Length in UTF-16 code units */
    length: number;
    /** The offending substring, exactly as it appeared */
    raw: string;
    /** What this is and why it matters */
    detail: string;
    /**
     * For smuggling channels that carry a recoverable payload, the decoded
     * cleartext. This is the whole point: it turns "there is something hidden
     * here" into "here is what it says".
     */
    decoded?: string;
}
export interface GuardConfig {
    /** Hidden/invisible/bidi character detection. Deterministic. */
    enableUnicodeChecks: boolean;
    /** Natural-language instruction-override detection. Heuristic. */
    enableInstructionChecks: boolean;
    /** Mixed-script (Cyrillic/Greek in Latin words) detection. */
    enableHomoglyphChecks: boolean;
    /** Stop after this many findings, to bound work on hostile input. */
    maxFindings: number;
    /** Regexes for content that should never be flagged. */
    whitelistPatterns: string[];
}
export declare const DEFAULT_GUARD_CONFIG: GuardConfig;
export interface GuardResult {
    findings: InjectionFinding[];
    /** Highest severity present, or null when clean. */
    highestSeverity: InjectionSeverity | null;
    /** Text with every hidden/invisible character removed. Safe to hand to a model. */
    cleanedText: string;
    /** How many UTF-16 code units `cleanedText` dropped. */
    strippedCount: number;
    /** True when findings were truncated by maxFindings. */
    truncated: boolean;
}
export declare class PromptGuard {
    /** Number of built-in instruction-phrase patterns. */
    static get phrasePatternCount(): number;
    /**
     * Scans text for inbound injection threats.
     *
     * @param text   - Content about to be given to (or received from) a model
     * @param config - Optional guard config
     */
    static scan(text: string, config?: GuardConfig): GuardResult;
    /**
     * Removes hidden characters while preserving legitimate emoji sequences
     * (ZWJ families, flags, VS16 presentation selectors), a leading BOM, and
     * bidirectional MARKS. Returns the cleaned text and how many code units
     * were dropped.
     *
     * This is the remediation for a smuggling finding, and it rests on one
     * promise: the visible meaning of the text does not change, only the covert
     * channel goes. Directional marks are excluded precisely because removing
     * them WOULD change rendering — an Arabic string loses the fix that makes
     * its numbers display correctly. A "safe" cleanup that quietly corrupts
     * someone's localisation is not safe.
     */
    static strip(text: string): {
        text: string;
        removed: number;
    };
    /**
     * Decodes a Unicode Tags-block run back to the ASCII it carries.
     * Non-tag characters are ignored.
     */
    static decodeTagPayload(raw: string): string;
    /**
     * Classifies the codepoint at `index`, or returns null when it is ordinary
     * visible text or a legitimate emoji component.
     *
     * Single source of truth for both the scanner and `strip()`, so the two can
     * never disagree about what counts as hidden.
     */
    private static hiddenFamilyAt;
    private static scanHiddenCharacters;
    private static emitHiddenFinding;
    private static scanPhrases;
    private static scanHomoglyphs;
}
//# sourceMappingURL=PromptGuard.d.ts.map