"use strict";
// ─────────────────────────────────────────────
//  PromptGuard — inbound threat detection
//
//  SecretScanner protects the OUTBOUND channel: secrets you might send to a
//  model. PromptGuard protects the INBOUND channel: instructions an attacker
//  hid in content your AI assistant is about to read.
//
//  The threat is indirect prompt injection. You ask Copilot/Cursor/Claude to
//  "review this file" or "fix the bug in this dependency". The file contains
//  text addressed not to you but to the model — often in characters your editor
//  does not render. The model reads it, the model obeys it, and it never
//  appears on your screen.
//
//  Three detection families:
//    1. Hidden characters  — deterministic, near-zero false positive. Text that
//       is invisible to a human but fully visible to a tokenizer.
//    2. Injection phrases  — heuristic. Imperative language aimed at a model.
//    3. Homoglyphs         — mixed-script identifiers used to disguise names.
//
//  Fully offline, zero network, no VS Code dependency — same contract as
//  SecretScanner so every Quell surface can use it.
// ─────────────────────────────────────────────
Object.defineProperty(exports, "__esModule", { value: true });
exports.PromptGuard = exports.DEFAULT_GUARD_CONFIG = void 0;
exports.DEFAULT_GUARD_CONFIG = {
    enableUnicodeChecks: true,
    enableInstructionChecks: true,
    enableHomoglyphChecks: true,
    maxFindings: 200,
    whitelistPatterns: [],
};
const SEVERITY_RANK = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3,
};
// ═════════════════════════════════════════════
//  Codepoint classification
// ═════════════════════════════════════════════
/**
 * Unicode Tags block. U+E0020–U+E007E map one-to-one onto printable ASCII
 * (subtract 0xE0000), which makes this a complete, lossless smuggling channel:
 * any ASCII instruction can be carried here and rendered as absolutely nothing.
 * This is the "ASCII smuggling" technique. Its presence in source, docs or a
 * prompt is never legitimate.
 */
function isTagChar(cp) {
    return cp >= 0xe0000 && cp <= 0xe007f;
}
/**
 * Bidirectional embeddings, overrides and isolates. Each one OPENS A SCOPE that
 * reorders everything until it is closed, so a reviewer and a compiler — or a
 * reviewer and a model — can see two entirely different things. This is the
 * Trojan Source attack (CVE-2021-42574).
 */
function isBidiChar(cp) {
    return ((cp >= 0x202a && cp <= 0x202e) || // LRE RLE PDF LRO RLO
        (cp >= 0x2066 && cp <= 0x2069) // LRI RLI FSI PDI
    );
}
/**
 * Directional MARKS, deliberately kept separate from the overrides above.
 *
 * LRM, RLM and ALM nudge the bidi algorithm for the character beside them. They
 * cannot open a reordering scope, so they cannot carry out a Trojan Source
 * attack on their own — and they are entirely routine in real Arabic and Hebrew
 * content, where they are the standard fix for how numbers and Latin fragments
 * render inside RTL text.
 *
 * Treating these as a high-severity attack would light up every properly
 * localised RTL file in a project. That is both a false positive and an
 * exclusion problem: it makes the tool noisiest for the people writing the
 * languages it understands least.
 */
function isBidiMark(cp) {
    return (cp === 0x200e || // LEFT-TO-RIGHT MARK
        cp === 0x200f || // RIGHT-TO-LEFT MARK
        cp === 0x061c // ARABIC LETTER MARK
    );
}
/** Variation selectors. VS1–VS16 plus the supplementary VS17–VS256 block. */
function isVariationSelector(cp) {
    return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}
/**
 * Zero-width and other invisible characters. A run of these encodes binary
 * (each codepoint is a symbol), so they are a smuggling channel too — just a
 * lower-bandwidth one than the tag block.
 */
function isInvisibleChar(cp) {
    return (cp === 0x200b || // ZERO WIDTH SPACE
        cp === 0x200c || // ZERO WIDTH NON-JOINER
        cp === 0x200d || // ZERO WIDTH JOINER
        (cp >= 0x2060 && cp <= 0x2064) || // WORD JOINER + invisible math operators
        (cp >= 0x206a && cp <= 0x206f) || // deprecated format controls
        cp === 0xfeff || // ZERO WIDTH NO-BREAK SPACE / BOM
        cp === 0x00ad || // SOFT HYPHEN
        cp === 0x180e || // MONGOLIAN VOWEL SEPARATOR
        cp === 0x115f || // HANGUL CHOSEONG FILLER
        cp === 0x1160 || // HANGUL JUNGSEONG FILLER
        cp === 0x3164 || // HANGUL FILLER
        cp === 0xffa0 // HALFWIDTH HANGUL FILLER
    );
}
/**
 * Scripts in which ZWNJ (U+200C) and ZWJ (U+200D) are ordinary orthography, not
 * a covert channel.
 *
 * In Persian, ZWNJ is what separates the parts of a compound word: می‌خواهم
 * ("I want") without it becomes میخواهم, a visibly different and incorrect
 * spelling. Sinhala and the Indic scripts use ZWJ to form conjuncts — ශ්‍රී
 * loses its ligature without it. Stripping these does not remove an invisible
 * payload, it misspells someone's language.
 *
 * The same courtesy the emoji check already extends to 👨‍👩‍👧 is owed here.
 */
function isJoinerScript(cp) {
    if (cp === undefined) {
        return false;
    }
    return ((cp >= 0x0600 && cp <= 0x06ff) || // Arabic
        (cp >= 0x0700 && cp <= 0x074f) || // Syriac
        (cp >= 0x0750 && cp <= 0x077f) || // Arabic Supplement
        (cp >= 0x0780 && cp <= 0x07bf) || // Thaana
        (cp >= 0x07c0 && cp <= 0x07ff) || // NKo
        (cp >= 0x0870 && cp <= 0x08ff) || // Arabic Extended-A/B
        (cp >= 0x0900 && cp <= 0x0dff) || // Devanagari … Sinhala
        (cp >= 0x0f00 && cp <= 0x0fff) || // Tibetan
        (cp >= 0x1000 && cp <= 0x109f) || // Myanmar
        (cp >= 0x1780 && cp <= 0x17ff) || // Khmer
        (cp >= 0xfb50 && cp <= 0xfdff) || // Arabic Presentation Forms-A
        (cp >= 0xfe70 && cp <= 0xfeff) // Arabic Presentation Forms-B
    );
}
/**
 * Cyrillic and Greek letters that are visually indistinguishable from a Latin
 * letter in common fonts. Deliberately NOT the whole alphabet: a homoglyph
 * attack depends on the substitute being unnoticeable, so distinctive letters
 * like μ, λ, Δ, ж or щ carry no deception value and appear constantly in
 * legitimate scientific and mathematical text.
 */
const CYRILLIC_CONFUSABLES = /[аеорсухіјѕһԛԝցАВЕКМНОРСТХЅІЈԁ]/;
const GREEK_CONFUSABLES = /[οναρτυχρΑΒΕΖΗΙΚΜΝΟΡΤΥΧϲϹ]/;
const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;
const REGIONAL_INDICATOR = /[\u{1F1E6}-\u{1F1FF}]/u;
function isEmojiBase(cp) {
    if (cp === undefined) {
        return false;
    }
    const s = String.fromCodePoint(cp);
    return PICTOGRAPHIC.test(s) || REGIONAL_INDICATOR.test(s);
}
/** Codepoint immediately before `index`, or undefined at the start of the string. */
function prevCodePoint(text, index) {
    if (index <= 0) {
        return undefined;
    }
    const prevUnit = text.charCodeAt(index - 1);
    // A trailing low surrogate belongs to the high surrogate before it — emoji
    // bases are almost all supplementary-plane, so getting this wrong would
    // misclassify every legitimate emoji sequence.
    if (prevUnit >= 0xdc00 && prevUnit <= 0xdfff && index >= 2) {
        const high = text.charCodeAt(index - 2);
        if (high >= 0xd800 && high <= 0xdbff) {
            return (high - 0xd800) * 0x400 + (prevUnit - 0xdc00) + 0x10000;
        }
    }
    return prevUnit;
}
/**
 * Negation guard for imperative patterns.
 *
 * Security documentation is written almost entirely in the negative — "never
 * share your API keys", "do not commit credentials", "this prevents leaking
 * secrets". Without this, the exfiltration detector rated every such sentence
 * CRITICAL, which meant a README telling you to protect your keys looked
 * identical to an attacker telling a model to steal them. That is the kind of
 * false positive that gets a security feature switched off on day one.
 */
const NEGATED = String.raw `(?<!\b(?:never|not|don't|dont|doesn't|didn't|shouldn't|mustn't|won't|cannot|can't|avoid|avoids|avoiding|refrain|prevent|prevents|preventing|stop|forbid|prohibit|discourage)\b[\s\w'"-]{0,25})`;
/**
 * Heuristic layer. Unlike the hidden-character detectors these CAN fire on
 * legitimate content — a security README, a prompt-engineering tutorial, or
 * Quell's own test fixtures will trip some of them. Severities are set with
 * that in mind: only patterns that are genuinely hard to write by accident are
 * rated high or critical.
 */
const PHRASE_PATTERNS = [
    // ── Model control tokens ─────────────────
    // Special tokens that delimit roles in a chat template. In ordinary source
    // or documentation these are near-inexplicable; in injected content they
    // are an attempt to forge a system turn.
    {
        name: 'Chat Template Token Injection',
        severity: 'critical',
        regex: /<\|(?:im_start|im_end|system|endoftext|eot_id|start_header_id|end_header_id|assistant|user)\|>/i,
        detail: 'Chat-template control token embedded in content. This is an attempt to forge a system or assistant turn inside data the model reads.',
    },
    {
        name: 'Instruction Delimiter Injection',
        severity: 'high',
        regex: /\[(?:\/?INST|\/?SYS)\]|<\/?(?:system|human|assistant)>/i,
        detail: 'Role delimiter used by common chat formats found in content. Injected content is trying to look like part of the conversation structure.',
    },
    // ── Direct instruction override ──────────
    {
        name: 'Instruction Override',
        severity: 'high',
        regex: /\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|preceding|earlier|foregoing|original|system|initial)\s+(?:instructions?|prompts?|rules?|directions?|commands?|guidelines?|constraints?|context)/i,
        detail: 'Imperative telling a model to discard its instructions. This is the canonical prompt-injection opener.',
    },
    {
        name: 'Instruction Override',
        severity: 'high',
        regex: /\bforget\s+(?:everything|all)\s+(?:you|that|above|before|previously)\b/i,
        detail: 'Imperative telling a model to discard prior context.',
    },
    {
        name: 'New Instruction Injection',
        severity: 'high',
        regex: /\b(?:new|updated|revised|real|actual|true)\s+(?:instructions?|system\s+prompt|rules?|directive)s?\s*[:—-]/i,
        detail: 'Content asserting a replacement instruction set, a standard way to hijack an assistant mid-task.',
    },
    // ── Concealment from the user ────────────
    // A legitimate document has no reason to ask a model to hide things from
    // the person operating it. These are the strongest behavioural tells.
    {
        name: 'User Concealment Directive',
        severity: 'critical',
        regex: /\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention\s+(?:this\s+)?to|reveal\s+(?:this\s+)?to|alert|notify|warn|show)\s+(?:the\s+|this\s+to\s+the\s+)?(?:user|human|developer|operator|owner)\b/i,
        detail: 'Content instructing the model to hide its actions from you. Legitimate documentation never asks for this.',
    },
    {
        name: 'User Concealment Directive',
        severity: 'critical',
        regex: /\bwithout\s+(?:telling|informing|notifying|alerting|asking|warning|the\s+knowledge\s+of)\s+(?:the\s+)?(?:user|human|developer|operator)\b/i,
        detail: 'Content instructing the model to act behind your back.',
    },
    {
        name: 'Silent Execution Directive',
        severity: 'high',
        regex: /\b(?:silently|quietly|secretly|covertly|discreetly)\s+(?:run|execute|perform|send|post|add|insert|modify|append|write|install|fetch)\b/i,
        detail: 'Content asking the model to take an action without surfacing it.',
    },
    // ── Data exfiltration directives ─────────
    {
        name: 'Exfiltration Directive',
        severity: 'critical',
        regex: new RegExp(NEGATED +
            String.raw `\b(?:send|post|upload|transmit|exfiltrate|leak|forward|email|publish|share)\s+(?:me\s+|us\s+|the\s+|all\s+|your\s+|any\s+)*(?:contents?\s+of\s+)?(?:\.env\b|env(?:ironment)?\s+(?:vars?|variables?)|credentials?|secrets?|api[\s_-]*keys?|access[\s_-]*tokens?|private[\s_-]*keys?|ssh[\s_-]*keys?|password)`, 'i'),
        detail: 'Content directing the model to send credentials somewhere. This is an exfiltration instruction.',
    },
    {
        name: 'Exfiltration Command',
        severity: 'critical',
        regex: /\b(?:curl|wget|fetch|Invoke-WebRequest|iwr)\b[^\n]{0,200}\$\(\s*(?:cat|printenv|env|type)\b/i,
        detail: 'Shell one-liner that reads local state and sends it over the network, embedded in content the model will read.',
    },
    {
        name: 'Decode-and-Execute Payload',
        severity: 'critical',
        regex: /\bbase64\s+(?:-d|-D|--decode)\b[^\n]{0,120}\|\s*(?:sh|bash|zsh|python[0-9.]*|node|perl|ruby)\b/i,
        detail: 'Encoded payload piped straight into an interpreter. Encoding here exists only to defeat review.',
    },
    {
        // Medium, not critical. Pipe-to-shell is the documented install method for
        // bun, rustup, nvm, Homebrew, deno and uv, so it appears in a great many
        // legitimate READMEs. It is worth noting — it does execute whatever the
        // server returns — but it is not by itself evidence that content is
        // trying to hijack a model, and rating it critical would have fired the
        // agent-facing alarm on ordinary install docs.
        name: 'Remote Script Execution',
        severity: 'medium',
        regex: /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i,
        detail: 'Pipe-to-shell from a remote URL. Common in install instructions, but it executes whatever the server returns, unreviewed — check the host is one you trust.',
    },
    // ── System prompt extraction ─────────────
    {
        name: 'System Prompt Extraction',
        severity: 'high',
        regex: /\b(?:reveal|repeat|print|output|echo|show|display|disclose|summar(?:ise|ize))\s+(?:me\s+)?(?:your|the|all)\s+(?:system\s+prompt|initial\s+(?:prompt|instructions?)|instructions?|prompt\s+text|guidelines|configuration)/i,
        detail: 'Attempt to make the model disclose its own instructions, usually reconnaissance before a targeted attack.',
    },
    // ── Model-directed address ───────────────
    // Deliberately CASE-SENSITIVE. Injected content shouts, because the attacker
    // wants the model to weight the line heavily. Ordinary prose does not, and
    // matching case-insensitively turned sentences like "the warning handed back
    // to the model" and "note: 'Applies to AI'" into high-severity findings —
    // both real false positives found by running this scanner over its own repo.
    {
        name: 'AI-Directed Instruction',
        severity: 'high',
        regex: /\b(?:IMPORTANT|ATTENTION|URGENT|WARNING|NOTICE)\b\s*[:!-]{0,2}[^\n]{0,30}?\b(?:for|to)\s+(?:the\s+)?(?:AI|LLM|assistant|agent|model|Claude|Copilot|Cursor|ChatGPT|GPT|Gemini|Codex)\b/,
        detail: 'Content addressed to the assistant rather than the reader. Data should never speak to the model.',
    },
    {
        name: 'AI-Directed Instruction',
        severity: 'high',
        regex: /\b(?:NOTE|MESSAGE|INSTRUCTIONS?|DIRECTIVE)\s+(?:TO|FOR)\s+(?:THE\s+)?(?:AI|ASSISTANT|LLM|AGENT|MODEL|CLAUDE|COPILOT|CURSOR)\b/,
        detail: 'A header addressing the assistant directly. Legitimate documentation speaks to the reader, not the tool.',
    },
    {
        name: 'AI-Directed Instruction',
        severity: 'medium',
        regex: /\b(?:AI|LLM|assistant|agent|Claude|Copilot|Cursor|ChatGPT|Gemini|Codex)\s*[,:]\s*(?:please\s+)?(?:ignore|disregard|stop|instead|note\s+that|you\s+must|you\s+should|do\s+not|always)\b/i,
        detail: 'Content directly addressing an assistant by name with an imperative.',
    },
    // ── Role reassignment / jailbreak ────────
    {
        name: 'Role Reassignment',
        severity: 'medium',
        regex: /\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|in|the)\b|\bfrom\s+now\s+on,?\s+you\s+(?:will|must|shall|are)\b|\bact\s+as\s+(?:if\s+you\s+are\s+)?(?:a|an|though)\b/i,
        detail: 'Attempt to reassign the assistant a new persona or operating mode.',
    },
    {
        name: 'Safety Bypass Attempt',
        severity: 'high',
        regex: /\b(?:developer|debug|god|admin|root|maintenance|unrestricted|DAN)\s+mode\s+(?:enabled?|activated?|on\b)|\b(?:disable|turn\s+off|suspend|ignore)\s+(?:your\s+|all\s+)?(?:safety|security|content)\s+(?:filters?|guidelines?|checks?|restrictions?|policies)/i,
        detail: 'Attempt to switch the model into a fictional unrestricted mode.',
    },
    // ── Supply-chain / dependency tampering ──
    {
        name: 'Dependency Tampering Directive',
        severity: 'high',
        regex: /\b(?:add|install|include|require|import)\s+(?:the\s+)?(?:package|dependency|module|library)\s+[`'"][^`'"\n]{2,60}[`'"]\s*(?:to\s+(?:package\.json|requirements\.txt|the\s+project)|before\s+(?:you\s+)?(?:continue|proceed|answer))/i,
        detail: 'Content instructing the assistant to add a dependency. A classic route to slopsquatting and supply-chain compromise.',
    },
];
// ═════════════════════════════════════════════
//  PromptGuard
// ═════════════════════════════════════════════
class PromptGuard {
    /** Number of built-in instruction-phrase patterns. */
    static get phrasePatternCount() {
        return PHRASE_PATTERNS.length;
    }
    /**
     * Scans text for inbound injection threats.
     *
     * @param text   - Content about to be given to (or received from) a model
     * @param config - Optional guard config
     */
    static scan(text, config = exports.DEFAULT_GUARD_CONFIG) {
        const findings = [];
        let truncated = false;
        const whitelist = config.whitelistPatterns
            .map((p) => { try {
            return new RegExp(p);
        }
        catch {
            return null;
        } })
            .filter((r) => r !== null);
        const isWhitelisted = (value) => whitelist.some((re) => re.test(value));
        // The cap bounds work on hostile input, but it must never cost us the
        // WORST finding. Detectors run in a fixed order, so a naive "stop at N"
        // would let a minified file's few hundred zero-width mediums fill the
        // buffer and silently discard a critical exfiltration directive found
        // later in the same file. Once full we instead displace the
        // lowest-severity finding held, so the buffer always retains the most
        // severe results regardless of discovery order.
        // Lowest severity rank currently held, so a candidate that cannot possibly
        // displace anything is rejected in O(1) rather than triggering a scan of
        // the buffer. Once every slot holds a critical this short-circuits every
        // remaining push, which is what keeps a pathological input cheap.
        let minRankHeld = Infinity;
        const push = (f) => {
            if (isWhitelisted(f.raw)) {
                return true;
            }
            if (findings.length < config.maxFindings) {
                findings.push(f);
                minRankHeld = Math.min(minRankHeld, SEVERITY_RANK[f.severity]);
                return true;
            }
            truncated = true;
            if (SEVERITY_RANK[f.severity] <= minRankHeld) {
                return true;
            }
            let weakestIndex = 0;
            for (let i = 1; i < findings.length; i++) {
                if (SEVERITY_RANK[findings[i].severity] < SEVERITY_RANK[findings[weakestIndex].severity]) {
                    weakestIndex = i;
                }
            }
            findings[weakestIndex] = f;
            minRankHeld = SEVERITY_RANK[findings[0].severity];
            for (let i = 1; i < findings.length; i++) {
                const r = SEVERITY_RANK[findings[i].severity];
                if (r < minRankHeld) {
                    minRankHeld = r;
                }
            }
            // Keep scanning: a later region of the file may hold something worse.
            return true;
        };
        if (config.enableUnicodeChecks) {
            this.scanHiddenCharacters(text, push);
        }
        if (config.enableInstructionChecks) {
            this.scanPhrases(text, push);
        }
        if (config.enableHomoglyphChecks) {
            this.scanHomoglyphs(text, push);
        }
        findings.sort((a, b) => {
            const bySeverity = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
            return bySeverity !== 0 ? bySeverity : a.index - b.index;
        });
        const { text: cleanedText, removed } = this.strip(text);
        let highestSeverity = null;
        for (const f of findings) {
            if (highestSeverity === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[highestSeverity]) {
                highestSeverity = f.severity;
            }
        }
        return { findings, highestSeverity, cleanedText, strippedCount: removed, truncated };
    }
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
    static strip(text) {
        let out = '';
        let removed = 0;
        let i = 0;
        while (i < text.length) {
            const cp = text.codePointAt(i);
            const size = cp > 0xffff ? 2 : 1;
            const family = this.hiddenFamilyAt(text, i, cp);
            if (family !== null && family !== 'bidi-mark' && family !== 'joiner') {
                removed += size;
            }
            else {
                out += text.slice(i, i + size);
            }
            i += size;
        }
        return { text: out, removed };
    }
    /**
     * Decodes a Unicode Tags-block run back to the ASCII it carries.
     * Non-tag characters are ignored.
     */
    static decodeTagPayload(raw) {
        let out = '';
        for (const ch of raw) {
            const cp = ch.codePointAt(0);
            if (isTagChar(cp)) {
                const ascii = cp - 0xe0000;
                // U+E0001 is LANGUAGE TAG, U+E007F is CANCEL TAG — both structural.
                if (ascii >= 0x20 && ascii <= 0x7e) {
                    out += String.fromCharCode(ascii);
                }
            }
        }
        return out;
    }
    /**
     * Classifies the codepoint at `index`, or returns null when it is ordinary
     * visible text or a legitimate emoji component.
     *
     * Single source of truth for both the scanner and `strip()`, so the two can
     * never disagree about what counts as hidden.
     */
    static hiddenFamilyAt(text, index, cp) {
        if (isTagChar(cp)) {
            return 'tag';
        }
        if (isBidiChar(cp)) {
            return 'bidi';
        }
        if (isBidiMark(cp)) {
            return 'bidi-mark';
        }
        if (isVariationSelector(cp)) {
            // VS15/VS16 after a pictographic base is ordinary emoji presentation.
            return isEmojiBase(prevCodePoint(text, index)) ? null : 'variation';
        }
        if (cp === 0x200c || cp === 0x200d) {
            const prev = prevCodePoint(text, index);
            const next = text.codePointAt(index + 1);
            // ZWJ between two pictographs is a legitimate emoji sequence
            // (family, profession, flag modifiers).
            if (cp === 0x200d && isEmojiBase(prev) && isEmojiBase(next)) {
                return null;
            }
            // Between two characters of a script that requires joiners, this is
            // spelling, not smuggling.
            if (isJoinerScript(prev) && isJoinerScript(next)) {
                return 'joiner';
            }
            return 'invisible';
        }
        if (cp === 0xfeff) {
            // A BOM at position 0 is a legitimate file encoding marker.
            return index === 0 ? null : 'invisible';
        }
        return isInvisibleChar(cp) ? 'invisible' : null;
    }
    // ── Detector: hidden characters ──────────
    static scanHiddenCharacters(text, push) {
        let i = 0;
        while (i < text.length) {
            const cp = text.codePointAt(i);
            const size = cp > 0xffff ? 2 : 1;
            const family = this.hiddenFamilyAt(text, i, cp);
            if (family === null) {
                i += size;
                continue;
            }
            // Group the maximal run of same-family hidden characters into one
            // finding — a smuggled payload is hundreds of codepoints long and
            // must not become hundreds of squiggles.
            const start = i;
            let j = i;
            while (j < text.length) {
                const c = text.codePointAt(j);
                const s = c > 0xffff ? 2 : 1;
                if (this.hiddenFamilyAt(text, j, c) !== family) {
                    break;
                }
                j += s;
            }
            const raw = text.slice(start, j);
            if (!this.emitHiddenFinding(family, raw, start, push)) {
                return;
            }
            i = j;
        }
    }
    static emitHiddenFinding(family, raw, index, push) {
        const count = Array.from(raw).length;
        switch (family) {
            case 'tag': {
                const decoded = this.decodeTagPayload(raw);
                return push({
                    type: 'Unicode Tag Smuggling',
                    severity: 'critical',
                    index,
                    length: raw.length,
                    raw,
                    detail: `${count} character(s) from the Unicode Tags block (U+E0000–U+E007F). These render as nothing ` +
                        `but a model reads them as plain ASCII. There is no legitimate use for this in source code, ` +
                        `documentation, or a prompt.`,
                    decoded: decoded.length > 0 ? decoded : undefined,
                });
            }
            case 'bidi':
                return push({
                    type: 'Bidirectional Text Override',
                    severity: 'high',
                    index,
                    length: raw.length,
                    raw,
                    detail: `${count} bidirectional override/isolate character(s). These open a scope that reorders how text ` +
                        `displays without changing what a compiler or model actually consumes, so what you read is not ` +
                        `what runs (Trojan Source, CVE-2021-42574).`,
                });
            case 'joiner':
                return push({
                    type: 'Script Joiner',
                    severity: 'low',
                    index,
                    length: raw.length,
                    raw,
                    detail: `${count} zero-width joiner/non-joiner character(s) between characters of a script that requires ` +
                        `them. This is ordinary spelling in Persian, Sinhala and the Indic scripts, not a hidden payload. ` +
                        `Noted only so the count is not surprising — these are never stripped.`,
                });
            case 'bidi-mark':
                return push({
                    type: 'Bidirectional Mark',
                    severity: 'low',
                    index,
                    length: raw.length,
                    raw,
                    detail: `${count} directional mark(s) (LRM/RLM/ALM). These are normal in Arabic and Hebrew text, where ` +
                        `they control how numbers and Latin fragments render, and they cannot reorder a span on their ` +
                        `own. Noted for completeness only — no action needed unless you did not expect RTL content here.`,
                });
            case 'variation':
                return push({
                    type: 'Variation Selector Smuggling',
                    severity: 'high',
                    index,
                    length: raw.length,
                    raw,
                    detail: `${count} variation selector(s) not attached to an emoji. Each one carries a byte, so a run of ` +
                        `them is a covert data channel hiding in apparently-empty space.`,
                });
            case 'invisible':
            default:
                return push({
                    type: 'Invisible Character Sequence',
                    severity: count >= 8 ? 'high' : 'medium',
                    index,
                    length: raw.length,
                    raw,
                    detail: `${count} zero-width or invisible character(s). ` +
                        (count >= 8
                            ? `A run this long is a payload, not a typo — invisible characters encode data one symbol at a time.`
                            : `Often accidental (copy-paste from a rich-text source), but also used to hide instructions or break up keywords to evade filters.`),
                });
        }
    }
    // ── Detector: instruction phrases ────────
    static scanPhrases(text, push) {
        for (const pattern of PHRASE_PATTERNS) {
            const re = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
            let match;
            while ((match = re.exec(text)) !== null) {
                if (match[0].length === 0) {
                    re.lastIndex++;
                    continue;
                }
                const ok = push({
                    type: pattern.name,
                    severity: pattern.severity,
                    index: match.index,
                    length: match[0].length,
                    raw: match[0],
                    detail: pattern.detail,
                });
                if (!ok) {
                    return;
                }
            }
        }
    }
    // ── Detector: homoglyphs ─────────────────
    static scanHomoglyphs(text, push) {
        // Word-ish runs that contain at least one ASCII Latin letter.
        const WORD = /[A-Za-zͰ-ϿЀ-ӿԀ-ԯ]{4,}/g;
        let match;
        while ((match = WORD.exec(text)) !== null) {
            const word = match[0];
            const hasLatin = /[A-Za-z]/.test(word);
            // Only characters that genuinely LOOK like a Latin letter are worth
            // flagging. Matching any Cyrillic or Greek codepoint meant ordinary
            // scientific and mathematical writing — μsec, ΔTemp, λ-calculus —
            // was reported as a disguise attempt. A homoglyph attack only works
            // if the substitute is visually indistinguishable.
            const cyrillic = CYRILLIC_CONFUSABLES.test(word);
            const greek = GREEK_CONFUSABLES.test(word);
            if (!hasLatin || (!cyrillic && !greek)) {
                continue;
            }
            const script = cyrillic ? 'Cyrillic' : 'Greek';
            const ok = push({
                type: 'Homoglyph / Mixed Script',
                severity: 'medium',
                index: match.index,
                length: word.length,
                raw: word,
                detail: `"${word}" mixes Latin with ${script} characters that look identical to Latin ones. ` +
                    `Used to disguise a package name, domain, or identifier as a familiar one.`,
            });
            if (!ok) {
                return;
            }
        }
    }
}
exports.PromptGuard = PromptGuard;
//# sourceMappingURL=PromptGuard.js.map