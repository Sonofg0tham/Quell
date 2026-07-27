import * as fs from 'fs';
import * as path from 'path';

// ─────────────────────────────────────────────────────────────
//  AiShieldManager
//  Manages AI-IDE ignore files to prevent secret file indexing.
//  Works with Cursor, Windsurf, Antigravity, Aider, and more.
// ─────────────────────────────────────────────────────────────

const MARKER_START = '# Quell AI Shield (auto-managed — do not edit this block)';
const MARKER_END = '# End Quell AI Shield';

/** Glob patterns injected into AI ignore files */
const SHIELD_PATTERNS = [
    '**/.env',
    '**/.env.*',
    '!**/.env.example',
    '!**/.env.sample',
    '!**/.env.template',
    '**/secrets.*',
    '**/secret.*',
    '**/*.pem',
    '**/*.key',
    '**/*.p12',
    '**/*.pfx',
    '**/credentials.json',
    '**/credentials.yml',
    '**/credentials.yaml',
    '**/serviceAccountKey.json',
    '**/*_rsa',
    '**/*_dsa',
    '**/*_ecdsa',
    '**/*_ed25519',
    '**/.netrc',
    '**/.npmrc',
    '**/.pypirc',
    '**/.git-credentials',
    '**/config/secrets*',
    '**/vault.*',
    // MCP server configuration. These routinely carry API tokens inline, because
    // most server install instructions tell you to paste them straight into the
    // `env` block — GitGuardian counted tens of thousands of live credentials
    // leaked from these files in 2025 alone.
    '**/.mcp.json',
    '**/mcp.json',
    '**/.cursor/mcp.json',
    '**/.vscode/mcp.json',
    '**/.windsurf/mcp_config.json',
    '**/claude_desktop_config.json',
].join('\n');

/**
 * AI IDE ignore file names.
 *
 * Two deliberate omissions:
 *  - `.claudeignore` does not exist. Claude Code excludes paths via a
 *    `permissions.deny` list in its own settings file, not an ignore file.
 *  - `.copilotignore` does not exist either. GitHub Copilot has no
 *    individual-developer exclusion mechanism at all; content exclusion is an
 *    org-level Business/Enterprise feature.
 * Writing invented filenames would imply protection that is not there.
 */
const IGNORE_FILES = [
    '.cursorignore',           // Cursor
    '.cursorindexingignore',   // Cursor — indexing-only exclusion, separate file
    '.codeiumignore',          // Windsurf / Codeium (the filename Cascade honours)
    '.windsurfignore',         // kept belt-and-braces; older Windsurf builds
    '.aiexclude',              // Antigravity / Gemini Code Assist (Google's documented file)
    '.antigravityignore',      // kept belt-and-braces
    '.geminiignore',           // Gemini CLI
    '.aiderignore',            // Aider
    '.clineignore',            // Cline
    '.rooignore',              // Roo Code
    '.augmentignore',          // Augment
    '.aiignore',               // generic / JetBrains AI
    '.llmignore',              // emerging vendor-neutral convention
];

/**
 * How much protection each ignore file actually buys, so the UI can tell the
 * truth rather than implying a guarantee.
 *
 * Every one of these is best-effort. The important caveat is that agent and
 * terminal modes generally bypass ignore files entirely by shelling out to
 * `cat` — the file is excluded from indexing, not from a determined agent.
 */
export interface ShieldCoverage {
    tool: string;
    file: string;
    /** Does the ignore file stop normal context/indexing? */
    blocksIndexing: boolean;
    /** Can the tool's agent/terminal mode read the file anyway via shell? */
    terminalBypass: boolean;
    note: string;
}

export const SHIELD_COVERAGE: ShieldCoverage[] = [
    { tool: 'Cursor', file: '.cursorignore', blocksIndexing: true, terminalBypass: true, note: 'Direct @-references and agent terminal commands can still reach the file.' },
    { tool: 'Windsurf', file: '.codeiumignore', blocksIndexing: true, terminalBypass: true, note: 'Cascade honours the file; its terminal does not.' },
    { tool: 'Gemini CLI', file: '.geminiignore', blocksIndexing: true, terminalBypass: true, note: 'Shell tool calls bypass the ignore list.' },
    { tool: 'Antigravity / Code Assist', file: '.aiexclude', blocksIndexing: true, terminalBypass: true, note: 'Documented exclusion for indexing only.' },
    { tool: 'JetBrains AI', file: '.aiignore', blocksIndexing: true, terminalBypass: true, note: 'Applies to AI features, not to a terminal.' },
    { tool: 'Aider', file: '.aiderignore', blocksIndexing: true, terminalBypass: true, note: 'Excludes files from the repo map.' },
    { tool: 'Cline / Roo', file: '.clineignore / .rooignore', blocksIndexing: true, terminalBypass: true, note: 'Excluded from context; command execution is unrestricted.' },
    { tool: 'GitHub Copilot', file: '— none —', blocksIndexing: false, terminalBypass: true, note: 'No per-developer exclusion exists. Content exclusion is org-level only and does not apply in Agent or Edit mode.' },
    { tool: 'Claude Code', file: '.claude/settings.json', blocksIndexing: true, terminalBypass: false, note: 'The only mechanism here that also blocks shell reads — a deny rule stops `cat .env`, not just indexing. Written by merge, so your own settings and deny rules are preserved.' },
];

/**
 * Deny rules written into the workspace's Claude Code settings.
 *
 * Every other entry in IGNORE_FILES is context exclusion: it keeps a file out of
 * the index, but an agent that decides to run `cat .env` still gets it. Claude
 * Code's deny list is the one mechanism in this product that also stops the
 * shell read, so it is the only place the shield is more than best-effort.
 *
 * A `Read` deny also covers `Edit` on the same path.
 */
const CLAUDE_DENY_RULES = [
    'Read(.env)',
    'Read(**/.env)',
    'Read(**/.env.*)',
    'Read(**/*.pem)',
    'Read(**/*.key)',
    'Read(**/*.p12)',
    'Read(**/*.pfx)',
    'Read(**/id_rsa)',
    'Read(**/id_dsa)',
    'Read(**/id_ecdsa)',
    'Read(**/id_ed25519)',
    'Read(**/credentials)',
    'Read(**/credentials.json)',
    'Read(**/serviceAccountKey.json)',
    'Read(**/.npmrc)',
    'Read(**/.pypirc)',
    'Read(**/.netrc)',
    'Read(**/.git-credentials)',
    'Read(**/.mcp.json)',
    'Read(**/mcp.json)',
];

const CLAUDE_SETTINGS_REL = ['.claude', 'settings.json'];

export class AiShieldManager {
    private static _enabled = false;

    // ── Public API ────────────────────────────────

    static get isEnabled(): boolean {
        return this._enabled;
    }

    /**
     * Inject the Quell block into all known AI ignore files.
     * Creates the file if it doesn't exist.
     * Returns the number of files that were newly created/updated.
     */
    static enable(workspacePath: string): number {
        let count = 0;
        for (const file of IGNORE_FILES) {
            if (this._inject(path.join(workspacePath, file))) { count++; }
        }
        if (this._writeClaudeDeny(workspacePath, true)) { count++; }
        this._enabled = true;
        return count;
    }

    /**
     * Remove the Quell block from all AI ignore files.
     * Leaves the file in place even if it is now empty — Quell never deletes
     * files it did not exclusively create.
     */
    static disable(workspacePath: string): void {
        for (const file of IGNORE_FILES) {
            this._remove(path.join(workspacePath, file));
        }
        this._writeClaudeDeny(workspacePath, false);
        this._enabled = false;
    }

    /**
     * Detect whether the AI shield is currently active for the workspace.
     * Updates internal state as a side effect.
     */
    static check(workspacePath: string): boolean {
        for (const file of IGNORE_FILES) {
            const filePath = path.join(workspacePath, file);
            try {
                const content = fs.readFileSync(filePath, 'utf-8');
                if (content.includes(MARKER_START)) {
                    this._enabled = true;
                    return true;
                }
            } catch { /* absent or unreadable — try the next one */ }
        }

        try {
            const raw = fs.readFileSync(path.join(workspacePath, ...CLAUDE_SETTINGS_REL), 'utf-8');
            if (raw.includes(CLAUDE_DENY_RULES[0])) {
                this._enabled = true;
                return true;
            }
        } catch { /* no Claude settings in this workspace */ }

        this._enabled = false;
        return false;
    }

    // ── Private Helpers ───────────────────────────

    /**
     * Adds or removes Quell's deny rules in the workspace's Claude Code settings.
     *
     * Unlike every other ignore file, this one is shared configuration the user
     * may already have populated, so it needs merge semantics rather than the
     * marker-block append used elsewhere. The rules are therefore:
     *
     *  - Only Quell's own rule strings are ever added or removed. Anything else
     *    in the file, including the user's own deny entries, is left untouched.
     *  - Unparseable JSON aborts. Overwriting a settings file we cannot read
     *    would destroy configuration to enforce a preference, which is a far
     *    worse outcome than the shield not covering one tool.
     *  - Key order and unrelated sections survive, because we mutate the parsed
     *    object rather than rewriting from a template.
     *
     * Returns true when the file was changed.
     */
    private static _writeClaudeDeny(workspacePath: string, enable: boolean): boolean {
        const filePath = path.join(workspacePath, ...CLAUDE_SETTINGS_REL);

        let settings: Record<string, unknown> = {};
        let existed = false;

        try {
            const raw = fs.readFileSync(filePath, 'utf-8');
            existed = true;
            const trimmed = raw.trim();
            if (trimmed.length > 0) {
                const parsed = JSON.parse(trimmed);
                if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
                    return false; // Not a settings object — leave it alone.
                }
                settings = parsed as Record<string, unknown>;
            }
        } catch (err) {
            // ENOENT is fine when enabling (we create it). Anything else — most
            // importantly a JSON syntax error — means hands off.
            const code = (err as NodeJS.ErrnoException)?.code;
            if (code !== 'ENOENT') { return false; }
            if (!enable) { return false; } // Nothing to remove from a file that isn't there.
        }

        const permissions = (typeof settings.permissions === 'object' && settings.permissions !== null && !Array.isArray(settings.permissions))
            ? settings.permissions as Record<string, unknown>
            : {};

        const currentDeny: string[] = Array.isArray(permissions.deny)
            ? (permissions.deny as unknown[]).filter((r): r is string => typeof r === 'string')
            : [];

        const ours = new Set(CLAUDE_DENY_RULES);
        const theirs = currentDeny.filter((r) => !ours.has(r));
        const nextDeny = enable ? [...theirs, ...CLAUDE_DENY_RULES] : theirs;

        // No-op check, so enabling twice does not rewrite the file.
        if (currentDeny.length === nextDeny.length && currentDeny.every((r, i) => r === nextDeny[i])) {
            return false;
        }

        if (!enable && nextDeny.length === 0 && !('deny' in permissions)) { return false; }

        permissions.deny = nextDeny;
        settings.permissions = permissions;

        try {
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
            writeFileAtomic(filePath, JSON.stringify(settings, null, 2) + '\n');
            return true;
        } catch {
            return existed ? false : false;
        }
    }

    private static _inject(filePath: string): boolean {
        const block = `\n${MARKER_START}\n${SHIELD_PATTERNS}\n${MARKER_END}\n`;
        let existing = '';

        try {
            existing = fs.readFileSync(filePath, 'utf-8');
            if (existing.includes(MARKER_START)) { return false; } // already shielded
        } catch { /* file doesn't exist yet */ }

        writeFileAtomic(filePath, existing + block);
        return true;
    }

    private static _remove(filePath: string): void {
        let content: string;
        try {
            content = fs.readFileSync(filePath, 'utf-8');
        } catch { return; }
        const regex = new RegExp(
            `\\n?${escapeRegex(MARKER_START)}[\\s\\S]*?${escapeRegex(MARKER_END)}\\n?`, 'g'
        );
        content = content.replace(regex, '');
        writeFileAtomic(filePath, content);
    }
}

function escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function writeFileAtomic(filePath: string, content: string): void {
    const tmp = filePath + '.' + process.pid + '.tmp';
    try {
        fs.writeFileSync(tmp, content, 'utf-8');
        fs.renameSync(tmp, filePath);
    } catch (err) {
        try { fs.unlinkSync(tmp); } catch { /* ignore temp-cleanup failure */ }
        throw err;
    }
}
