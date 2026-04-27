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
    '**/config/secrets*',
    '**/vault.*',
].join('\n');

/** AI IDE ignore file names (new IDEs can be added here) */
const IGNORE_FILES = [
    '.cursorignore',
    '.windsurfignore',
    '.antigravityignore',
    '.aiderignore',
    '.aiignore',
];

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
        this._enabled = true;
        return count;
    }

    /**
     * Remove the Quell block from all AI ignore files.
     * Deletes the file entirely if it becomes empty.
     */
    static disable(workspacePath: string): void {
        for (const file of IGNORE_FILES) {
            this._remove(path.join(workspacePath, file));
        }
        this._enabled = false;
    }

    /**
     * Detect whether the AI shield is currently active for the workspace.
     * Updates internal state as a side effect.
     */
    static check(workspacePath: string): boolean {
        for (const file of IGNORE_FILES) {
            const filePath = path.join(workspacePath, file);
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf-8');
                if (content.includes(MARKER_START)) {
                    this._enabled = true;
                    return true;
                }
            }
        }
        this._enabled = false;
        return false;
    }

    // ── Private Helpers ───────────────────────────

    private static _inject(filePath: string): boolean {
        const block = `\n${MARKER_START}\n${SHIELD_PATTERNS}\n${MARKER_END}\n`;
        let existing = '';

        try {
            existing = fs.readFileSync(filePath, 'utf-8');
            if (existing.includes(MARKER_START)) { return false; } // already shielded
        } catch { /* file doesn't exist yet */ }

        fs.writeFileSync(filePath, existing + block, 'utf-8');
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
        if (content.trim() === '') {
            fs.unlinkSync(filePath);
        } else {
            fs.writeFileSync(filePath, content, 'utf-8');
        }
    }
}

function escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
