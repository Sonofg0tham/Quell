import * as vscode from 'vscode';
import { Logger } from './Logger';
import { SecretScanner, EnvRedactor, ENV_MASK } from '../packages/scanner/src';
import { getConfig } from './configHelper';

const MASK = ENV_MASK;

/**
 * Manages .env file discovery and redaction.
 * Prevents AI from ingesting raw environment secrets by providing
 * redacted versions with keys visible but values masked.
 */
export class EnvManager {

    /** Glob patterns for env-like files */
    private static readonly ENV_GLOBS = [
        '**/.env',
        '**/.env.*',
        '**/.env.local',
        '**/.env.development',
        '**/.env.production',
        '**/.env.staging',
        '**/.env.test',
    ];

    /** Folders to always exclude */
    private static readonly EXCLUDE_PATTERN = '{**/node_modules/**,**/.git/**,**/dist/**,**/build/**,**/out/**}';

    /**
     * Searches for all .env files in the workspace (excluding typical build dirs),
     * reads them asynchronously, and returns a combined redacted string.
     * 
     * Keys are preserved (e.g. `DATABASE_URL`) so the AI understands the shape,
     * but all values are replaced with `<HIDDEN_BY_QUELL>`.
     */
    public static async getRedactedEnv(): Promise<string> {
        const envFiles = await vscode.workspace.findFiles(
            '{**/.env,**/.env.*}',
            this.EXCLUDE_PATTERN
        );

        if (!envFiles || envFiles.length === 0) {
            Logger.info('ENV: No .env files found in workspace.');
            return 'No .env files found in the workspace.';
        }

        Logger.info(`ENV: Found ${envFiles.length} .env file(s) to redact.`);
        let combinedContent = '';

        for (const uri of envFiles) {
            const relPath = vscode.workspace.asRelativePath(uri);
            combinedContent += `\n# ─── ${relPath} (Redacted by Quell) ───\n`;

            try {
                // Async file read — does NOT block the extension host
                const rawBytes = await vscode.workspace.fs.readFile(uri);
                const fileContent = Buffer.from(rawBytes).toString('utf-8');
                combinedContent += this.redactEnvContent(fileContent);

                Logger.info(`ENV: Redacted ${relPath}`);
            } catch (error) {
                const errMsg = error instanceof Error ? error.message : String(error);
                Logger.error(`ENV: Failed to read ${relPath}: ${errMsg}`);
                combinedContent += `# Error reading file: ${errMsg}\n`;
            }
        }

        // ── Defence in depth ──
        // The line parser below is deliberately fail-closed, but this is the one
        // feature whose entire promise is "real values never leave your machine",
        // so the assembled output gets a second, independent pass through the
        // secret scanner. Anything the parser somehow let through is caught here.
        return this.backstop(combinedContent).trim();
    }

    /**
     * Masks the values in a single .env file's content.
     * Delegates to the standalone, CI-tested parser in the scanner package.
     */
    public static redactEnvContent(fileContent: string): string {
        return EnvRedactor.redact(fileContent);
    }

    /**
     * Final safety net: scan the assembled output and mask anything the scanner
     * still recognises as a secret. Placeholders are collapsed to the same
     * `<HIDDEN_BY_QUELL>` marker rather than vault-backed handles — this text is
     * headed for a chat window, not an editor, so there is nothing to restore.
     */
    private static backstop(content: string): string {
        try {
            const { redactedText, secrets } = SecretScanner.redact(content, getConfig());
            if (secrets.size === 0) { return content; }

            Logger.warn(`ENV: Backstop scanner masked ${secrets.size} value(s) the .env parser did not catch.`);
            let safe = redactedText;
            for (const placeholder of secrets.keys()) {
                safe = safe.split(placeholder).join(MASK);
            }
            return safe;
        } catch (err) {
            // If the backstop itself fails we must not fall back to emitting the
            // unverified text — withhold the content instead.
            Logger.error(`ENV: Backstop scan failed (${err instanceof Error ? err.message : String(err)}); withholding content.`);
            return `# ${MASK} (Quell could not verify this content was safe to share)`;
        }
    }
}
