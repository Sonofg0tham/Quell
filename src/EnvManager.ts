import * as vscode from 'vscode';
import { Logger } from './Logger';

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
     * but all values are replaced with `<HIDDEN_BY_VYBERGUARD>`.
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
            combinedContent += `\n# ─── ${relPath} (Redacted by VyberGuard) ───\n`;

            try {
                // Async file read — does NOT block the extension host
                const rawBytes = await vscode.workspace.fs.readFile(uri);
                const fileContent = Buffer.from(rawBytes).toString('utf-8');
                const lines = fileContent.split(/\r?\n/);

                for (const line of lines) {
                    const trimmed = line.trim();

                    // Preserve blank lines and comments
                    if (!trimmed || trimmed.startsWith('#')) {
                        combinedContent += line + '\n';
                        continue;
                    }

                    const equalsIdx = trimmed.indexOf('=');
                    if (equalsIdx > 0) {
                        const key = trimmed.substring(0, equalsIdx).trim();
                        // Expose key name, mask value
                        combinedContent += `${key}=<HIDDEN_BY_VYBERGUARD>\n`;
                    } else {
                        combinedContent += line + ' # <Warning: Unparsed Line>\n';
                    }
                }

                Logger.info(`ENV: Redacted ${relPath}`);
            } catch (error) {
                const errMsg = error instanceof Error ? error.message : String(error);
                Logger.error(`ENV: Failed to read ${relPath}: ${errMsg}`);
                combinedContent += `# Error reading file: ${errMsg}\n`;
            }
        }

        return combinedContent.trim();
    }
}
