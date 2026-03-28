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

        const CONCURRENCY_LIMIT = 5;
        const total = envFiles.length;

        for (let i = 0; i < total; i += CONCURRENCY_LIMIT) {
            const batch = envFiles.slice(i, i + CONCURRENCY_LIMIT);

            const batchResults = await Promise.all(batch.map(async (uri) => {
                const relPath = vscode.workspace.asRelativePath(uri);
                let fileResult = `\n# ─── ${relPath} (Redacted by Quell) ───\n`;

                try {
                    // Async file read — does NOT block the extension host
                    const rawBytes = await vscode.workspace.fs.readFile(uri);
                    const fileContent = Buffer.from(rawBytes).toString('utf-8');
                    const lines = fileContent.split(/\r?\n/);

                    for (const line of lines) {
                        const trimmed = line.trim();

                        // Preserve blank lines and comments
                        if (!trimmed || trimmed.startsWith('#')) {
                            fileResult += line + '\n';
                            continue;
                        }

                        const equalsIdx = trimmed.indexOf('=');
                        if (equalsIdx > 0) {
                            const key = trimmed.substring(0, equalsIdx).trim();
                            // Expose key name, mask value
                            fileResult += `${key}=<HIDDEN_BY_QUELL>\n`;
                        } else {
                            fileResult += line + ' # <Warning: Unparsed Line>\n';
                        }
                    }

                    Logger.info(`ENV: Redacted ${relPath}`);
                } catch (error) {
                    const errMsg = error instanceof Error ? error.message : String(error);
                    Logger.error(`ENV: Failed to read ${relPath}: ${errMsg}`);
                    fileResult += `# Error reading file: ${errMsg}\n`;
                }

                return fileResult;
            }));

            combinedContent += batchResults.join('');
        }

        return combinedContent.trim();
    }
}
