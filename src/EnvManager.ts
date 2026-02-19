import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export class EnvManager {

    /**
     * Reads the .env file, redacts values, and returns a safe string for the AI context.
     */
    public static async getRedactedEnv(workspaceFolder: vscode.Uri): Promise<string> {
        const envPath = path.join(workspaceFolder.fsPath, '.env');

        if (!fs.existsSync(envPath)) {
            return 'No .env file found in the workspace root.';
        }

        try {
            const fileContent = fs.readFileSync(envPath, 'utf-8');
            const lines = fileContent.split('\n');
            let redactedContent = '# .env (Redacted by VibeGuard)\n';

            for (const line of lines) {
                const trimmed = line.trim();
                // Skip comments and empty lines
                if (!trimmed || trimmed.startsWith('#')) {
                    redactedContent += line + '\n';
                    continue;
                }

                // Naive parsing KEY=VALUE
                const parts = trimmed.split('=');
                if (parts.length >= 2) {
                    const key = parts[0].trim();
                    // Redact the value part
                    redactedContent += `${key}=<HIDDEN_BY_VIBEGUARD>\n`;
                } else {
                    redactedContent += line + '\n';
                }
            }

            return redactedContent;
        } catch (error) {
            return `Error reading .env file: ${error}`;
        }
    }
}
