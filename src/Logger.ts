import * as vscode from 'vscode';

/**
 * Centralized logging via a dedicated VS Code Output Channel.
 * Users can open "VyberGuard" in the Output panel to see scan activity.
 */
export class Logger {
    private static outputChannel: vscode.OutputChannel;
    private static sessionStats = { scans: 0, secretsFound: 0, redactions: 0 };

    public static init(): vscode.OutputChannel {
        this.outputChannel = vscode.window.createOutputChannel('VyberGuard');
        this.outputChannel.appendLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        this.outputChannel.appendLine('  🛡️  VyberGuard — Secret Leak Prevention');
        this.outputChannel.appendLine('  Session started: ' + new Date().toLocaleString());
        this.outputChannel.appendLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        this.outputChannel.appendLine('');
        return this.outputChannel;
    }

    private static timestamp(): string {
        return new Date().toLocaleTimeString();
    }

    public static info(message: string): void {
        this.outputChannel.appendLine(`[${this.timestamp()}] ℹ️  ${message}`);
    }

    public static warn(message: string): void {
        this.outputChannel.appendLine(`[${this.timestamp()}] ⚠️  ${message}`);
    }

    public static error(message: string): void {
        this.outputChannel.appendLine(`[${this.timestamp()}] ❌ ${message}`);
    }

    public static scan(source: string, secretCount: number, types: string[]): void {
        this.sessionStats.scans++;
        this.sessionStats.secretsFound += secretCount;

        if (secretCount > 0) {
            this.warn(`SCAN [${source}]: Found ${secretCount} secret(s) — [${types.join(', ')}]`);
        } else {
            this.info(`SCAN [${source}]: Clean — no secrets detected.`);
        }
    }

    public static redaction(count: number): void {
        this.sessionStats.redactions += count;
        this.info(`REDACT: Replaced ${count} secret(s) with secure placeholders.`);
    }

    public static restore(count: number): void {
        this.info(`RESTORE: Restored ${count} secret(s) from secure vault.`);
    }

    public static statsLine(): string {
        const s = this.sessionStats;
        return `Scans: ${s.scans} | Secrets found: ${s.secretsFound} | Redactions: ${s.redactions}`;
    }

    public static show(): void {
        this.outputChannel.show();
    }

    public static dispose(): void {
        this.outputChannel.dispose();
    }
}
