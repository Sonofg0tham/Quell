import * as vscode from 'vscode';
import { Logger } from './Logger';

/**
 * Manages the VyberGuard status bar indicator.
 * States: idle → scanning → alert/safe → ai-shield-on
 */
export class StatusBar {
    private static item: vscode.StatusBarItem;
    private static scanCount: number = 0;
    private static resetTimer: ReturnType<typeof setTimeout> | undefined;
    private static _aiShieldActive = false;
    private static _rawSecretCount = 0;

    public static init(context: vscode.ExtensionContext): void {
        this.item = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            1000
        );
        this.item.command = 'vyberguard.showLog';
        this.setIdle();
        this.item.show();
        context.subscriptions.push(this.item);
    }

    /** Default resting state — reflects AI Shield + exposure count */
    public static setIdle(): void {
        this.clearTimer();
        if (this._aiShieldActive) {
            this.item.text = '$(shield) VyberGuard  🛡 AI Shield ON';
            this.item.tooltip = `🛡️ AI Shield is ACTIVE\nSecret files are hidden from AI indexers.\n\n${Logger.statsLine()}`;
            this.item.color = '#2DD4BF'; // Vivid teal = shielded
            this.item.backgroundColor = undefined;
        } else if (this._rawSecretCount > 0) {
            this.item.text = `$(shield) VyberGuard  ⚠ ${this._rawSecretCount} exposed`;
            this.item.tooltip = `⚠️ ${this._rawSecretCount} raw secret(s) detected in workspace.\nClick to view VyberGuard log.\n\n${Logger.statsLine()}`;
            this.item.color = '#FBBF24'; // Amber = exposed but not alerted
            this.item.backgroundColor = undefined;
        } else {
            this.item.text = '$(shield) VyberGuard';
            this.item.tooltip = `🛡️ VyberGuard is active\n${Logger.statsLine()}`;
            this.item.color = undefined;
            this.item.backgroundColor = undefined;
        }
    }

    /** Momentarily show scanning state */
    public static setScanning(): void {
        this.clearTimer();
        this.item.text = '$(loading~spin) Scanning…';
        this.item.tooltip = 'VyberGuard is scanning for secrets…';
        this.item.color = undefined;
        this.item.backgroundColor = undefined;
    }

    /** Flash alert when secrets are found */
    public static setAlert(secretCount: number): void {
        this.clearTimer();
        this.scanCount++;
        this.item.text = `$(shield) VyberGuard — ${secretCount} secret(s) intercepted!`;
        this.item.tooltip = `⚠️ ${secretCount} secret(s) detected and redacted.\nClick to view the VyberGuard log.\n\n${Logger.statsLine()}`;
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        this.item.color = undefined;
        this.resetTimer = setTimeout(() => this.setIdle(), 8000);
    }

    /** Brief confirmation that scan was clean */
    public static setSafe(): void {
        this.clearTimer();
        this.scanCount++;
        this.item.text = '$(shield) VyberGuard ✓ Clean';
        this.item.tooltip = `✅ No secrets detected.\n\n${Logger.statsLine()}`;
        this.item.color = '#2DD4BF'; // Teal = safe
        this.item.backgroundColor = undefined;
        this.resetTimer = setTimeout(() => this.setIdle(), 4000);
    }

    /** Update AI Shield active state (persists in idle) */
    public static setAiShield(active: boolean): void {
        this._aiShieldActive = active;
        this.setIdle();
    }

    /** Update the live raw secret exposure count (amber badge in idle) */
    public static setExposureBadge(count: number): void {
        this._rawSecretCount = count;
        // Only update idle display — don't interrupt active states
        if (!this.resetTimer) {
            this.setIdle();
        }
    }

    private static clearTimer(): void {
        if (this.resetTimer) {
            clearTimeout(this.resetTimer);
            this.resetTimer = undefined;
        }
    }
}
