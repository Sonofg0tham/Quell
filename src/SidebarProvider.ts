import * as vscode from 'vscode';
import { SecretScanner } from './SecretScanner';

export class SidebarProvider implements vscode.WebviewViewProvider {
    private _view?: vscode.WebviewView;
    private sessionScans = 0;
    private sessionSecrets = 0;
    private scanResults: Array<{ file: string; count: number; types: string[] }> = [];
    private _aiShieldActive = false;
    private _clipboardWarning = false;

    constructor(private readonly _extensionUri: vscode.Uri) { }

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken,
    ) {
        this._view = webviewView;
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };
        webviewView.webview.html = this.getHtmlForWebview();
        webviewView.webview.onDidReceiveMessage(data => {
            switch (data.type) {
                case 'action':
                    if (data.args) {
                        vscode.commands.executeCommand(data.command, ...data.args);
                    } else {
                        vscode.commands.executeCommand(data.command);
                    }
                    break;
            }
        });
    }

    public recordScan(secretCount: number, findings?: Array<{ file: string; count: number; types: string[] }>): void {
        this.sessionScans++;
        this.sessionSecrets += secretCount;
        if (findings) { this.scanResults = findings; }
        this.refresh();
    }

    public setAiShield(active: boolean): void {
        this._aiShieldActive = active;
        this.refresh();
    }

    public setClipboardWarning(active: boolean): void {
        this._clipboardWarning = active;
        this.refresh();
    }

    public refresh(): void {
        if (this._view) {
            this._view.webview.html = this.getHtmlForWebview();
        }
    }

    private getHtmlForWebview(): string {
        const config = vscode.workspace.getConfiguration('quell');
        const iconUri = this._view?.webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'assets', 'icon.png')
        );
        const entropyEnabled = config.get<boolean>('enableEntropyScanning', true);
        const customCount = config.get<Array<unknown>>('customPatterns', []).length;
        const totalPatterns = SecretScanner.patternCount + customCount;

        const escapeHtml = (unsafe: string): string => {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        };

        // ─── Findings section ─────────────────────────────
        let findingsHtml = '';
        if (this.scanResults.length > 0) {
            const items = this.scanResults.slice(0, 8).map(f => {
                const escapedFileJs = f.file.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
                const safeFileJs = escapeHtml(escapedFileJs);
                const safeFile = escapeHtml(f.file);
                return `
                <div class="finding-item"
                    role="button"
                    tabindex="0"
                    onclick="vscode.postMessage({type:'action', command:'quell.openFile', args:['${safeFileJs}']})"
                    onkeydown="if(event.key === 'Enter' || event.key === ' ') { event.preventDefault(); vscode.postMessage({type:'action', command:'quell.openFile', args:['${safeFileJs}']}); }"
                >
                    <span class="finding-file" title="${safeFile}">${safeFile}</span>
                    <span class="finding-count" title="${f.count} secret(s)">${f.count}</span>
                </div>`;
            }).join('');
            const moreTag = this.scanResults.length > 8
                ? `<div class="finding-more">+${this.scanResults.length - 8} more files</div>` : '';
            findingsHtml = `
                <div class="section">
                    <div class="section-header">
                        <span class="section-title">Findings</span>
                        <span class="badge badge-alert">${this.scanResults.length} files</span>
                    </div>
                    <div class="findings-list">${items}${moreTag}</div>
                </div>`;
        } else if (this.sessionScans > 0) {
            findingsHtml = `
                <div class="section">
                    <div class="section-header">
                        <span class="section-title">Findings</span>
                        <span class="badge badge-safe">Clean</span>
                    </div>
                    <div class="safe-state">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                        Workspace is clean
                    </div>
                </div>`;
        }

        // ─── Clipboard warning ─────────────────────────────
        const clipboardBanner = this._clipboardWarning ? `
            <div class="clipboard-warning">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                <span>Secret in clipboard! Use <kbd>Ctrl+Shift+C</kbd> to safely copy.</span>
            </div>` : '';

        // ─── AI Shield state ──────────────────────────────
        const shieldClass = this._aiShieldActive ? 'shield-on' : 'shield-off';
        const shieldLabel = this._aiShieldActive ? 'ON' : 'OFF';
        const shieldCmd = this._aiShieldActive ? 'quell.disableAiShield' : 'quell.enableAiShield';
        const shieldDesc = this._aiShieldActive
            ? 'AI indexers cannot read your secret files.'
            : 'AI tools may index your credentials.';
            
        // ─── Auto-Sanitize state ──────────────────────────
        const autoSanitizeEnabled = config.get<boolean>('autoSanitizeClipboard', false);

        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${this._view?.webview.cspSource} https: data:; style-src 'unsafe-inline' ${this._view?.webview.cspSource}; script-src 'unsafe-inline';">
            <title>Quell</title>
            <style>
                @keyframes pulseGlow {
                    0%, 100% { box-shadow: 0 0 8px rgba(37,99,235,0.15); }
                    50% { box-shadow: 0 0 18px rgba(37,99,235,0.3), 0 0 40px rgba(37,99,235,0.08); }
                }
                @keyframes shimmer {
                    0% { background-position: -200% 0; }
                    100% { background-position: 200% 0; }
                }
                @keyframes fadeSlideIn {
                    from { opacity: 0; transform: translateY(6px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                @keyframes breathe {
                    0%, 100% { opacity: 0.5; transform: scale(0.85); }
                    50% { opacity: 1; transform: scale(1); }
                }
                :root {
                    --bg:              var(--vscode-editor-background);
                    --fg:              var(--vscode-editor-foreground);
                    --accent:          #2563EB;
                    --accent-bright:   #60A5FA;
                    --sapphire:        #2563EB;
                    --accent-dim:      rgba(37,99,235,0.10);
                    --accent-glow:     rgba(37,99,235,0.06);
                    --purple:          #A78BFA;
                    --teal:            #2563EB;
                    --rose:            #FB7185;
                    --amber:           #FBBF24;
                    --border:          rgba(37,99,235,0.12);
                    --border-subtle:   var(--vscode-panel-border, rgba(255,255,255,0.04));
                    --surface:         rgba(255,255,255,0.02);
                    --surface-hover:   rgba(37,99,235,0.08);
                    --glass:           rgba(255,255,255,0.03);
                    --glass-border:    rgba(255,255,255,0.08);
                    --muted:           var(--vscode-descriptionForeground, rgba(255,255,255,0.4));
                    --mono:            var(--vscode-editor-font-family, "SF Mono", "Cascadia Code", Consolas, monospace);
                    --radius:          12px;
                    --radius-sm:       8px;
                    --gap:             16px;
                }
                * { box-sizing: border-box; margin: 0; }
                body {
                    margin: 0; padding: 0;
                    font-family: var(--vscode-font-family), system-ui, -apple-system, sans-serif;
                    font-size: 12.5px;
                    color: var(--fg);
                    background: var(--bg);
                    overflow-x: hidden;
                    -webkit-font-smoothing: antialiased;
                }
                svg { flex-shrink: 0; }

                /* ── Layout ────────────────────────── */
                .shell {
                    display: flex;
                    flex-direction: column;
                    gap: var(--gap);
                    padding: 14px 10px 28px;
                    animation: fadeSlideIn 0.35s ease-out;
                }

                /* ── Header ────────────────────────── */
                .header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 16px 20px;
                    background: linear-gradient(135deg, rgba(37,99,235,0.1) 0%, rgba(29,78,216,0.05) 100%);
                    border: 1px solid rgba(37,99,235,0.2);
                    border-radius: var(--radius);
                    position: relative;
                    overflow: hidden;
                    backdrop-filter: blur(16px);
                    box-shadow: 0 4px 24px rgba(0,0,0,0.2), inset 0 1px 1px rgba(255,255,255,0.05);
                }
                .header::before {
                    content: '';
                    position: absolute;
                    inset: 0;
                    background: 
                        linear-gradient(120deg, transparent 40%, rgba(37,99,235,0.05) 45%, rgba(37,99,235,0.1) 50%, rgba(37,99,235,0.05) 55%, transparent 60%);
                    background-size: 200% 100%;
                    animation: shimmer 6s infinite linear;
                    pointer-events: none;
                }
                .header::after {
                    content: '';
                    position: absolute;
                    top: -50%; left: -50%;
                    width: 200%; height: 200%;
                    background: radial-gradient(circle at center, rgba(37,99,235,0.03) 0%, transparent 70%);
                    pointer-events: none;
                }
                .brand {
                    display: flex;
                    align-items: center;
                    gap: 11px;
                }
                .brand-icon {
                    width: 32px; height: 32px;
                    background: transparent;
                    border-radius: 8px;
                    position: relative;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    overflow: hidden;
                    box-shadow: 0 4px 12px rgba(37,99,235,0.25);
                }
                .brand-icon img {
                    width: 100%; height: 100%;
                    object-fit: cover;
                }
                .brand-name {
                    font-size: 16px;
                    font-weight: 800;
                    letter-spacing: 0.6px;
                    background: linear-gradient(135deg, #fff 20%, var(--accent-bright) 80%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                }
                .brand-tag {
                    font-size: 10.5px;
                    color: rgba(255, 255, 255, 0.85);
                    letter-spacing: 0.3px;
                    margin-top: 1px;
                }
                .header-stats {
                    text-align: right;
                }
                .scan-count {
                    font-family: var(--mono);
                    font-size: 22px;
                    font-weight: 800;
                    color: ${this.sessionSecrets > 0 ? 'var(--rose)' : 'var(--accent)'};
                    line-height: 1;
                    ${this.sessionSecrets > 0 ? 'text-shadow: 0 0 12px rgba(251,113,133,0.35);' : 'opacity: 0.5;'}
                }
                .scan-label {
                    font-size: 8.5px;
                    color: var(--muted);
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin-top: 3px;
                }

                /* ── Clipboard warning banner ───────── */
                .clipboard-warning {
                    display: flex;
                    align-items: flex-start;
                    gap: 8px;
                    padding: 10px 12px;
                    background: rgba(251, 191, 36, 0.06);
                    border: 1px solid rgba(251, 191, 36, 0.25);
                    border-radius: var(--radius);
                    font-size: 11.5px;
                    color: var(--amber);
                    line-height: 1.45;
                    backdrop-filter: blur(8px);
                }
                .clipboard-warning svg { width: 14px; height: 14px; margin-top: 1px; }
                kbd {
                    display: inline-block;
                    font-family: var(--mono);
                    font-size: 9.5px;
                    padding: 1px 5px;
                    border: 1px solid rgba(251,191,36,0.3);
                    border-radius: 4px;
                    background: rgba(251,191,36,0.08);
                }

                /* ── AI Shield card ─────────────────── */
                .shield-card {
                    border-radius: var(--radius);
                    border: 1px solid var(--border);
                    overflow: hidden;
                    transition: all 0.3s ease;
                    backdrop-filter: blur(8px);
                }
                .shield-card.shield-on {
                    border-color: rgba(45, 212, 191, 0.25);
                    background: linear-gradient(145deg, rgba(37,99,235,0.06) 0%, rgba(37,99,235,0.02) 100%);
                    box-shadow: 0 2px 16px rgba(37,99,235,0.06), inset 0 1px 0 rgba(37,99,235,0.1);
                }
                .shield-card.shield-off {
                    background: var(--surface);
                }
                .shield-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 11px 14px;
                }
                .shield-label-group {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .shield-dot {
                    width: 6px; height: 6px;
                    border-radius: 50%;
                    display: inline-block;
                }
                .shield-dot.active {
                    background: var(--teal);
                    box-shadow: 0 0 6px var(--teal);
                    animation: breathe 2s ease-in-out infinite;
                }
                .shield-dot.inactive {
                    background: var(--muted);
                    opacity: 0.4;
                }
                .shield-title {
                    font-size: 12px;
                    font-weight: 600;
                }
                .shield-desc {
                    font-size: 11px;
                    color: var(--muted);
                    padding: 0 14px 11px;
                    line-height: 1.5;
                }
                .toggle-btn {
                    font-family: var(--mono);
                    font-size: 9.5px;
                    font-weight: 700;
                    letter-spacing: 1.2px;
                    padding: 4px 10px;
                    border-radius: 4px;
                    cursor: pointer;
                    border: none;
                    transition: all 0.2s ease;
                }
                .toggle-btn.on {
                    background: rgba(45, 212, 191, 0.15);
                    color: var(--teal);
                    border: 1px solid rgba(37,99,235,0.3);
                    box-shadow: 0 0 8px rgba(37,99,235,0.1);
                }
                .toggle-btn.off {
                    background: var(--surface);
                    color: var(--muted);
                    border: 1px solid var(--glass-border);
                }
                .toggle-btn:hover { opacity: 0.85; transform: scale(1.03); }

                /* ── Primary action button ──────────── */
                .btn-cta {
                    width: 100%;
                    padding: 11px 14px;
                    background: linear-gradient(140deg, rgba(37,99,235,0.14) 0%, rgba(29,78,216,0.07) 100%);
                    color: var(--accent-bright);
                    border: 1px solid rgba(37,99,235,0.18);
                    border-radius: var(--radius);
                    font-size: 12.5px;
                    font-weight: 700;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 8px;
                    transition: all 0.25s cubic-bezier(0.4,0,0.2,1);
                    position: relative;
                    overflow: hidden;
                    letter-spacing: 0.3px;
                }
                .btn-cta::before {
                    content: '';
                    position: absolute;
                    top: 0; left: 0; right: 0;
                    height: 1px;
                    background: linear-gradient(90deg, transparent 10%, rgba(37,99,235,0.5) 50%, transparent 90%);
                }
                .btn-cta::after {
                    content: '';
                    position: absolute;
                    inset: 0;
                    background: linear-gradient(90deg, transparent, rgba(37,99,235,0.08), transparent);
                    background-size: 200% 100%;
                    animation: shimmer 3s ease-in-out infinite;
                    pointer-events: none;
                }
                .btn-cta:hover {
                    background: linear-gradient(140deg, rgba(37,99,235,0.22) 0%, rgba(29,78,216,0.12) 100%);
                    border-color: rgba(37,99,235,0.4);
                    box-shadow: 0 4px 24px rgba(37,99,235,0.12), 0 0 0 1px rgba(37,99,235,0.08);
                    transform: translateY(-1px);
                }
                .btn-cta:active { transform: translateY(0) scale(0.99); }
                .btn-cta:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
                .btn-cta svg { width: 14px; height: 14px; }

                /* ── Tool grid ──────────────────────── */
                .tool-grid {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 6px;
                }
                .btn-tool {
                    display: flex;
                    align-items: center;
                    gap: 7px;
                    padding: 10px 12px;
                    background: var(--glass);
                    border: 1px solid var(--glass-border);
                    border-radius: var(--radius-sm);
                    font-size: 11.5px;
                    font-weight: 600;
                    color: var(--fg);
                    cursor: pointer;
                    text-align: left;
                    transition: all 0.2s cubic-bezier(0.4,0,0.2,1);
                    white-space: nowrap;
                    overflow: hidden;
                    backdrop-filter: blur(8px);
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .btn-tool:hover {
                    background: var(--surface-hover);
                    border-color: rgba(37,99,235,0.3);
                    box-shadow: 0 4px 12px rgba(37,99,235,0.12);
                    transform: translateY(-2px);
                }
                .btn-tool:active { transform: translateY(0) scale(0.97); }
                .btn-tool svg { width: 14px; height: 14px; flex-shrink: 0; color: var(--accent); transition: all 0.2s; }
                .btn-tool:hover svg { transform: rotate(-5deg) scale(1.1); filter: drop-shadow(0 0 4px var(--accent)); }
                .btn-tool:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }
                .btn-tool span { overflow: hidden; text-overflow: ellipsis; }

                /* ── Stats row ──────────────────────── */
                .stats-row {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 6px;
                }
                .stat-box {
                    border: 1px solid var(--border);
                    border-radius: var(--radius);
                    padding: 12px 14px;
                    position: relative;
                    overflow: hidden;
                    background: var(--surface);
                    backdrop-filter: blur(6px);
                    transition: border-color 0.25s ease;
                }
                .stat-box:hover { border-color: rgba(37,99,235,0.18); }
                .stat-box::after {
                    content: '';
                    position: absolute;
                    inset: 0 auto 0 0;
                    width: 2.5px;
                    background: var(--border);
                    border-radius: var(--radius) 0 0 var(--radius);
                    transition: width 0.2s ease;
                }
                .stat-box:hover::after { width: 3.5px; }
                .stat-box.accent-teal::after  { background: linear-gradient(180deg, var(--teal), rgba(37,99,235,0.4)); }
                .stat-box.accent-rose::after  { background: linear-gradient(180deg, var(--rose), rgba(251,113,133,0.4)); }
                .stat-box.accent-purple::after { background: linear-gradient(180deg, var(--purple), rgba(167,139,250,0.4)); }
                .stat-num {
                    font-family: var(--mono);
                    font-size: 24px;
                    line-height: 1;
                    font-weight: 700;
                    letter-spacing: -0.5px;
                }
                .stat-lbl {
                    font-size: 9px;
                    color: var(--muted);
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin-top: 5px;
                    font-weight: 500;
                }

                /* ── Sections ───────────────────────── */
                .section { display: flex; flex-direction: column; gap: 8px; }
                .section-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }
                .section-title {
                    font-size: 9.5px;
                    text-transform: uppercase;
                    letter-spacing: 1.5px;
                    color: var(--muted);
                    font-weight: 700;
                    position: relative;
                    padding-left: 10px;
                }
                .section-title::before {
                    content: '';
                    position: absolute;
                    left: 0; top: 50%;
                    transform: translateY(-50%);
                    width: 3px; height: 10px;
                    border-radius: 2px;
                    background: linear-gradient(180deg, var(--accent), rgba(37,99,235,0.3));
                }
                .badge {
                    font-family: var(--mono);
                    font-size: 9.5px;
                    padding: 2px 7px;
                    border-radius: 4px;
                    font-weight: 700;
                    letter-spacing: 0.3px;
                }
                .badge-alert {
                    background: rgba(251, 113, 133, 0.1);
                    color: var(--rose);
                    border: 1px solid rgba(251,113,133,0.2);
                }
                .badge-safe {
                    background: rgba(45, 212, 191, 0.08);
                    color: var(--teal);
                    border: 1px solid rgba(37,99,235,0.18);
                }

                /* ── Findings ───────────────────────── */
                .findings-list {
                    border: 1px solid rgba(251,113,133,0.15);
                    border-radius: var(--radius);
                    overflow: hidden;
                    background: rgba(251,113,133,0.02);
                }
                .finding-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 8px 12px;
                    border-bottom: 1px solid rgba(251,113,133,0.08);
                    border-left: 2.5px solid var(--rose);
                    font-size: 11px;
                    transition: background 0.15s ease, transform 0.1s ease;
                    cursor: pointer;
                }
                .finding-item:hover { 
                    background: rgba(251,113,133,0.08);
                }
                .finding-item:active {
                    transform: scale(0.99);
                }
                .finding-item:focus-visible {
                    outline: 2px solid var(--accent-bright);
                    outline-offset: -2px;
                    background: rgba(251,113,133,0.08);
                }
                .finding-item:last-child { border-bottom: none; }
                .finding-file {
                    font-family: var(--mono);
                    color: var(--muted);
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                    flex: 1;
                    font-size: 10.5px;
                }
                .finding-count {
                    font-family: var(--mono);
                    color: var(--rose);
                    font-weight: 700;
                    margin-left: 8px;
                    white-space: nowrap;
                    font-size: 11px;
                }
                .finding-more {
                    text-align: center;
                    font-size: 9.5px;
                    color: var(--muted);
                    padding: 6px;
                    background: rgba(255,255,255,0.015);
                }
                .safe-state {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    padding: 10px 14px;
                    border: 1px solid rgba(37,99,235,0.15);
                    border-radius: var(--radius);
                    background: linear-gradient(145deg, rgba(37,99,235,0.05) 0%, rgba(37,99,235,0.02) 100%);
                    color: var(--teal);
                    font-size: 12px;
                    font-weight: 500;
                }
                .safe-state svg { width: 14px; height: 14px; }

                /* ── Config table ───────────────────── */
                .config-table {
                    border: 1px solid var(--border);
                    border-radius: var(--radius);
                    overflow: hidden;
                    background: var(--surface);
                }
                .config-row {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 9px 14px;
                    border-bottom: 1px solid var(--border);
                    font-size: 11.5px;
                    transition: background 0.15s ease;
                }
                .config-row:hover { background: rgba(37,99,235,0.02); }
                .config-row:last-child { border-bottom: none; }
                .config-key { color: var(--muted); font-weight: 500; }
                .config-val {
                    font-family: var(--mono);
                    font-size: 11px;
                    color: var(--accent);
                    font-weight: 700;
                }

                /* ── Divider ───────────────────────── */
                .section-divider {
                    height: 1px;
                    background: linear-gradient(90deg, transparent 5%, var(--border) 50%, transparent 95%);
                    margin: 2px 0;
                }
            </style>
        </head>
        <body>
            <div class="shell">

                <!-- ── Header ─────────────────────────── -->
                <div class="header">
                    <div class="brand">
                        <div class="brand-icon">
                            <img src="${iconUri}" alt="Quell">
                        </div>
                        <div>
                            <div class="brand-name">Quell</div>
                            <div class="brand-tag">AI Secret Privacy</div>
                        </div>
                    </div>
                    <div class="header-stats">
                        <div class="scan-count">${this.sessionSecrets}</div>
                        <div class="scan-label">Detected</div>
                    </div>
                </div>

                ${clipboardBanner}

                <!-- ── AI Shield card ──────────────────── -->
                <div class="shield-card ${shieldClass}">
                    <div class="shield-header">
                        <div class="shield-label-group">
                            <span class="shield-dot ${this._aiShieldActive ? 'active' : 'inactive'}"></span>
                            <span class="shield-title">AI Indexing Shield</span>
                        </div>
                        <button class="toggle-btn ${this._aiShieldActive ? 'on' : 'off'}"
                            onclick="vscode.postMessage({type:'action', command:'${shieldCmd}'})">${shieldLabel}</button>
                    </div>
                    <div class="shield-desc">${shieldDesc}</div>
                </div>

                <!-- ── Clipboard Auto-Sanitize card ────── -->
                <div class="shield-card ${autoSanitizeEnabled ? 'shield-on' : 'shield-off'}" style="margin-top: 8px;">
                    <div class="shield-header">
                        <div class="shield-label-group">
                            <span class="shield-dot ${autoSanitizeEnabled ? 'active' : 'inactive'}"></span>
                            <span class="shield-title">Clipboard Auto-Sanitize</span>
                        </div>
                        <button class="toggle-btn ${autoSanitizeEnabled ? 'on' : 'off'}"
                            onclick="vscode.postMessage({type:'action', command:'quell.toggleAutoSanitize'})">${autoSanitizeEnabled ? 'ON' : 'OFF'}</button>
                    </div>
                    <div class="shield-desc">${autoSanitizeEnabled ? 'Actively securing copied secrets.' : 'Warns only when secrets are copied.'}</div>
                </div>

                <div class="section-divider"></div>

                <!-- ── Primary actions ─────────────────── -->
                <div class="section">
                    <button class="btn-cta" onclick="vscode.postMessage({type:'action', command:'quell.copyRedacted'})">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                        Copy Redacted  <kbd style="font-family:var(--mono);font-size:9.5px;color:rgba(96,165,250,0.9);border:none;background:rgba(37,99,235,0.12);padding:2px 6px;border-radius:4px;letter-spacing:0.5px;">⇧C</kbd>
                    </button>
                    <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'quell.sanitizedPaste'})" style="width:100%;justify-content:center;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>
                        <span>Sanitized Paste</span>
                        <kbd style="font-family:var(--mono);font-size:9.5px;color:var(--muted);background:var(--surface);padding:2px 6px;border-radius:4px;border:1px solid var(--glass-border);margin-left:auto;letter-spacing:0.5px;">⇧V</kbd>
                    </button>
                </div>

                <div class="section-divider"></div>

                <!-- ── Tool grid ───────────────────────── -->
                <div class="section">
                    <div class="section-title">Analysis</div>
                    <div class="tool-grid">
                        <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'quell.scanWorkspace'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                            <span>Scan All</span>
                        </button>
                        <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'quell.redactActiveFile'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                            <span>Redact File</span>
                        </button>
                        <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'quell.restoreSecrets'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>
                            <span>Restore</span>
                        </button>
                        <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'quell.showLog'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 7 4 4 20 4 20 7"></polyline><line x1="9" y1="20" x2="15" y2="20"></line><line x1="12" y1="4" x2="12" y2="20"></line></svg>
                            <span>Show Log</span>
                        </button>
                    </div>
                </div>

                <div class="section-divider"></div>

                <!-- ── Session stats ───────────────────── -->
                <div class="section">
                    <div class="section-title">Session</div>
                    <div class="stats-row">
                        <div class="stat-box ${this.sessionScans > 0 ? 'accent-teal' : ''}">
                            <div class="stat-num">${this.sessionScans}</div>
                            <div class="stat-lbl">Scans</div>
                        </div>
                        <div class="stat-box ${this.sessionSecrets > 0 ? 'accent-rose' : ''}">
                            <div class="stat-num" style="color:${this.sessionSecrets > 0 ? 'var(--rose)' : 'inherit'}">${this.sessionSecrets}</div>
                            <div class="stat-lbl">Detected</div>
                        </div>
                    </div>
                </div>

                ${findingsHtml}

                <div class="section-divider"></div>

                <!-- ── Engine config ───────────────────── -->
                <div class="section">
                    <div class="section-title">Engine</div>
                    <div class="config-table">
                        <div class="config-row">
                            <span class="config-key">Signatures</span>
                            <span class="config-val">${totalPatterns}</span>
                        </div>
                        <div class="config-row">
                            <span class="config-key">Entropy Scanner</span>
                            <span class="config-val" style="color:${entropyEnabled ? 'var(--teal)' : 'var(--muted)'}">${entropyEnabled ? 'Active' : 'Off'}</span>
                        </div>
                    </div>
                </div>

            </div>
            <script>const vscode = acquireVsCodeApi();</script>
        </body>
        </html>`;
    }
}
