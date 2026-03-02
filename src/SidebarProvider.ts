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
                    vscode.commands.executeCommand(data.command);
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
        const config = vscode.workspace.getConfiguration('vyberguard');
        const entropyEnabled = config.get<boolean>('enableEntropyScanning', true);
        const customCount = config.get<Array<unknown>>('customPatterns', []).length;
        const totalPatterns = SecretScanner.patternCount + customCount;

        // ─── Findings section ─────────────────────────────
        let findingsHtml = '';
        if (this.scanResults.length > 0) {
            const items = this.scanResults.slice(0, 8).map(f => `
                <div class="finding-item">
                    <span class="finding-file">${f.file}</span>
                    <span class="finding-count">${f.count}</span>
                </div>`).join('');
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
        const shieldCmd = this._aiShieldActive ? 'vyberguard.disableAiShield' : 'vyberguard.enableAiShield';
        const shieldDesc = this._aiShieldActive
            ? 'AI indexers cannot read your secret files.'
            : 'AI tools may index your credentials.';

        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VyberGuard</title>
            <style>
                :root {
                    --bg:              var(--vscode-editor-background);
                    --fg:              var(--vscode-editor-foreground);
                    --purple:          #C084FC;
                    --teal:            #2DD4BF;
                    --rose:            #FB7185;
                    --amber:           #FBBF24;
                    --border:          var(--vscode-panel-border, rgba(255,255,255,0.06));
                    --surface:         rgba(255,255,255,0.025);
                    --surface-hover:   rgba(255,255,255,0.05);
                    --muted:           var(--vscode-descriptionForeground, rgba(255,255,255,0.45));
                    --mono:            var(--vscode-editor-font-family, "SF Mono", Consolas, monospace);
                    --radius:          5px;
                    --gap:             18px;
                }
                * { box-sizing: border-box; }
                body {
                    margin: 0; padding: 0;
                    font-family: var(--vscode-font-family), system-ui, sans-serif;
                    font-size: 13px;
                    color: var(--fg);
                    background: var(--bg);
                    overflow-x: hidden;
                }
                svg { flex-shrink: 0; }

                /* ── Layout ────────────────────────── */
                .shell {
                    display: flex;
                    flex-direction: column;
                    gap: var(--gap);
                    padding: 16px 14px 24px;
                }

                /* ── Header ────────────────────────── */
                .header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding-bottom: 14px;
                    border-bottom: 1px solid var(--border);
                }
                .brand {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .brand-icon {
                    width: 26px; height: 26px;
                    background: var(--purple);
                    -webkit-mask: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>') no-repeat center / contain;
                    mask: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>') no-repeat center / contain;
                }
                .brand-name {
                    font-size: 14px;
                    font-weight: 600;
                    letter-spacing: 0.3px;
                }
                .brand-tag {
                    font-size: 10px;
                    color: var(--muted);
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }
                .header-stats {
                    text-align: right;
                }
                .scan-count {
                    font-family: var(--mono);
                    font-size: 18px;
                    font-weight: 600;
                    color: ${this.sessionSecrets > 0 ? 'var(--rose)' : 'var(--muted)'};
                    line-height: 1;
                }
                .scan-label {
                    font-size: 10px;
                    color: var(--muted);
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-top: 2px;
                }

                /* ── Clipboard warning banner ───────── */
                .clipboard-warning {
                    display: flex;
                    align-items: flex-start;
                    gap: 8px;
                    padding: 10px 12px;
                    background: rgba(251, 191, 36, 0.08);
                    border: 1px solid rgba(251, 191, 36, 0.3);
                    border-radius: var(--radius);
                    font-size: 12px;
                    color: var(--amber);
                    line-height: 1.4;
                }
                .clipboard-warning svg { width: 14px; height: 14px; margin-top: 1px; }
                kbd {
                    display: inline-block;
                    font-family: var(--mono);
                    font-size: 10px;
                    padding: 0 4px;
                    border: 1px solid rgba(251,191,36,0.4);
                    border-radius: 3px;
                }

                /* ── AI Shield card ─────────────────── */
                .shield-card {
                    border-radius: var(--radius);
                    border: 1px solid var(--border);
                    overflow: hidden;
                }
                .shield-card.shield-on {
                    border-color: rgba(45, 212, 191, 0.3);
                    background: rgba(45, 212, 191, 0.04);
                }
                .shield-card.shield-off {
                    background: var(--surface);
                }
                .shield-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 10px 12px;
                }
                .shield-label-group {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .shield-title {
                    font-size: 12px;
                    font-weight: 500;
                }
                .shield-desc {
                    font-size: 11px;
                    color: var(--muted);
                    padding: 0 12px 10px;
                    line-height: 1.45;
                }
                .toggle-btn {
                    font-family: var(--mono);
                    font-size: 10px;
                    font-weight: 700;
                    letter-spacing: 1px;
                    padding: 3px 8px;
                    border-radius: 3px;
                    cursor: pointer;
                    border: none;
                    transition: all 0.15s ease;
                }
                .toggle-btn.on {
                    background: rgba(45, 212, 191, 0.15);
                    color: var(--teal);
                    border: 1px solid rgba(45,212,191,0.3);
                }
                .toggle-btn.off {
                    background: var(--surface-hover);
                    color: var(--muted);
                    border: 1px solid var(--border);
                }
                .toggle-btn:hover { opacity: 0.8; }

                /* ── Primary action button ──────────── */
                .btn-cta {
                    width: 100%;
                    padding: 9px 14px;
                    background: rgba(192,132,252,0.1);
                    color: var(--purple);
                    border: 1px solid rgba(192,132,252,0.25);
                    border-radius: var(--radius);
                    font-size: 13px;
                    font-weight: 500;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 8px;
                    transition: all 0.15s ease;
                }
                .btn-cta:hover {
                    background: rgba(192,132,252,0.16);
                    border-color: rgba(192,132,252,0.45);
                    box-shadow: 0 0 14px rgba(192,132,252,0.12);
                }
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
                    padding: 8px 10px;
                    background: var(--surface);
                    border: 1px solid var(--border);
                    border-radius: var(--radius);
                    font-size: 12px;
                    color: var(--fg);
                    cursor: pointer;
                    text-align: left;
                    transition: all 0.15s ease;
                    white-space: nowrap;
                    overflow: hidden;
                }
                .btn-tool:hover {
                    background: var(--surface-hover);
                    border-color: rgba(255,255,255,0.12);
                }
                .btn-tool svg { width: 13px; height: 13px; flex-shrink: 0; opacity: 0.7; }
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
                    padding: 10px 12px;
                    position: relative;
                    overflow: hidden;
                }
                .stat-box::after {
                    content: '';
                    position: absolute;
                    inset: 0 auto 0 0;
                    width: 3px;
                    background: var(--border);
                    border-radius: var(--radius) 0 0 var(--radius);
                }
                .stat-box.accent-teal::after  { background: var(--teal); }
                .stat-box.accent-rose::after  { background: var(--rose); }
                .stat-box.accent-purple::after { background: var(--purple); }
                .stat-num {
                    font-family: var(--mono);
                    font-size: 22px;
                    line-height: 1;
                    font-weight: 600;
                }
                .stat-lbl {
                    font-size: 10px;
                    color: var(--muted);
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-top: 4px;
                }

                /* ── Sections ───────────────────────── */
                .section { display: flex; flex-direction: column; gap: 8px; }
                .section-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }
                .section-title {
                    font-size: 10px;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    color: var(--muted);
                    font-weight: 600;
                }
                .badge {
                    font-family: var(--mono);
                    font-size: 10px;
                    padding: 1px 6px;
                    border-radius: 3px;
                    font-weight: 600;
                }
                .badge-alert {
                    background: rgba(251, 113, 133, 0.12);
                    color: var(--rose);
                    border: 1px solid rgba(251,113,133,0.25);
                }
                .badge-safe {
                    background: rgba(45, 212, 191, 0.1);
                    color: var(--teal);
                    border: 1px solid rgba(45,212,191,0.2);
                }

                /* ── Findings ───────────────────────── */
                .findings-list {
                    border: 1px solid rgba(251,113,133,0.2);
                    border-radius: var(--radius);
                    overflow: hidden;
                    background: rgba(251,113,133,0.03);
                }
                .finding-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 7px 10px;
                    border-bottom: 1px solid rgba(251,113,133,0.1);
                    border-left: 3px solid var(--rose);
                    font-size: 11px;
                }
                .finding-item:last-child { border-bottom: none; }
                .finding-file {
                    font-family: var(--mono);
                    color: var(--muted);
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                    flex: 1;
                }
                .finding-count {
                    font-family: var(--mono);
                    color: var(--rose);
                    font-weight: 700;
                    margin-left: 8px;
                    white-space: nowrap;
                }
                .finding-more {
                    text-align: center;
                    font-size: 10px;
                    color: var(--muted);
                    padding: 6px;
                    background: rgba(255,255,255,0.02);
                }
                .safe-state {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    padding: 10px 12px;
                    border: 1px solid rgba(45,212,191,0.2);
                    border-radius: var(--radius);
                    background: rgba(45,212,191,0.04);
                    color: var(--teal);
                    font-size: 12px;
                }
                .safe-state svg { width: 14px; height: 14px; }

                /* ── Config table ───────────────────── */
                .config-table {
                    border: 1px solid var(--border);
                    border-radius: var(--radius);
                    overflow: hidden;
                }
                .config-row {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 8px 12px;
                    border-bottom: 1px solid var(--border);
                    font-size: 12px;
                }
                .config-row:last-child { border-bottom: none; }
                .config-key { color: var(--muted); }
                .config-val {
                    font-family: var(--mono);
                    font-size: 11px;
                    color: var(--purple);
                }
            </style>
        </head>
        <body>
            <div class="shell">

                <!-- ── Header ─────────────────────────── -->
                <div class="header">
                    <div class="brand">
                        <div class="brand-icon"></div>
                        <div>
                            <div class="brand-name">VyberGuard</div>
                            <div class="brand-tag">AI Secret Shield</div>
                        </div>
                    </div>
                    <div class="header-stats">
                        <div class="scan-count">${this.sessionSecrets}</div>
                        <div class="scan-label">Intercepted</div>
                    </div>
                </div>

                ${clipboardBanner}

                <!-- ── AI Shield card ──────────────────── -->
                <div class="shield-card ${shieldClass}">
                    <div class="shield-header">
                        <div class="shield-label-group">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="${this._aiShieldActive ? 'var(--teal)' : 'var(--muted)'}" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                            <span class="shield-title">AI Indexing Shield</span>
                        </div>
                        <button class="toggle-btn ${this._aiShieldActive ? 'on' : 'off'}"
                            onclick="vscode.postMessage({type:'action', command:'${shieldCmd}'})">${shieldLabel}</button>
                    </div>
                    <div class="shield-desc">${shieldDesc}</div>
                </div>

                <!-- ── Primary actions ─────────────────── -->
                <div class="section">
                    <button class="btn-cta" onclick="vscode.postMessage({type:'action', command:'vyberguard.copyRedacted'})">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                        Copy Redacted  <kbd style="font-family:var(--mono);font-size:10px;color:rgba(192,132,252,0.7);border:none;background:rgba(192,132,252,0.1);padding:1px 5px;border-radius:3px;">⇧C</kbd>
                    </button>
                    <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'vyberguard.sanitizedPaste'})" style="width:100%;justify-content:center;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>
                        <span>Sanitized Paste</span>
                        <kbd style="font-family:var(--mono);font-size:10px;color:var(--muted);background:var(--surface);padding:1px 5px;border-radius:3px;border:1px solid var(--border);margin-left:auto;">⇧V</kbd>
                    </button>
                </div>

                <!-- ── Tool grid ───────────────────────── -->
                <div class="section">
                    <div class="section-title">Analysis</div>
                    <div class="tool-grid">
                        <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'vyberguard.scanWorkspace'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                            <span>Scan All</span>
                        </button>
                        <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'vyberguard.redactActiveFile'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
                            <span>Redact File</span>
                        </button>
                        <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'vyberguard.restoreSecrets'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>
                            <span>Restore</span>
                        </button>
                        <button class="btn-tool" onclick="vscode.postMessage({type:'action', command:'vyberguard.showLog'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 7 4 4 20 4 20 7"></polyline><line x1="9" y1="20" x2="15" y2="20"></line><line x1="12" y1="4" x2="12" y2="20"></line></svg>
                            <span>Show Log</span>
                        </button>
                    </div>
                </div>

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
                            <div class="stat-lbl">Intercepted</div>
                        </div>
                    </div>
                </div>

                ${findingsHtml}

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
