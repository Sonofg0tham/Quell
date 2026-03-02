import * as vscode from 'vscode';
import { SecretScanner, ScannerConfig, DEFAULT_CONFIG } from './SecretScanner';
import { EnvManager } from './EnvManager';
import { Logger } from './Logger';
import { StatusBar } from './StatusBar';
import { DecorationProvider } from './DecorationProvider';
import { SidebarProvider } from './SidebarProvider';
import { AiShieldManager } from './AiShieldManager';

// ─────────────────────────────────────────────────────
//  Helper: Read VS Code settings into ScannerConfig
// ─────────────────────────────────────────────────────
function getConfig(): ScannerConfig {
    const cfg = vscode.workspace.getConfiguration('vyberguard');
    return {
        enableEntropy: cfg.get<boolean>('enableEntropyScanning', DEFAULT_CONFIG.enableEntropy),
        entropyThreshold: cfg.get<number>('entropyThreshold', DEFAULT_CONFIG.entropyThreshold),
        minimumTokenLength: cfg.get<number>('minimumTokenLength', DEFAULT_CONFIG.minimumTokenLength),
        customPatterns: cfg.get<Array<{ name: string; regex: string }>>('customPatterns', DEFAULT_CONFIG.customPatterns),
        whitelistPatterns: cfg.get<string[]>('whitelistPatterns', DEFAULT_CONFIG.whitelistPatterns),
    };
}


// ═════════════════════════════════════════════════════
//  Activation
// ═════════════════════════════════════════════════════
export function activate(context: vscode.ExtensionContext) {

    // ── Initialise subsystems ────────────────
    const outputChannel = Logger.init();
    context.subscriptions.push(outputChannel);

    StatusBar.init(context);
    DecorationProvider.init(context);

    // ── Sidebar Dashboard ────────────────
    const sidebarProvider = new SidebarProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('vyberguard.dashboard', sidebarProvider)
    );

    Logger.info(`Activated with ${SecretScanner.patternCount} built-in patterns.`);
    Logger.info('Ready to intercept secrets in chat, files, and .env context.');

    // ── AI Shield: restore previous session state ────────────
    const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath;
    if (workspacePath) {
        const shieldOn = AiShieldManager.check(workspacePath);
        StatusBar.setAiShield(shieldOn);
        sidebarProvider.setAiShield(shieldOn);
    }

    // ── Vibe Check: first-install workspace scan ─────────────
    const hasRunVibeCheck = context.globalState.get<boolean>('vyberguard.vibeCheckDone', false);
    if (!hasRunVibeCheck && workspacePath) {
        context.globalState.update('vyberguard.vibeCheckDone', true);
        setTimeout(async () => {
            const files = await vscode.workspace.findFiles(
                '**/*.{ts,js,tsx,jsx,py,env,json,yml,yaml,toml}',
                '{**/node_modules/**,**/.git/**,**/dist/**,**/out/**}'
            );
            const config = getConfig();
            let totalSecrets = 0;
            let fileCount = 0;
            for (const uri of files.slice(0, 50)) {
                try {
                    const bytes = await vscode.workspace.fs.readFile(uri);
                    const { secrets } = SecretScanner.redact(Buffer.from(bytes).toString('utf-8'), config);
                    if (secrets.size > 0) { totalSecrets += secrets.size; fileCount++; }
                } catch { /* skip */ }
            }
            if (totalSecrets > 0) {
                Logger.warn(`VIBE CHECK: Found ${totalSecrets} potential secret(s) across ${fileCount} file(s).`);
                vscode.window.showWarningMessage(
                    `🛡️ VyberGuard Vibe Check: Found ${totalSecrets} exposed secret(s) in ${fileCount} file(s). Enable AI Shield to protect them.`,
                    'Enable AI Shield', 'Scan Details'
                ).then(choice => {
                    if (choice === 'Enable AI Shield') { vscode.commands.executeCommand('vyberguard.enableAiShield'); }
                    if (choice === 'Scan Details') { vscode.commands.executeCommand('vyberguard.scanWorkspace'); }
                });
                StatusBar.setExposureBadge(totalSecrets);
            }
        }, 3000);
    }

    // ─────────────────────────────────────────
    // 1. Chat Participant
    // ─────────────────────────────────────────
    const vyberguard = vscode.chat.createChatParticipant(
        'vyberguard',
        async (request, _chatContext, stream, _token) => {

            // ── /context command ──
            if (request.command === 'context') {
                const workspaceFolders = vscode.workspace.workspaceFolders;
                if (!workspaceFolders) {
                    stream.markdown('🚫 No workspace folder open. Cannot scan for `.env` files.');
                    return;
                }

                StatusBar.setScanning();
                stream.progress('Scanning workspace for configuration files…');

                const redactedEnv = await EnvManager.getRedactedEnv();

                stream.markdown('🛡️ **VyberGuard Context Scanner**\n\n');
                stream.markdown('Below is a **redacted** view of your workspace environment files. ');
                stream.markdown('Keys are visible so the AI understands the shape, but all values are masked.\n\n');
                stream.markdown('```env\n' + redactedEnv + '\n```\n\n');
                stream.markdown('> *Real values never leave your machine.*');

                StatusBar.setSafe();
                Logger.info('CHAT: Served redacted .env context.');
                return;
            }

            // ── Standard prompt processing ──
            StatusBar.setScanning();
            const userPrompt = request.prompt;
            const config = getConfig();
            const { redactedText, secrets, detectedTypes } = SecretScanner.redact(userPrompt, config);

            if (secrets.size > 0) {
                // Store each secret securely in OS Keychain via VS Code SecretStorage
                for (const [placeholder, secretValue] of secrets) {
                    await context.secrets.store(placeholder, secretValue);
                }

                const typesList = Array.from(detectedTypes).join(', ');
                Logger.scan('Chat Prompt', secrets.size, Array.from(detectedTypes));
                Logger.redaction(secrets.size);
                StatusBar.setAlert(secrets.size);

                stream.markdown('🚨 **VyberGuard Security Intercept**\n\n');
                stream.markdown(`I intercepted your prompt and found **${secrets.size}** sensitive item(s).\n\n`);
                stream.markdown(`| Detail | Value |\n|---|---|\n`);
                stream.markdown(`| **Detected** | ${typesList} |\n`);
                stream.markdown(`| **Action** | Redacted & stored in OS Keychain |\n\n`);

                stream.markdown('**Sanitised Payload:**\n');
                stream.markdown('```\n' + redactedText + '\n```\n\n');

                stream.markdown('---\n');
                stream.markdown('> 💡 Paste the sanitised text into your editor, then use the button below to restore real values securely.\n\n');
                stream.markdown('[$(key) Restore Secrets in Active File](command:vyberguard.restoreSecrets)\n');

                return { metadata: { command: 'redacted' } };
            }

            // Clean — no secrets found
            StatusBar.setSafe();
            Logger.scan('Chat Prompt', 0, []);

            stream.markdown('🛡️ **VyberGuard — All Clear**\n\n');
            stream.markdown('No secrets detected in your prompt. Safe to proceed.\n\n');
            stream.markdown('> ' + userPrompt);

            return { metadata: { command: 'echo' } };
        }
    );

    vyberguard.iconPath = new vscode.ThemeIcon('shield');
    context.subscriptions.push(vyberguard);


    // ─────────────────────────────────────────
    // 2. Command: Restore Secrets
    // ─────────────────────────────────────────
    const restoreCmd = vscode.commands.registerCommand('vyberguard.restoreSecrets', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('VyberGuard: No active editor. Open the file containing placeholders first.');
            return;
        }

        const document = editor.document;
        const text = document.getText();
        const placeholderRegex = /{{SECRET_[a-z0-9]+}}/g;
        const matches = text.match(placeholderRegex);

        if (!matches) {
            vscode.window.showInformationMessage('🛡️ VyberGuard: No placeholders found in this file.');
            return;
        }

        let restoredText = text;
        let restoredCount = 0;
        const uniqueMatches = [...new Set(matches)];

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: '🛡️ VyberGuard — Restoring Secrets',
            cancellable: false,
        }, async () => {
            for (const placeholder of uniqueMatches) {
                const realValue = await context.secrets.get(placeholder);
                if (realValue) {
                    const count = restoredText.split(placeholder).length - 1;
                    if (count > 0) {
                        restoredText = restoredText.split(placeholder).join(realValue);
                        restoredCount += count;
                    }
                }
            }

            if (restoredCount > 0) {
                const fullRange = new vscode.Range(
                    document.positionAt(0),
                    document.positionAt(text.length)
                );
                await editor.edit((editBuilder) => editBuilder.replace(fullRange, restoredText));

                vscode.window.showInformationMessage(`🛡️ VyberGuard: Restored ${restoredCount} secret(s) successfully.`);
                Logger.restore(restoredCount);
                DecorationProvider.updateDecorations(editor);
                sidebarProvider.refresh();
            } else {
                vscode.window.showWarningMessage(
                    'VyberGuard: Found placeholders but could not retrieve values. ' +
                    'They may have expired or been stored in a different session.'
                );
            }
        });
    });


    // ─────────────────────────────────────────
    // 3. Command: Redact Active File
    // ─────────────────────────────────────────
    const redactFileCmd = vscode.commands.registerCommand('vyberguard.redactActiveFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('VyberGuard: No active editor found.');
            return;
        }

        const document = editor.document;
        const text = document.getText();
        const config = getConfig();

        StatusBar.setScanning();
        const { redactedText, secrets, detectedTypes } = SecretScanner.redact(text, config);

        if (secrets.size === 0) {
            vscode.window.showInformationMessage('🛡️ VyberGuard: No secrets found in this file.');
            StatusBar.setSafe();
            Logger.scan('Redact File', 0, []);
            return;
        }

        // ── Confirmation dialog (configurable) ──
        const confirmEnabled = vscode.workspace.getConfiguration('vyberguard').get<boolean>('confirmBeforeRedact', true);
        if (confirmEnabled) {
            const typesList = Array.from(detectedTypes).join(', ');
            const choice = await vscode.window.showWarningMessage(
                `VyberGuard found ${secrets.size} secret(s) [${typesList}]. Redact them now?`,
                { modal: true, detail: 'Real values will be stored in your OS Keychain and replaced with safe placeholders.' },
                'Redact', 'Cancel'
            );
            if (choice !== 'Redact') {
                StatusBar.setIdle();
                return;
            }
        }

        // Store secrets securely
        for (const [placeholder, secretValue] of secrets) {
            await context.secrets.store(placeholder, secretValue);
        }

        // Apply redaction to the editor
        const fullRange = new vscode.Range(
            document.positionAt(0),
            document.positionAt(text.length)
        );
        await editor.edit((editBuilder) => editBuilder.replace(fullRange, redactedText));

        const typesList = Array.from(detectedTypes).join(', ');
        vscode.window.showInformationMessage(
            `🛡️ VyberGuard: Redacted ${secrets.size} secret(s) [${typesList}]. ` +
            `Run "VyberGuard: Restore Secrets" to bring them back.`
        );

        StatusBar.setAlert(secrets.size);
        Logger.scan('Redact File', secrets.size, Array.from(detectedTypes));
        Logger.redaction(secrets.size);
        DecorationProvider.updateDecorations(editor);
        sidebarProvider.recordScan(secrets.size);
    });


    // ─────────────────────────────────────────
    // 4. Command: Redact Selection
    // ─────────────────────────────────────────
    const redactSelectionCmd = vscode.commands.registerCommand('vyberguard.redactSelection', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('VyberGuard: No active editor found.');
            return;
        }

        const selection = editor.selection;
        if (selection.isEmpty) {
            vscode.window.showInformationMessage('VyberGuard: No text selected.');
            return;
        }

        const selectedText = editor.document.getText(selection);
        const config = getConfig();

        StatusBar.setScanning();
        const { redactedText, secrets, detectedTypes } = SecretScanner.redact(selectedText, config);

        if (secrets.size === 0) {
            vscode.window.showInformationMessage('🛡️ VyberGuard: No secrets found in selection.');
            StatusBar.setSafe();
            return;
        }

        // Store & replace
        for (const [placeholder, secretValue] of secrets) {
            await context.secrets.store(placeholder, secretValue);
        }

        await editor.edit((editBuilder) => editBuilder.replace(selection, redactedText));

        const typesList = Array.from(detectedTypes).join(', ');
        vscode.window.showInformationMessage(
            `🛡️ VyberGuard: Redacted ${secrets.size} secret(s) in selection [${typesList}].`
        );

        StatusBar.setAlert(secrets.size);
        Logger.scan('Selection', secrets.size, Array.from(detectedTypes));
        Logger.redaction(secrets.size);
        DecorationProvider.updateDecorations(editor);
        sidebarProvider.recordScan(secrets.size);
    });


    // ─────────────────────────────────────────
    // 5. Command: Scan Workspace
    // ─────────────────────────────────────────
    const scanWorkspaceCmd = vscode.commands.registerCommand('vyberguard.scanWorkspace', async () => {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders) {
            vscode.window.showErrorMessage('VyberGuard: No workspace folder open.');
            return;
        }

        const config = getConfig();
        let totalSecrets = 0;
        const allTypes = new Set<string>();
        const findings: Array<{ file: string; count: number; types: string[] }> = [];

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: '🛡️ VyberGuard — Scanning Workspace',
            cancellable: true,
        }, async (progress, token) => {
            const files = await vscode.workspace.findFiles(
                '**/*.{ts,js,tsx,jsx,py,rb,go,java,cs,php,env,yaml,yml,json,toml,ini,cfg,conf,xml,properties}',
                '{**/node_modules/**,**/.git/**,**/dist/**,**/build/**,**/out/**,**/*.min.*}'
            );

            const total = files.length;
            let processed = 0;

            for (const uri of files) {
                if (token.isCancellationRequested) { break; }

                processed++;
                progress.report({
                    message: `${processed}/${total} files…`,
                    increment: (1 / total) * 100,
                });

                try {
                    const rawBytes = await vscode.workspace.fs.readFile(uri);
                    const content = Buffer.from(rawBytes).toString('utf-8');
                    const { secrets, detectedTypes } = SecretScanner.redact(content, config);

                    if (secrets.size > 0) {
                        const relPath = vscode.workspace.asRelativePath(uri);
                        totalSecrets += secrets.size;
                        const typesArr = Array.from(detectedTypes);
                        typesArr.forEach((t) => allTypes.add(t));
                        findings.push({ file: relPath, count: secrets.size, types: typesArr });
                    }
                } catch {
                    // Skip unreadable files
                }
            }
        });

        if (totalSecrets === 0) {
            vscode.window.showInformationMessage('🛡️ VyberGuard: Workspace is clean — no secrets detected!');
            StatusBar.setSafe();
            Logger.scan('Workspace', 0, []);
            sidebarProvider.recordScan(0);
        } else {
            // Show detailed findings in output channel
            Logger.warn(`WORKSPACE SCAN: Found ${totalSecrets} potential secret(s) in ${findings.length} file(s):`);
            for (const f of findings) {
                Logger.warn(`  📄 ${f.file}: ${f.count} secret(s) [${f.types.join(', ')}]`);
            }
            Logger.show();

            StatusBar.setAlert(totalSecrets);
            sidebarProvider.recordScan(totalSecrets, findings);
            vscode.window.showWarningMessage(
                `VyberGuard: Found ${totalSecrets} potential secret(s) in ${findings.length} file(s). See Output panel for details.`,
                'Show Log'
            ).then((choice) => {
                if (choice === 'Show Log') { Logger.show(); }
            });
        }
    });


    // ─────────────────────────────────────────
    // 6. Command: Show Log
    // ─────────────────────────────────────────
    const showLogCmd = vscode.commands.registerCommand('vyberguard.showLog', () => {
        Logger.show();
    });


    // ─────────────────────────────────────────
    // 7. Hover Provider for Placeholders
    // ─────────────────────────────────────────
    const hoverProvider = vscode.languages.registerHoverProvider('*', {
        provideHover(document, position) {
            const range = document.getWordRangeAtPosition(position, /{{SECRET_[a-z0-9]+}}/);
            if (range) {
                const md = new vscode.MarkdownString();
                md.isTrusted = true;
                md.supportHtml = true;
                md.appendMarkdown('### 🛡️ VyberGuard Secure Placeholder\n\n');
                md.appendMarkdown('This value has been redacted and stored in your **OS Keychain**.\n\n');
                md.appendMarkdown('| | |\n|---|---|\n');
                md.appendMarkdown('| **Status** | 🔒 Encrypted in vault |\n');
                md.appendMarkdown('| **Scope** | This VS Code session |\n\n');
                md.appendMarkdown('[$(key) Restore Secrets](command:vyberguard.restoreSecrets "Restore all secrets in this file")');
                return new vscode.Hover(md, range);
            }
        },
    });


    // ─────────────────────────────────────────
    // 8. File Save Watcher (warns on saving
    //    files that still contain raw secrets)
    // ─────────────────────────────────────────
    const saveWatcher = vscode.workspace.onWillSaveTextDocument((event) => {
        const config = getConfig();
        const text = event.document.getText();
        const { secrets, detectedTypes } = SecretScanner.redact(text, config);

        if (secrets.size > 0) {
            const typesList = Array.from(detectedTypes).join(', ');
            Logger.warn(`SAVE WARNING: ${vscode.workspace.asRelativePath(event.document.uri)} contains ${secrets.size} potential secret(s) [${typesList}]`);

            // Show a non-blocking warning — we don't want to prevent saves
            vscode.window.showWarningMessage(
                `🛡️ VyberGuard: This file may contain ${secrets.size} secret(s) [${typesList}]. ` +
                `Consider running "VyberGuard: Redact Active File" before sharing.`,
                'Redact Now', 'Dismiss'
            ).then((choice) => {
                if (choice === 'Redact Now') {
                    vscode.commands.executeCommand('vyberguard.redactActiveFile');
                }
            });
        }
    });


    // ─────────────────────────────────────────
    // 10. Command: Refresh Sidebar
    // ─────────────────────────────────────────
    const refreshSidebarCmd = vscode.commands.registerCommand('vyberguard.refreshSidebar', () => {
        sidebarProvider.refresh();
    });


    // ─────────────────────────────────────────
    // 11. Command: Sanitized Paste (Ctrl+Shift+V)
    //     Reads clipboard, strips secrets, pastes
    //     clean text into the active editor.
    //     Works with ANY chat interface!
    // ─────────────────────────────────────────
    const sanitizedPasteCmd = vscode.commands.registerCommand('vyberguard.sanitizedPaste', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('VyberGuard: No active editor to paste into.');
            return;
        }

        const clipboardText = await vscode.env.clipboard.readText();
        if (!clipboardText) {
            vscode.window.showInformationMessage('VyberGuard: Clipboard is empty.');
            return;
        }

        const config = getConfig();
        StatusBar.setScanning();
        const { redactedText, secrets, detectedTypes } = SecretScanner.redact(clipboardText, config);

        if (secrets.size > 0) {
            // Store secrets in keychain
            for (const [placeholder, secretValue] of secrets) {
                await context.secrets.store(placeholder, secretValue);
            }

            // Paste the sanitized version
            await editor.edit((editBuilder) => {
                editBuilder.replace(editor.selection, redactedText);
            });

            const typesList = Array.from(detectedTypes).join(', ');
            vscode.window.showWarningMessage(
                `🛡️ VyberGuard: Intercepted ${secrets.size} secret(s) from clipboard [${typesList}]. Pasted sanitized version.`,
                'Show Log'
            ).then((choice) => {
                if (choice === 'Show Log') { Logger.show(); }
            });

            StatusBar.setAlert(secrets.size);
            Logger.scan('Sanitized Paste', secrets.size, Array.from(detectedTypes));
            Logger.redaction(secrets.size);
            sidebarProvider.recordScan(secrets.size);
        } else {
            // No secrets — paste as normal
            await editor.edit((editBuilder) => {
                editBuilder.replace(editor.selection, clipboardText);
            });

            StatusBar.setSafe();
            Logger.scan('Sanitized Paste', 0, []);
        }

        DecorationProvider.updateDecorations(editor);
    });


    // ─────────────────────────────────────────
    // 12. Command: Copy Redacted
    //     Takes selected text (or entire file),
    //     scans it, puts redacted version on
    //     clipboard. User can then safely paste
    //     into any AI chat.
    // ─────────────────────────────────────────
    const copyRedactedCmd = vscode.commands.registerCommand('vyberguard.copyRedacted', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('VyberGuard: No active editor.');
            return;
        }

        // Use selection if available, otherwise entire file
        const selection = editor.selection;
        const text = selection.isEmpty
            ? editor.document.getText()
            : editor.document.getText(selection);

        const config = getConfig();
        StatusBar.setScanning();
        const { redactedText, secrets, detectedTypes } = SecretScanner.redact(text, config);

        if (secrets.size > 0) {
            // Store secrets in keychain for later restore
            for (const [placeholder, secretValue] of secrets) {
                await context.secrets.store(placeholder, secretValue);
            }

            await vscode.env.clipboard.writeText(redactedText);

            const typesList = Array.from(detectedTypes).join(', ');
            vscode.window.showInformationMessage(
                `🛡️ VyberGuard: Copied redacted text to clipboard — ${secrets.size} secret(s) removed [${typesList}]. Safe to paste into AI chat!`
            );

            StatusBar.setAlert(secrets.size);
            Logger.scan('Copy Redacted', secrets.size, Array.from(detectedTypes));
            Logger.redaction(secrets.size);
            sidebarProvider.recordScan(secrets.size);
        } else {
            // No secrets — copy as-is
            await vscode.env.clipboard.writeText(text);
            vscode.window.showInformationMessage('🛡️ VyberGuard: No secrets detected. Copied to clipboard as-is.');
            StatusBar.setSafe();
            Logger.scan('Copy Redacted', 0, []);
        }
    });


    // ─────────────────────────────────────────
    // 14. Command: Enable AI Shield
    // ─────────────────────────────────────────
    const enableAiShieldCmd = vscode.commands.registerCommand('vyberguard.enableAiShield', () => {
        if (!workspacePath) {
            vscode.window.showErrorMessage('VyberGuard: No workspace folder open.');
            return;
        }
        const created = AiShieldManager.enable(workspacePath);
        StatusBar.setAiShield(true);
        sidebarProvider.setAiShield(true);
        Logger.info(`AI Shield ENABLED — injected patterns into ${created} ignore file(s).`);
        vscode.window.showInformationMessage(
            `🛡️ VyberGuard AI Shield ON — AI indexers are now blocked from reading your secret files in ${created} ignore file(s).`
        );
    });

    // ─────────────────────────────────────────
    // 15. Command: Disable AI Shield
    // ─────────────────────────────────────────
    const disableAiShieldCmd = vscode.commands.registerCommand('vyberguard.disableAiShield', () => {
        if (!workspacePath) {
            vscode.window.showErrorMessage('VyberGuard: No workspace folder open.');
            return;
        }
        AiShieldManager.disable(workspacePath);
        StatusBar.setAiShield(false);
        sidebarProvider.setAiShield(false);
        Logger.info('AI Shield DISABLED.');
        vscode.window.showInformationMessage('🛡️ VyberGuard AI Shield OFF — AI indexers can now access all files.');
    });

    // ─────────────────────────────────────────
    // 16. Clipboard Sentry
    //     Polls clipboard every 3s when window
    //     is focused. Warns if a secret is
    //     detected, without touching the data.
    // ─────────────────────────────────────────
    let lastClipboardText = '';
    let clipboardWarningActive = false;
    const clipboardSentryInterval = setInterval(async () => {
        if (!vscode.window.state.focused) { return; }
        try {
            const text = await vscode.env.clipboard.readText();
            if (!text || text === lastClipboardText) { return; }
            lastClipboardText = text;
            const config = getConfig();
            const { secrets, detectedTypes } = SecretScanner.redact(text, config);
            if (secrets.size > 0 && !clipboardWarningActive) {
                clipboardWarningActive = true;
                sidebarProvider.setClipboardWarning(true);
                const typesList = Array.from(detectedTypes).join(', ');
                Logger.warn(`CLIPBOARD SENTRY: Detected ${secrets.size} secret(s) on clipboard [${typesList}]. Use Ctrl+Shift+C to safely copy.`);
                vscode.window.showWarningMessage(
                    `⚠️ VyberGuard: Secret detected on clipboard [${typesList}]. Use Ctrl+Shift+C to copy safely for AI chat!`,
                    'How?'
                ).then(choice => {
                    clipboardWarningActive = false;
                    sidebarProvider.setClipboardWarning(false);
                    if (choice === 'How?') {
                        vscode.window.showInformationMessage(
                            '1. Select the text in your editor.\n2. Press Ctrl+Shift+C (Copy Redacted).\n3. Paste into AI chat — secrets are replaced with safe placeholders.'
                        );
                    }
                });
            } else if (secrets.size === 0) {
                if (clipboardWarningActive) {
                    clipboardWarningActive = false;
                    sidebarProvider.setClipboardWarning(false);
                }
            }
        } catch { /* clipboard read failures are silent */ }
    }, 3000);
    context.subscriptions.push({ dispose: () => clearInterval(clipboardSentryInterval) });


    // ─────────────────────────────────────────
    // 13. Register all subscriptions
    // ─────────────────────────────────────────
    context.subscriptions.push(
        restoreCmd,
        redactFileCmd,
        redactSelectionCmd,
        scanWorkspaceCmd,
        showLogCmd,
        refreshSidebarCmd,
        sanitizedPasteCmd,
        copyRedactedCmd,
        enableAiShieldCmd,
        disableAiShieldCmd,
        hoverProvider,
        saveWatcher,
    );


    // Welcome toast on first activation
    Logger.info('All systems operational. Your secrets are protected.');
}


// ═════════════════════════════════════════════════════
//  Deactivation
// ═════════════════════════════════════════════════════
export function deactivate() {
    DecorationProvider.dispose();
    Logger.dispose();
}
