import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { SecretScanner } from '../packages/scanner/src';
import { EnvManager } from './EnvManager';
import { Logger } from './Logger';
import { StatusBar } from './StatusBar';
import { DecorationProvider } from './DecorationProvider';
import { SidebarProvider } from './SidebarProvider';
import { AiShieldManager } from './AiShieldManager';
import { DiagnosticProvider } from './DiagnosticProvider';
import { getConfig } from './configHelper';

// ─────────────────────────────────────────────────────
//  VaultIndex helpers  (globalState-backed enumeration for SecretStorage,
//  which has no native list/iterate API)
// ─────────────────────────────────────────────────────
const VAULT_INDEX_KEY = 'quell.vaultIndex';

async function vaultIndexAdd(context: vscode.ExtensionContext, placeholder: string): Promise<void> {
    const stored = context.globalState.get<string[]>(VAULT_INDEX_KEY, []);
    const index = new Set<string>(stored);
    if (!index.has(placeholder)) {
        index.add(placeholder);
        await context.globalState.update(VAULT_INDEX_KEY, Array.from(index));
    }
}

async function vaultIndexClear(context: vscode.ExtensionContext): Promise<void> {
    await context.globalState.update(VAULT_INDEX_KEY, []);
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
    DiagnosticProvider.init(context);

    // ── Sidebar Dashboard ────────────────
    const sidebarProvider = new SidebarProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('quell.dashboard', sidebarProvider)
    );

    Logger.info(`Activated with ${SecretScanner.patternCount} built-in patterns.`);
    Logger.info('Ready to intercept secrets in chat, files, and .env context.');

    // ── Session-scoped save warning dismissals (path → secret count at dismissal) ──
    const dismissedFiles = new Map<string, number>();

    // ── Track last active text editor (so sidebar buttons work) ──
    let lastActiveEditor = vscode.window.activeTextEditor;
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) { lastActiveEditor = editor; }
        })
    );

    // ── AI Shield: restore previous session state ────────────
    const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath;
    if (workspacePath) {
        const shieldOn = AiShieldManager.check(workspacePath);
        StatusBar.setAiShield(shieldOn);
        sidebarProvider.setAiShield(shieldOn);
    }

    // ── First install: open walkthrough + delayed vibe-check scan ──
    const isFirstInstall = !context.globalState.get<boolean>('quell.installed', false);
    if (isFirstInstall) {
        context.globalState.update('quell.installed', true);
        vscode.commands.executeCommand('workbench.action.openWalkthrough', 'Sonofg0tham.quell#quell.gettingStarted', false);
    }

    // ── Vibe Check: first-install workspace scan ─────────────
    if (isFirstInstall && workspacePath) {
        setTimeout(async () => {
            const files = await vscode.workspace.findFiles(
                '**/*.{ts,js,tsx,jsx,py,env,json,yml,yaml,toml}',
                '{**/node_modules/**,**/.git/**,**/dist/**,**/out/**}'
            );
            const config = getConfig();
            const totalFiles = files.length;
            let totalSecrets = 0;
            let fileCount = 0;

            await Promise.all(files.slice(0, 50).map(async (uri) => {
                try {
                    const bytes = await vscode.workspace.fs.readFile(uri);
                    const { secrets } = SecretScanner.redact(Buffer.from(bytes).toString('utf-8'), config);
                    if (secrets.size > 0) {
                        totalSecrets += secrets.size;
                        fileCount++;
                    }
                } catch { /* skip */ }
            }));

            const capNote = totalFiles > 50 ? ` (scanned 50 of ${totalFiles} files — run 'Scan Workspace' for a full audit)` : '';
            if (totalSecrets > 0) {
                Logger.warn(`VIBE CHECK: Found ${totalSecrets} potential secret(s) across ${fileCount} file(s).`);
                vscode.window.showWarningMessage(
                    `🛡️ Quell: Found ${totalSecrets} exposed secret(s) in ${fileCount} file(s).${capNote}`,
                    'Enable AI Shield', 'Scan Details'
                ).then(choice => {
                    if (choice === 'Enable AI Shield') { vscode.commands.executeCommand('quell.enableAiShield'); }
                    if (choice === 'Scan Details') { vscode.commands.executeCommand('quell.scanWorkspace'); }
                });
                StatusBar.setExposureBadge(totalSecrets);
            } else {
                Logger.info('VIBE CHECK: Workspace is clean.');
                vscode.window.showInformationMessage(`✅ Quell: Initial scan complete — no exposed secrets found.${capNote}`);
            }
        }, 5000);
    }

    // ─────────────────────────────────────────
    // 1. Chat Participant
    // ─────────────────────────────────────────
    const quell = vscode.chat.createChatParticipant(
        'quell',
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

                stream.markdown('## 🛡️ Quell Context Scanner\n\n');
                stream.markdown('I have analyzed your environment files. Below is a **safely redacted** view of your workspace configuration.\n\n');
                stream.markdown('> 💡 Key names are preserved so the AI understands the architecture, but all sensitive values are masked.\n\n');
                stream.markdown('```env\n' + redactedEnv + '\n```\n\n');
                stream.markdown('---\n');
                stream.markdown('✨ *Real values never leave your machine.*');

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
                    await vaultIndexAdd(context, placeholder);
                }

                const typesList = Array.from(detectedTypes).join(', ');
                Logger.scan('Chat Prompt', secrets.size, Array.from(detectedTypes));
                Logger.redaction(secrets.size);
                StatusBar.setAlert(secrets.size);

                stream.markdown('## 🚨 Quell Security Intercept\n\n');
                stream.markdown(`I intercepted your prompt and found **${secrets.size}** sensitive item(s) that should not be shared with AI models.\n\n`);
                
                stream.markdown(`| Detail | Description |\n|:---|:---|\n`);
                stream.markdown(`| **Detected** | ${typesList} |\n`);
                stream.markdown(`| **Protection** | Redacted & stored in OS Keychain |\n\n`);

                stream.markdown('### 🛡️ Sanitized Payload\n');
                stream.markdown('Copy the text below into your chat window:\n\n');
                stream.markdown('```\n' + redactedText + '\n```\n\n');

                stream.markdown('---\n');
                stream.markdown('**✨ Next Step:** After pasting the safe version above, use the button below to restore the real secrets in your editor.\n\n');
                stream.markdown('[$(key) Restore Secrets in Active File](command:quell.restoreSecrets)\n');

                return { metadata: { command: 'redacted' } };
            }

            // Clean — no secrets found
            StatusBar.setSafe();
            Logger.scan('Chat Prompt', 0, []);

            stream.markdown('## ✨ Quell — All Clear\n\n');
            stream.markdown('No secrets detected in your prompt. Your data is safe to share with the AI model.\n\n');
            stream.markdown('**Your Prompt:**\n');
            stream.markdown('> ' + userPrompt);

            return { metadata: { command: 'echo' } };
        }
    );

    quell.iconPath = new vscode.ThemeIcon('shield');
    context.subscriptions.push(quell);


    // ─────────────────────────────────────────
    // 2. Command: Restore Secrets
    // ─────────────────────────────────────────
    const restoreCmd = vscode.commands.registerCommand('quell.restoreSecrets', async () => {
        const editor = vscode.window.activeTextEditor || lastActiveEditor;
        if (!editor) {
            vscode.window.showErrorMessage('Quell: No active editor. Open the file containing placeholders first.');
            return;
        }

        const document = editor.document;
        const text = document.getText();
        const placeholderRegex = /{{SECRET_[a-z0-9]+}}/g;
        const matches = text.match(placeholderRegex);

        if (!matches) {
            vscode.window.showInformationMessage('🛡️ Quell: No placeholders found in this file.');
            return;
        }

        let restoredText = text;
        let restoredCount = 0;
        const uniqueMatches = [...new Set(matches)];

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: '🛡️ Quell — Restoring Secrets',
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

                vscode.window.showInformationMessage(`🛡️ Quell: Restored ${restoredCount} secret(s) successfully.`);
                Logger.restore(restoredCount);
                DecorationProvider.updateDecorations(editor);
                sidebarProvider.refresh();
            } else {
                vscode.window.showWarningMessage(
                    'Quell: Found placeholders but could not retrieve values. ' +
                    'They may have expired or been stored in a different session.'
                );
            }
        });
    });


    // ─────────────────────────────────────────
    // 3. Command: Redact Active File
    // ─────────────────────────────────────────
    const redactFileCmd = vscode.commands.registerCommand('quell.redactActiveFile', async () => {
        const editor = vscode.window.activeTextEditor || lastActiveEditor;
        if (!editor) {
            vscode.window.showErrorMessage('Quell: No active editor found.');
            return;
        }

        const document = editor.document;
        const text = document.getText();
        const config = getConfig();

        StatusBar.setScanning();
        const { redactedText, secrets, detectedTypes } = SecretScanner.redact(text, config);

        if (secrets.size === 0) {
            vscode.window.showInformationMessage('🛡️ Quell: No secrets found in this file.');
            StatusBar.setSafe();
            Logger.scan('Redact File', 0, []);
            return;
        }

        // ── Confirmation dialog (configurable) ──
        const confirmEnabled = vscode.workspace.getConfiguration('quell').get<boolean>('confirmBeforeRedact', false);
        if (confirmEnabled) {
            const typesList = Array.from(detectedTypes).join(', ');
            const choice = await vscode.window.showWarningMessage(
                `Quell found ${secrets.size} secret(s) [${typesList}]. Redact them now?`,
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
            await vaultIndexAdd(context, placeholder);
        }

        // Apply redaction to the editor
        const fullRange = new vscode.Range(
            document.positionAt(0),
            document.positionAt(text.length)
        );
        await editor.edit((editBuilder) => editBuilder.replace(fullRange, redactedText));

        const typesList = Array.from(detectedTypes).join(', ');
        vscode.window.showInformationMessage(
            `🛡️ Quell: Redacted ${secrets.size} secret(s) [${typesList}]. ` +
            `Run "Quell: Restore Secrets" to bring them back.`
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
    const redactSelectionCmd = vscode.commands.registerCommand('quell.redactSelection', async () => {
        const editor = vscode.window.activeTextEditor || lastActiveEditor;
        if (!editor) {
            vscode.window.showErrorMessage('Quell: No active editor found.');
            return;
        }

        const selection = editor.selection;
        if (selection.isEmpty) {
            vscode.window.showInformationMessage('Quell: No text selected.');
            return;
        }

        const selectedText = editor.document.getText(selection);
        const config = getConfig();

        StatusBar.setScanning();
        const { redactedText, secrets, detectedTypes } = SecretScanner.redact(selectedText, config);

        if (secrets.size === 0) {
            vscode.window.showInformationMessage('🛡️ Quell: No secrets found in selection.');
            StatusBar.setSafe();
            return;
        }

        // Store & replace
        for (const [placeholder, secretValue] of secrets) {
            await context.secrets.store(placeholder, secretValue);
            await vaultIndexAdd(context, placeholder);
        }

        await editor.edit((editBuilder) => editBuilder.replace(selection, redactedText));

        const typesList = Array.from(detectedTypes).join(', ');
        vscode.window.showInformationMessage(
            `🛡️ Quell: Redacted ${secrets.size} secret(s) in selection [${typesList}].`
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
    const scanWorkspaceCmd = vscode.commands.registerCommand('quell.scanWorkspace', async () => {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders) {
            vscode.window.showErrorMessage('Quell: No workspace folder open.');
            return;
        }

        const config = getConfig();
        let totalSecrets = 0;
        const allTypes = new Set<string>();
        const findings: Array<{ file: string; count: number; types: string[] }> = [];

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: '🛡️ Quell — Scanning Workspace',
            cancellable: true,
        }, async (progress, token) => {
            const files = await vscode.workspace.findFiles(
                '**/*.{ts,js,tsx,jsx,py,rb,go,java,cs,php,env,yaml,yml,json,toml,ini,cfg,conf,xml,properties}',
                '{**/node_modules/**,**/.git/**,**/dist/**,**/build/**,**/out/**,**/*.min.*,**/package-lock.json,**/yarn.lock,**/pnpm-lock.yaml,**/.next*/**,**/.nuxt/**,**/.vercel/**,**/_next/**,**/static/chunks/**}'
            );

            const total = files.length;
            let processed = 0;
            const CONCURRENCY_LIMIT = 5;

            // Process files in batches to prevent EMFILE/OOM and allow cancellation
            for (let i = 0; i < total; i += CONCURRENCY_LIMIT) {
                if (token.isCancellationRequested) { break; }
                const batch = files.slice(i, i + CONCURRENCY_LIMIT);

                await Promise.all(batch.map(async (uri) => {
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
                    } finally {
                        processed++;
                        progress.report({
                            message: `${processed}/${total} files…`,
                            increment: (1 / total) * 100,
                        });
                    }
                }));
            }
        });

        if (totalSecrets === 0) {
            vscode.window.showInformationMessage('🛡️ Quell: Workspace is clean — no secrets detected!');
            StatusBar.setSafe();
            Logger.scan('Workspace', 0, []);
            sidebarProvider.recordScan(0);
        } else {
            // Show summary finding in output channel
            Logger.warn(`WORKSPACE SCAN: Found ${totalSecrets} potential secret(s) in ${findings.length} file(s).`);

            StatusBar.setAlert(totalSecrets);
            sidebarProvider.recordScan(totalSecrets, findings);
            vscode.window.showWarningMessage(
                `Quell: Found ${totalSecrets} potential secret(s) in ${findings.length} file(s). See Quell dashboard for details.`
            );
        }
    });


    // ─────────────────────────────────────────
    // 6. Command: Show Log
    // ─────────────────────────────────────────
    const showLogCmd = vscode.commands.registerCommand('quell.showLog', () => {
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
                md.appendMarkdown('### 🛡️ Quell Secure Placeholder\n\n');
                md.appendMarkdown('This value has been redacted and stored in your **OS Keychain**.\n\n');
                md.appendMarkdown('| | |\n|---|---|\n');
                md.appendMarkdown('| **Status** | 🔒 Encrypted in vault |\n');
                md.appendMarkdown('| **Scope** | Persisted in OS Keychain |\n\n');
                md.appendMarkdown('[$(key) Restore Secrets](command:quell.restoreSecrets "Restore all secrets in this file")');
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

        // Skip large files to avoid blocking the save with a synchronous scan.
        const MAX_SAVE_SCAN_BYTES = 1_000_000; // 1 MB
        if (text.length > MAX_SAVE_SCAN_BYTES) {
            Logger.info(`SAVE SCAN: Skipped ${vscode.workspace.asRelativePath(event.document.uri)} — file exceeds 1MB size limit.`);
            return;
        }

        const { secrets, detectedTypes } = SecretScanner.redact(text, config);

        if (secrets.size > 0) {
            const filePath = event.document.uri.fsPath;
            const prevCount = dismissedFiles.get(filePath);
            if (prevCount !== undefined && prevCount === secrets.size) { return; }

            const typesList = Array.from(detectedTypes).join(', ');
            Logger.warn(`SAVE WARNING: ${vscode.workspace.asRelativePath(event.document.uri)} contains ${secrets.size} potential secret(s) [${typesList}]`);

            // Show a non-blocking warning — we don't want to prevent saves
            vscode.window.showWarningMessage(
                `🛡️ Quell: This file may contain ${secrets.size} secret(s) [${typesList}]. ` +
                `Consider running "Quell: Redact Active File" before sharing.`,
                'Redact Now', 'Dismiss for this session'
            ).then((choice) => {
                if (choice === 'Redact Now') {
                    vscode.commands.executeCommand('quell.redactActiveFile');
                } else if (choice === 'Dismiss for this session') {
                    dismissedFiles.set(filePath, secrets.size);
                }
            });
        }
    });


    // ─────────────────────────────────────────
    // 10. Command: Refresh Sidebar
    // ─────────────────────────────────────────
    const refreshSidebarCmd = vscode.commands.registerCommand('quell.refreshSidebar', () => {
        sidebarProvider.refresh();
    });


    // ─────────────────────────────────────────
    // 11. Command: Sanitized Paste (Ctrl+Shift+V)
    //     Reads clipboard, strips secrets, pastes
    //     clean text into the active editor.
    //     Works with ANY chat interface!
    // ─────────────────────────────────────────
    const sanitizedPasteCmd = vscode.commands.registerCommand('quell.sanitizedPaste', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('Quell: No active editor to paste into.');
            return;
        }

        const clipboardText = await vscode.env.clipboard.readText();
        if (!clipboardText) {
            vscode.window.showInformationMessage('Quell: Clipboard is empty.');
            return;
        }

        const config = getConfig();
        StatusBar.setScanning();
        const { redactedText, secrets, detectedTypes } = SecretScanner.redact(clipboardText, config);

        if (secrets.size > 0) {
            // Store secrets in keychain
            for (const [placeholder, secretValue] of secrets) {
                await context.secrets.store(placeholder, secretValue);
                await vaultIndexAdd(context, placeholder);
            }

            // Paste the sanitized version
            await editor.edit((editBuilder) => {
                editBuilder.replace(editor.selection, redactedText);
            });

            const typesList = Array.from(detectedTypes).join(', ');
            vscode.window.showWarningMessage(
                `🛡️ Quell: Intercepted ${secrets.size} secret(s) from clipboard [${typesList}]. Pasted sanitized version.`,
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
    const copyRedactedCmd = vscode.commands.registerCommand('quell.copyRedacted', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('Quell: No active editor.');
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
                await vaultIndexAdd(context, placeholder);
            }

            await vscode.env.clipboard.writeText(redactedText);

            const typesList = Array.from(detectedTypes).join(', ');
            vscode.window.showInformationMessage(
                `🛡️ Quell: Copied redacted text to clipboard — ${secrets.size} secret(s) removed [${typesList}]. Safe to paste into AI chat!`
            );

            StatusBar.setAlert(secrets.size);
            Logger.scan('Copy Redacted', secrets.size, Array.from(detectedTypes));
            Logger.redaction(secrets.size);
            sidebarProvider.recordScan(secrets.size);
        } else {
            // No secrets — copy as-is
            await vscode.env.clipboard.writeText(text);
            vscode.window.showInformationMessage('🛡️ Quell: No secrets detected. Copied to clipboard as-is.');
            StatusBar.setSafe();
            Logger.scan('Copy Redacted', 0, []);
        }
    });


    // ─────────────────────────────────────────
    // 14. Command: Enable AI Shield
    // ─────────────────────────────────────────
    const enableAiShieldCmd = vscode.commands.registerCommand('quell.enableAiShield', () => {
        if (!workspacePath) {
            vscode.window.showErrorMessage('Quell: No workspace folder open.');
            return;
        }
        const created = AiShieldManager.enable(workspacePath);
        StatusBar.setAiShield(true);
        sidebarProvider.setAiShield(true);
        Logger.info(`AI Shield ENABLED — injected patterns into ${created} ignore file(s).`);
        vscode.window.showInformationMessage(
            `🛡️ Quell AI Shield ON — AI indexers are now blocked from reading your secret files in ${created} ignore file(s).`
        );
    });

    // ─────────────────────────────────────────
    // 15. Command: Disable AI Shield
    // ─────────────────────────────────────────
    const disableAiShieldCmd = vscode.commands.registerCommand('quell.disableAiShield', () => {
        if (!workspacePath) {
            vscode.window.showErrorMessage('Quell: No workspace folder open.');
            return;
        }
        AiShieldManager.disable(workspacePath);
        StatusBar.setAiShield(false);
        sidebarProvider.setAiShield(false);
        Logger.info('AI Shield DISABLED.');
        vscode.window.showInformationMessage('🛡️ Quell AI Shield OFF — AI indexers can now access all files.');
    });

    // ─────────────────────────────────────────
    // 16. Clipboard Sentry
    // ─────────────────────────────────────────
    // 16. Clipboard Sentry & Auto-Sanitizer
    //     Polls clipboard when window is focused.
    //     If autoSanitizeClipboard is enabled, it
    //     instantly strips secrets from clipboard
    //     and stores them securely.
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
            const autoSanitize = vscode.workspace.getConfiguration('quell').get<boolean>('autoSanitizeClipboard', false);
            const { secrets, detectedTypes, redactedText } = SecretScanner.redact(text, config);
            
            if (secrets.size > 0) {
                const typesList = Array.from(detectedTypes).join(', ');
                
                if (autoSanitize) {
                    // Auto-Sanitize: Overwrite clipboard with safe placeholders
                    for (const [placeholder, secretValue] of secrets) {
                        await context.secrets.store(placeholder, secretValue);
                        await vaultIndexAdd(context, placeholder);
                    }
                    await vscode.env.clipboard.writeText(redactedText);
                    lastClipboardText = redactedText; // prevent infinite loop
                    
                    Logger.warn(`CLIPBOARD SENTRY: Auto-sanitized ${secrets.size} secret(s) [${typesList}].`);
                    vscode.window.withProgress(
                        { location: vscode.ProgressLocation.Notification, title: `🛡️ Quell: Auto-sanitized ${secrets.size} secret(s) [${typesList}]. Safe to paste.`, cancellable: false },
                        () => new Promise(resolve => setTimeout(resolve, 5000))
                    );
                    
                    StatusBar.setAlert(secrets.size);
                    Logger.scan('Clipboard Auto-Sanitize', secrets.size, Array.from(detectedTypes));
                    sidebarProvider.recordScan(secrets.size);
                    
                } else {
                    // Just warn (Legacy behavior)
                    if (!clipboardWarningActive) {
                        clipboardWarningActive = true;
                        sidebarProvider.setClipboardWarning(true);
                        Logger.warn(`CLIPBOARD SENTRY: Detected ${secrets.size} secret(s) on clipboard [${typesList}]. Use Ctrl+Shift+C to safely copy.`);
                        vscode.window.showWarningMessage(
                            `⚠️ Quell: Secret detected on clipboard [${typesList}]. Enable 'Auto Sanitize Clipboard' in settings to protect AI chats!`,
                            'Enable Auto-Sanitize', 'How to copy safely?'
                        ).then(choice => {
                            clipboardWarningActive = false;
                            sidebarProvider.setClipboardWarning(false);
                            if (choice === 'Enable Auto-Sanitize') {
                                vscode.workspace.getConfiguration('quell').update('autoSanitizeClipboard', true, vscode.ConfigurationTarget.Global);
                                vscode.window.showInformationMessage('🛡️ Quell: Auto-sanitize enabled. Future secrets will be instantly protected.');
                            } else if (choice === 'How to copy safely?') {
                                vscode.window.showInformationMessage(
                                    '1. Select the text in your editor.\n2. Press Ctrl+Shift+C (Copy Redacted).\n3. Paste into AI chat — secrets are replaced with safe placeholders.'
                                );
                            }
                        });
                    }
                }
            } else if (secrets.size === 0) {
                if (clipboardWarningActive) {
                    clipboardWarningActive = false;
                    sidebarProvider.setClipboardWarning(false);
                }
            }
        } catch { /* clipboard read failures are silent */ }
    }, 1000);
    context.subscriptions.push({ dispose: () => clearInterval(clipboardSentryInterval) });


    // ─────────────────────────────────────────
    // 17. Command: Open File
    // ─────────────────────────────────────────
    const openFileCmd = vscode.commands.registerCommand('quell.openFile', async (relPath: string) => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) return;
        const uri = vscode.Uri.joinPath(workspaceFolders[0].uri, relPath);
        const doc = await vscode.workspace.openTextDocument(uri);
        await vscode.window.showTextDocument(doc);
    });

    // ─────────────────────────────────────────
    // 18. Command: Redact Single Secret (Quick Fix)
    //     Called by DiagnosticProvider code action
    //     to redact one specific secret by range.
    // ─────────────────────────────────────────
    const redactSingleSecretCmd = vscode.commands.registerCommand(
        'quell.redactSingleSecret',
        async (uriString: string, startLine: number, startChar: number, endLine: number, endChar: number, secretValue: string) => {
            const uri = vscode.Uri.parse(uriString);
            const range = new vscode.Range(
                new vscode.Position(startLine, startChar),
                new vscode.Position(endLine, endChar)
            );

            // Verify the secret is still at that range before replacing
            const doc = await vscode.workspace.openTextDocument(uri);
            if (doc.getText(range) !== secretValue) { return; }

            const uuid = crypto.randomUUID().replace(/-/g, '').substring(0, 16);
            const placeholder = `{{SECRET_${uuid}}}`;
            await context.secrets.store(placeholder, secretValue);
            await vaultIndexAdd(context, placeholder);

            const edit = new vscode.WorkspaceEdit();
            edit.replace(uri, range, placeholder);
            await vscode.workspace.applyEdit(edit);

            Logger.info(`Redacted single secret [Quick Fix] → ${placeholder}`);
            StatusBar.setAlert(1);
            setTimeout(() => StatusBar.setSafe(), 4000);

            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor && activeEditor.document.uri.toString() === uriString) {
                DecorationProvider.updateDecorations(activeEditor);
            }
            sidebarProvider.recordScan(1);
        }
    );

    // ─────────────────────────────────────────
    // 19. Command: Toggle Auto-Sanitize
    // ─────────────────────────────────────────

    const toggleAutoSanitizeCmd = vscode.commands.registerCommand('quell.toggleAutoSanitize', async () => {
        const config = vscode.workspace.getConfiguration('quell');
        const current = config.get<boolean>('autoSanitizeClipboard', false);
        await config.update('autoSanitizeClipboard', !current, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage(
            `🛡️ Quell: Clipboard Auto-Sanitize is now ${!current ? 'ENABLED' : 'DISABLED'}.`
        );
        sidebarProvider.refresh();
    });

    // ─────────────────────────────────────────
    // 20. Command: Open Demo File (walkthrough)
    // ─────────────────────────────────────────
    const openDemoCmd = vscode.commands.registerCommand('quell.openDemo', async () => {
        const doc = await vscode.workspace.openTextDocument({
            language: 'plaintext',
            content: [
                '# Quell Demo — fake credentials for testing (safe to share)',
                '# Watch the yellow squiggles appear, then press Ctrl+. for Quick Fix',
                '',
                '# GitHub Personal Access Token (fake)',
                'GITHUB_TOKEN=ghp_ABCDEFabcdef1234567890abcdef123456',
                '',
                '# PostgreSQL connection string (fake)',
                'DATABASE_URL=postgresql://admin:S3cr3tP4ssw0rd@db.example.com:5432/myapp',
                '',
                '# OpenAI Project Key (fake)',
                'OPENAI_API_KEY=sk-proj-ABCDEFabcdef1234567890ABCDEFabcdef1234567890ab',
            ].join('\n'),
        });
        await vscode.window.showTextDocument(doc);
    });

    // ─────────────────────────────────────────
    // 21. Command: Clear Vault
    // ─────────────────────────────────────────
    const clearVaultCmd = vscode.commands.registerCommand('quell.clearVault', async () => {
        const index: string[] = context.globalState.get<string[]>(VAULT_INDEX_KEY, []);
        if (index.length === 0) {
            vscode.window.showInformationMessage('🛡️ Quell: Vault is already empty.');
            return;
        }
        const answer = await vscode.window.showWarningMessage(
            `🛡️ Quell: This will permanently delete ${index.length} stored secret(s) from the keychain. The placeholders in your files will remain but can no longer be restored. Continue?`,
            { modal: true },
            'Delete all secrets'
        );
        if (answer !== 'Delete all secrets') { return; }
        for (const ph of index) {
            await context.secrets.delete(ph);
        }
        await vaultIndexClear(context);
        Logger.info(`Vault cleared — deleted ${index.length} secret(s).`);
        vscode.window.showInformationMessage(`🛡️ Quell: Vault cleared. ${index.length} secret(s) removed.`);
        sidebarProvider.refresh();
    });

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
        openFileCmd,
        toggleAutoSanitizeCmd,
        redactSingleSecretCmd,
        openDemoCmd,
        clearVaultCmd
    );


    // Welcome toast on first activation
    Logger.info('All systems operational. Your secrets are protected.');
}


// ═════════════════════════════════════════════════════
//  Deactivation
// ═════════════════════════════════════════════════════
export function deactivate() {
    DecorationProvider.dispose();
    DiagnosticProvider.dispose();
    Logger.dispose();
}
