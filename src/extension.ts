import * as vscode from 'vscode';
import { SecretScanner } from './SecretScanner';
import { EnvManager } from './EnvManager';

export function activate(extContext: vscode.ExtensionContext) {
    // 1. Define the Chat Participant
    const vibeguard = vscode.chat.createChatParticipant('vibeguard', async (request: vscode.ChatRequest, context: vscode.ChatContext, stream: vscode.ChatResponseStream, token: vscode.CancellationToken) => {

        const userPrompt = request.prompt;

        // Command: /context (Custom command handling example)
        if (request.command === 'context') {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders) {
                stream.markdown('No workspace folder open. Cannot read .env context.');
                return { metadata: { command: 'no-workspace' } };
            }

            const redactedEnv = await EnvManager.getRedactedEnv(workspaceFolders[0].uri);
            stream.markdown(`🛡️ **VibeGuard Context**\n\nHere is the safe version of your \`.env\` file:\n\n`);
            stream.markdown('```env\n' + redactedEnv + '\n```');
            return { metadata: { command: 'shared-context' } };
        }

        // 2. Redact Secrets
        const { redactedText, secrets } = SecretScanner.redact(userPrompt);

        if (secrets.size > 0) {
            // Securely store the secrets
            for (const [placeholder, realValue] of secrets) {
                await extContext.secrets.store(placeholder, realValue);
            }

            stream.markdown(`🛡️ **VibeGuard Secured**\n\nI detected **${secrets.size}** secret(s) and redacted them before processing.\n\n`);
            stream.markdown(`**Sanitized Prompt Sent:**\n> ${redactedText}\n\n`);
            stream.markdown(`Use the command \`VibeGuard: Restore Secrets\` to reveal them in your active file if needed.`);

            // In a real app, you would send 'redactedText' to the LLM here.
            // For this demo, we just echo it.
            return { metadata: { command: 'redacted-echo' } };
        }

        // 3. Echo Mode (if safe)
        stream.markdown(`🛡️ **VibeGuard Echo Mode**\n\nNo secrets detected. You sent: \n> ${userPrompt}`);

        return { metadata: { command: 'echo' } };
    });

    extContext.subscriptions.push(vibeguard);

    // 4. Register Restore Command
    let restoreDisposable = vscode.commands.registerCommand('vibeguard.restoreSecrets', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor found to restore secrets into.');
            return;
        }

        const document = editor.document;
        const fullText = document.getText();
        let restoredText = fullText;
        let restoredCount = 0;

        // Naive scan for any {{SECRET_X}} pattern in the file
        const secretRegex = /\{\{SECRET_\d+\}\}/g;
        const matches = fullText.match(secretRegex);

        if (matches) {
            // We use a Set to avoid replacing the same placeholder multiple times redundantly,
            // though string.replace only does one at a time unless global regex used.
            // Better: Iterate unique placeholders.
            const uniquePlaceholders = [...new Set(matches)];

            for (const placeholder of uniquePlaceholders) {
                const realValue = await extContext.secrets.get(placeholder);
                if (realValue) {
                    // Global replace for this specific placeholder
                    // Escape braces for regex
                    const escapedPlaceholder = placeholder.replace(/\{/g, '\\{').replace(/\}/g, '\\}');
                    const currentPlaceholderRegex = new RegExp(escapedPlaceholder, 'g');

                    // Check if it's still in the text (could have been part of another replacement, unlikely with this format)
                    if (currentPlaceholderRegex.test(restoredText)) {
                        // Count occurrences
                        const count = (restoredText.match(currentPlaceholderRegex) || []).length;
                        restoredText = restoredText.replace(currentPlaceholderRegex, realValue);
                        restoredCount += count;
                    }
                }
            }
        }

        if (restoredCount > 0) {
            const fullRange = new vscode.Range(
                document.positionAt(0),
                document.positionAt(fullText.length)
            );

            await editor.edit(editBuilder => {
                editBuilder.replace(fullRange, restoredText);
            });
            vscode.window.showInformationMessage(`Restored ${restoredCount} secrets successfully.`);
        } else {
            vscode.window.showInformationMessage('No active secrets found to restore.');
        }
    });

    extContext.subscriptions.push(restoreDisposable);
}

export function deactivate() { }
