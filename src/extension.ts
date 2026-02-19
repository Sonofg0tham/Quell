import * as vscode from 'vscode';
import { SecretScanner } from './SecretScanner';

export function activate(context: vscode.ExtensionContext) {
    // 1. Define the Chat Participant
    const vibeguard = vscode.chat.createChatParticipant('vibeguard', async (request: vscode.ChatRequest, context: vscode.ChatContext, stream: vscode.ChatResponseStream, token: vscode.CancellationToken) => {

        const userPrompt = request.prompt;

        // 2. Scan for Secrets
        const secretDetected = SecretScanner.scan(userPrompt);

        if (secretDetected) {
            stream.markdown(`⚠️ **Security Alert**: ${secretDetected}\n\nI blocked this request to prevent leaking your secret.`);
            return { metadata: { command: 'blocked' } };
        }

        // 3. Echo Mode (if safe)
        stream.markdown(`🛡️ **VibeGuard Echo Mode**\n\nNo secrets detected. You sent: \n> ${userPrompt}`);

        return { metadata: { command: 'echo' } };
    });

    context.subscriptions.push(vibeguard);
}

export function deactivate() { }
