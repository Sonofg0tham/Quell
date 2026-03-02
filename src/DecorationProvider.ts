import * as vscode from 'vscode';

/**
 * Provides inline editor decorations for VyberGuard placeholders.
 * When a file contains {{SECRET_xxx}} tokens, they get highlighted
 * with an orange dashed border and a lock icon so they're unmissable.
 */
export class DecorationProvider {
    private static placeholderDecorationType: vscode.TextEditorDecorationType;
    private static disposables: vscode.Disposable[] = [];

    public static init(context: vscode.ExtensionContext): void {
        this.placeholderDecorationType = vscode.window.createTextEditorDecorationType({
            backgroundColor: 'rgba(255, 165, 0, 0.15)',
            border: '1px dashed rgba(255, 165, 0, 0.6)',
            borderRadius: '3px',
            overviewRulerColor: 'rgba(255, 165, 0, 0.8)',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            after: {
                contentText: ' 🔒',
                color: 'rgba(255, 165, 0, 0.8)',
                fontStyle: 'normal',
            },
        });

        // Refresh decorations on editor change
        this.disposables.push(
            vscode.window.onDidChangeActiveTextEditor((editor) => {
                if (editor) {
                    this.updateDecorations(editor);
                }
            }),
            vscode.workspace.onDidChangeTextDocument((event) => {
                const editor = vscode.window.activeTextEditor;
                if (editor && event.document === editor.document) {
                    this.updateDecorations(editor);
                }
            })
        );

        // Decorate the currently active editor on init
        if (vscode.window.activeTextEditor) {
            this.updateDecorations(vscode.window.activeTextEditor);
        }

        context.subscriptions.push(...this.disposables);
    }

    /** Scans the document for placeholder tokens and applies decorations */
    public static updateDecorations(editor: vscode.TextEditor): void {
        const config = vscode.workspace.getConfiguration('vyberguard');
        if (!config.get<boolean>('showInlineDecorations', true)) {
            editor.setDecorations(this.placeholderDecorationType, []);
            return;
        }

        const text = editor.document.getText();
        const decorations: vscode.DecorationOptions[] = [];
        const regex = /{{SECRET_[a-z0-9]+}}/g;
        let match: RegExpExecArray | null;

        while ((match = regex.exec(text)) !== null) {
            const startPos = editor.document.positionAt(match.index);
            const endPos = editor.document.positionAt(match.index + match[0].length);

            const hoverMsg = new vscode.MarkdownString();
            hoverMsg.isTrusted = true;
            hoverMsg.appendMarkdown('**🛡️ VyberGuard Secure Placeholder**\n\n');
            hoverMsg.appendMarkdown('The real secret is stored in your OS Keychain.\n\n');
            hoverMsg.appendMarkdown('[Restore Secrets](command:vyberguard.restoreSecrets "Restore all secrets in this file")');

            decorations.push({
                range: new vscode.Range(startPos, endPos),
                hoverMessage: hoverMsg,
            });
        }

        editor.setDecorations(this.placeholderDecorationType, decorations);
    }

    public static clearAll(): void {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            editor.setDecorations(this.placeholderDecorationType, []);
        }
    }

    public static dispose(): void {
        this.placeholderDecorationType?.dispose();
        this.disposables.forEach((d) => d.dispose());
    }
}
