import * as vscode from 'vscode';
import { SecretScanner, ScannerConfig, DEFAULT_CONFIG } from './SecretScanner';

export class DiagnosticProvider implements vscode.CodeActionProvider {
    private static collection: vscode.DiagnosticCollection;
    private static disposables: vscode.Disposable[] = [];
    private static timeout: NodeJS.Timeout | undefined;
    // Maps "uriString:startLine:startChar" → secret value for per-secret Quick Fix
    private static secretRangeMap = new Map<string, string>();

    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    public static init(context: vscode.ExtensionContext): void {
        this.collection = vscode.languages.createDiagnosticCollection('quell');
        this.disposables.push(this.collection);

        this.disposables.push(
            vscode.window.onDidChangeActiveTextEditor(editor => {
                if (editor) { this.updateDiagnostics(editor.document); }
            }),
            vscode.workspace.onDidChangeTextDocument(event => {
                const doc = event.document;
                if (this.timeout) { clearTimeout(this.timeout); }
                this.timeout = setTimeout(() => {
                    const activeEditor = vscode.window.activeTextEditor;
                    if (activeEditor && activeEditor.document === doc) {
                        this.updateDiagnostics(doc);
                    }
                }, 500);
            })
        );

        if (vscode.window.activeTextEditor) {
            this.updateDiagnostics(vscode.window.activeTextEditor.document);
        }

        context.subscriptions.push(
            vscode.languages.registerCodeActionsProvider('*', new DiagnosticProvider(), {
                providedCodeActionKinds: DiagnosticProvider.providedCodeActionKinds
            })
        );

        context.subscriptions.push(...this.disposables);
    }

    public static updateDiagnostics(document: vscode.TextDocument): void {
        const config = vscode.workspace.getConfiguration('quell');
        const enableEntropy = config.get<boolean>('enableEntropyScanning', DEFAULT_CONFIG.enableEntropy);
        const scannerConfig: ScannerConfig = {
            enableEntropy,
            entropyThreshold: config.get<number>('entropyThreshold', DEFAULT_CONFIG.entropyThreshold),
            minimumTokenLength: config.get<number>('minimumTokenLength', DEFAULT_CONFIG.minimumTokenLength),
            customPatterns: config.get<Array<{ name: string; regex: string }>>('customPatterns', DEFAULT_CONFIG.customPatterns),
            whitelistPatterns: config.get<string[]>('whitelistPatterns', DEFAULT_CONFIG.whitelistPatterns),
        };

        const uriString = document.uri.toString();
        const text = document.getText();
        const diagnostics: vscode.Diagnostic[] = [];

        // Clear previous range→secret mappings for this document
        for (const key of [...this.secretRangeMap.keys()]) {
            if (key.startsWith(uriString + ':')) { this.secretRangeMap.delete(key); }
        }

        // Find secrets using standard redaction engine
        const { secrets, detectedTypes } = SecretScanner.redact(text, scannerConfig);

        if (secrets.size === 0) {
            this.collection.set(document.uri, []);
            return;
        }

        const typeHint = detectedTypes.size > 0 ? Array.from(detectedTypes).join(' / ') : 'Token';

        // Map them back to the document to create diagnostics
        for (const [_, secretValue] of secrets) {
            let startIndex = 0;
            let index: number;
            // Find all instances of this secret value in the text
            while ((index = text.indexOf(secretValue, startIndex)) > -1) {
                const startPos = document.positionAt(index);
                const endPos = document.positionAt(index + secretValue.length);
                const range = new vscode.Range(startPos, endPos);

                const diagnostic = new vscode.Diagnostic(
                    range,
                    `🚨 Exposed Secret [${typeHint}]: Run "Quell: Redact Active File" before sharing.`,
                    vscode.DiagnosticSeverity.Warning
                );
                diagnostic.source = 'Quell';
                diagnostic.code = 'exposed-secret';
                diagnostics.push(diagnostic);

                // Store secret value keyed by range position for Quick Fix lookup
                const rangeKey = `${uriString}:${startPos.line}:${startPos.character}`;
                this.secretRangeMap.set(rangeKey, secretValue);

                startIndex = index + secretValue.length;
            }
        }

        this.collection.set(document.uri, diagnostics);
    }

    public provideCodeActions(document: vscode.TextDocument, range: vscode.Range | vscode.Selection, context: vscode.CodeActionContext): vscode.CodeAction[] {
        const diagnostics = context.diagnostics.filter(d => d.source === 'Quell');
        if (diagnostics.length === 0) { return []; }

        const actions: vscode.CodeAction[] = [];
        const uriString = document.uri.toString();

        // Per-secret actions for each flagged range
        for (const diagnostic of diagnostics) {
            const r = diagnostic.range;
            const rangeKey = `${uriString}:${r.start.line}:${r.start.character}`;
            const secretValue = DiagnosticProvider.secretRangeMap.get(rangeKey);
            if (secretValue) {
                const perSecretFix = new vscode.CodeAction('🛡️ Quell: Redact this secret', vscode.CodeActionKind.QuickFix);
                perSecretFix.command = {
                    command: 'quell.redactSingleSecret',
                    title: 'Redact this secret',
                    arguments: [
                        uriString,
                        r.start.line, r.start.character,
                        r.end.line, r.end.character,
                        secretValue
                    ]
                };
                perSecretFix.diagnostics = [diagnostic];
                perSecretFix.isPreferred = diagnostics.length === 1;
                actions.push(perSecretFix);
            }
        }

        // Whole-file fallback
        const fileFix = new vscode.CodeAction('🛡️ Quell: Redact all secrets in file', vscode.CodeActionKind.QuickFix);
        fileFix.command = {
            command: 'quell.redactActiveFile',
            title: 'Redact all secrets in file',
            tooltip: 'Replace all exposed secrets with secure placeholders'
        };
        fileFix.diagnostics = diagnostics;
        fileFix.isPreferred = actions.length === 0;
        actions.push(fileFix);

        return actions;
    }

    public static dispose(): void {
        this.collection?.dispose();
        this.disposables.forEach(d => d.dispose());
        this.secretRangeMap.clear();
    }
}
