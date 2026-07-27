import * as vscode from 'vscode';
import { PromptGuard, InjectionFinding, InjectionSeverity } from '../packages/scanner/src';
import { getGuardConfig, isInjectionScanningEnabled } from './configHelper';
import { Logger } from './Logger';

/**
 * InjectionProvider — inline diagnostics for inbound prompt-injection threats.
 *
 * Deliberately a separate DiagnosticCollection from DiagnosticProvider. The two
 * report opposite directions of travel and a user needs to tell them apart at a
 * glance: a yellow squiggle means "you are about to leak something", a red one
 * means "this file is trying to talk to your AI behind your back".
 */
export class InjectionProvider implements vscode.CodeActionProvider {
    private static collection: vscode.DiagnosticCollection;
    private static disposables: vscode.Disposable[] = [];
    private static timeout: NodeJS.Timeout | undefined;

    /** Maps "uriString:line:char" → finding, for per-finding Quick Fixes. */
    private static findingMap = new Map<string, InjectionFinding>();

    /** Files already reported this session, so we warn once rather than nag. */
    private static warnedFiles = new Set<string>();

    /** Skip scanning documents above this size — injection payloads live in text, not build output. */
    private static readonly MAX_SCAN_BYTES = 2_000_000;

    public static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

    public static init(context: vscode.ExtensionContext): void {
        this.collection = vscode.languages.createDiagnosticCollection('quell-injection');
        this.disposables.push(this.collection);

        this.disposables.push(
            vscode.window.onDidChangeActiveTextEditor(editor => {
                if (editor) { this.updateDiagnostics(editor.document); }
            }),
            vscode.workspace.onDidChangeTextDocument(event => {
                const doc = event.document;
                if (this.timeout) { clearTimeout(this.timeout); }
                this.timeout = setTimeout(() => {
                    const active = vscode.window.activeTextEditor;
                    if (active && active.document === doc) { this.updateDiagnostics(doc); }
                }, 500);
            }),
            vscode.workspace.onDidCloseTextDocument(doc => {
                const prefix = doc.uri.toString() + ':';
                for (const key of [...this.findingMap.keys()]) {
                    if (key.startsWith(prefix)) { this.findingMap.delete(key); }
                }
                this.collection.delete(doc.uri);
            })
        );

        if (vscode.window.activeTextEditor) {
            this.updateDiagnostics(vscode.window.activeTextEditor.document);
        }

        context.subscriptions.push(
            vscode.languages.registerCodeActionsProvider('*', new InjectionProvider(), {
                providedCodeActionKinds: InjectionProvider.providedCodeActionKinds
            })
        );

        context.subscriptions.push(...this.disposables);
    }

    public static updateDiagnostics(document: vscode.TextDocument): void {
        const uriString = document.uri.toString();

        for (const key of [...this.findingMap.keys()]) {
            if (key.startsWith(uriString + ':')) { this.findingMap.delete(key); }
        }

        if (!isInjectionScanningEnabled()) {
            this.collection.set(document.uri, []);
            return;
        }

        const text = document.getText();
        if (text.length > this.MAX_SCAN_BYTES) {
            this.collection.set(document.uri, []);
            return;
        }

        const { findings } = PromptGuard.scan(text, getGuardConfig());
        if (findings.length === 0) {
            this.collection.set(document.uri, []);
            return;
        }

        const diagnostics: vscode.Diagnostic[] = [];

        for (const finding of findings) {
            const startPos = document.positionAt(finding.index);
            const endPos = document.positionAt(finding.index + finding.length);
            const range = new vscode.Range(startPos, endPos);

            let message = `🕵️ Prompt Injection [${finding.type}]: ${finding.detail}`;
            if (finding.decoded) {
                message += `\n\nHidden text decodes to: "${finding.decoded}"`;
            }

            const diagnostic = new vscode.Diagnostic(range, message, this.toVsSeverity(finding.severity));
            diagnostic.source = 'Quell';
            diagnostic.code = 'prompt-injection';
            diagnostics.push(diagnostic);

            // Key includes type and length: two findings can legitimately start at the
            // same position (a phrase match and a hidden-character run, say), and a
            // position-only key would hand the Quick Fix the wrong one.
            this.findingMap.set(`${uriString}:${startPos.line}:${startPos.character}:${finding.type}:${finding.length}`, finding);
        }

        this.collection.set(document.uri, diagnostics);

        // Only a recoverable covert payload earns a modal-style interruption.
        //
        // A decoded smuggling finding is unambiguous: text was hidden from you,
        // and here is what it said. Phrase findings are heuristic and the content
        // is right there on screen — popping an error claiming a file "contains
        // hidden instructions" every time someone opens a security README would
        // be both wrong and infuriating. Those still get a squiggle and a log
        // line, which is the proportionate response.
        const smuggled = findings.filter(f => f.severity === 'critical' && f.decoded);
        const critical = findings.filter(f => f.severity === 'critical');

        if (critical.length > 0) {
            const relPath = vscode.workspace.asRelativePath(document.uri);
            Logger.warn(
                `INJECTION: ${relPath} contains ${critical.length} critical finding(s) [${critical.map(f => f.type).join(', ')}]` +
                (smuggled[0]?.decoded ? ` — hidden text decodes to: "${smuggled[0].decoded}"` : '')
            );
        }

        if (smuggled.length > 0 && !this.warnedFiles.has(uriString)) {
            this.warnedFiles.add(uriString);
            const relPath = vscode.workspace.asRelativePath(document.uri);
            const decoded = smuggled[0].decoded!;
            vscode.window.showErrorMessage(
                `🕵️ Quell: "${relPath}" contains text hidden from you but readable by an AI. It says: "${this.truncate(decoded, 120)}"`,
                'Strip Hidden Characters', 'Show Log'
            ).then(choice => {
                if (choice === 'Strip Hidden Characters') {
                    vscode.commands.executeCommand('quell.stripHiddenCharacters');
                } else if (choice === 'Show Log') {
                    Logger.show();
                }
            });
        }
    }

    private static truncate(s: string, max: number): string {
        return s.length <= max ? s : s.slice(0, max) + '…';
    }

    private static toVsSeverity(severity: InjectionSeverity): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            default:
                return vscode.DiagnosticSeverity.Information;
        }
    }

    public provideCodeActions(
        document: vscode.TextDocument,
        _range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        const diagnostics = context.diagnostics.filter(
            d => d.source === 'Quell' && d.code === 'prompt-injection'
        );
        if (diagnostics.length === 0) { return []; }

        const actions: vscode.CodeAction[] = [];
        const uriString = document.uri.toString();
        let hasHidden = false;

        for (const diagnostic of diagnostics) {
            const prefix = `${uriString}:${diagnostic.range.start.line}:${diagnostic.range.start.character}:`;
            const finding = [...InjectionProvider.findingMap.entries()]
                .find(([k]) => k.startsWith(prefix))?.[1];
            if (!finding) { continue; }

            // Only hidden-character findings have a safe automatic fix: deleting
            // them cannot change the visible meaning of the text. Phrase and
            // homoglyph findings need a human to decide.
            if (this.isStrippable(finding)) {
                hasHidden = true;
                const fix = new vscode.CodeAction(
                    `🕵️ Quell: Remove this hidden ${finding.type.toLowerCase()}`,
                    vscode.CodeActionKind.QuickFix
                );
                const edit = new vscode.WorkspaceEdit();
                edit.delete(document.uri, diagnostic.range);
                fix.edit = edit;
                fix.diagnostics = [diagnostic];
                fix.isPreferred = true;
                actions.push(fix);
            }
        }

        if (hasHidden) {
            const stripAll = new vscode.CodeAction(
                '🕵️ Quell: Remove all hidden characters in file',
                vscode.CodeActionKind.QuickFix
            );
            stripAll.command = {
                command: 'quell.stripHiddenCharacters',
                title: 'Remove all hidden characters in file',
            };
            stripAll.diagnostics = diagnostics;
            actions.push(stripAll);
        }

        return actions;
    }

    private isStrippable(finding: InjectionFinding): boolean {
        return finding.type === 'Unicode Tag Smuggling'
            || finding.type === 'Bidirectional Text Override'
            || finding.type === 'Variation Selector Smuggling'
            || finding.type === 'Invisible Character Sequence';
    }

    /** Forget the "already warned" set, e.g. after the user strips a file. */
    public static clearWarned(uri?: vscode.Uri): void {
        if (uri) { this.warnedFiles.delete(uri.toString()); } else { this.warnedFiles.clear(); }
    }

    public static dispose(): void {
        if (this.timeout) { clearTimeout(this.timeout); }
        this.collection?.dispose();
        this.disposables.forEach(d => d.dispose());
        this.findingMap.clear();
        this.warnedFiles.clear();
    }
}
