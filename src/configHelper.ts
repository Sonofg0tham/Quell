import * as vscode from 'vscode';
import { ScannerConfig, DEFAULT_CONFIG } from '../packages/scanner/src';
import { Logger } from './Logger';

const _warnedPatterns = new Set<string>();

export function getConfig(): ScannerConfig {
    const cfg = vscode.workspace.getConfiguration('quell');
    const rawPatterns = cfg.get<Array<{ name: string; regex: string }>>('customPatterns', DEFAULT_CONFIG.customPatterns);
    const customPatterns: Array<{ name: string; regex: string }> = [];
    for (const p of rawPatterns) {
        try {
            new RegExp(p.regex);
            customPatterns.push(p);
        } catch (e) {
            const key = `${p.name}::${p.regex}`;
            if (!_warnedPatterns.has(key)) {
                _warnedPatterns.add(key);
                Logger.warn(`Custom pattern "${p.name}" has an invalid regex and will be skipped: ${e instanceof Error ? e.message : String(e)}`);
            }
        }
    }
    return {
        enableEntropy: cfg.get<boolean>('enableEntropyScanning', DEFAULT_CONFIG.enableEntropy),
        entropyThreshold: cfg.get<number>('entropyThreshold', DEFAULT_CONFIG.entropyThreshold),
        minimumTokenLength: cfg.get<number>('minimumTokenLength', DEFAULT_CONFIG.minimumTokenLength),
        customPatterns,
        whitelistPatterns: cfg.get<string[]>('whitelistPatterns', DEFAULT_CONFIG.whitelistPatterns),
        redactTestKeys: cfg.get<boolean>('redactTestKeys', DEFAULT_CONFIG.redactTestKeys),
    };
}
