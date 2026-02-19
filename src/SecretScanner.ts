import * as vscode from 'vscode';

export class SecretScanner {
    private static readonly PATTERNS = [
        { name: 'AWS Access Key', regex: /(AKIA|ASIA)[0-9A-Z]{16}/ },
        { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
        { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24}/ },
        { name: 'Bearer Token', regex: /Bearer\s+[a-zA-Z0-9\-\._]{20,}/ }
    ];

    public static scan(text: string): string | null {
        // 1. Regex Scan
        for (const pattern of this.PATTERNS) {
            if (pattern.regex.test(text)) {
                return `Detected ${pattern.name}`;
            }
        }

        // 2. Entropy Scan
        // Split text into words to avoid flagging normal sentences, but check long strings
        const words = text.split(/\s+/);
        for (const word of words) {
            if (word.length > 20 && this.calculateEntropy(word) > 4.5) {
                return `Detected High Entropy String (Potential Secret)`;
            }
        }

        return null;
    }

    private static calculateEntropy(str: string): number {
        const len = str.length;
        const frequencies: { [key: string]: number } = {};

        for (const char of str) {
            frequencies[char] = (frequencies[char] || 0) + 1;
        }

        let entropy = 0;
        for (const char in frequencies) {
            const p = frequencies[char] / len;
            entropy -= p * Math.log2(p);
        }

        return entropy;
    }
}
