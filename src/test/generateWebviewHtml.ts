import { SidebarProvider } from '../SidebarProvider';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

// Mock vscode config
const mockConfig = {
    get: (key: string, defaultValue: any) => defaultValue
};
(vscode.workspace as any).getConfiguration = () => mockConfig;

const mockUri = vscode.Uri.file('/mock/path');

const provider = new SidebarProvider(mockUri);

// Inject malicious filenames
const mockResults = [
    { file: 'normal_file.ts', count: 1, types: ['AWS Key'] },
    { file: 'malicious_file"><script>alert("xss")</script>.ts', count: 2, types: ['Stripe Key'] },
    { file: 'another_malicious\' onmouseover=\'alert("xss")\'.ts', count: 1, types: ['GitHub Token'] }
];

(provider as any).scanResults = mockResults;
(provider as any).sessionScans = 1;

const html = (provider as any).getHtmlForWebview();

const outPath = path.join(__dirname, 'webview_test.html');
fs.writeFileSync(outPath, html);
console.log('Wrote HTML to', outPath);
