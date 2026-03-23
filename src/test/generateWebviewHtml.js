"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var SidebarProvider_1 = require("../src/SidebarProvider");
var fs = require("fs");
var path = require("path");
var vscode = require("vscode");
// Mock vscode objects
var mockUri = vscode.Uri.file('/mock/path');
// Create an instance of SidebarProvider
var provider = new SidebarProvider_1.SidebarProvider(mockUri);
// Inject some mock scan results containing malicious filenames
var mockResults = [
    { file: 'normal_file.ts', count: 1, types: ['AWS Key'] },
    { file: 'malicious_file"><script>alert("xss")</script>.ts', count: 2, types: ['Stripe Key'] },
    { file: 'another_malicious\' onmouseover=\'alert("xss")\'.ts', count: 1, types: ['GitHub Token'] }
];
// We need to bypass the private visibility to set the results for testing
provider.scanResults = mockResults;
provider.sessionScans = 1;
// Get the HTML output
var html = provider.getHtmlForWebview();
// Write it to a file
var outPath = path.join(__dirname, 'webview_test.html');
fs.writeFileSync(outPath, html);
console.log('Wrote HTML to', outPath);
