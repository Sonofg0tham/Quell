## 2025-03-25 - [Fix XSS in VS Code Webview]
**Vulnerability:** XSS vulnerability in VS Code Webview where malformed file paths were incorrectly escaped.
**Learning:** Webview Content Security Policy allows 'unsafe-inline' scripts; all dynamic data must be rigorously HTML-escaped before interpolation into HTML strings. For inline JavaScript event handlers (e.g., onclick, onkeydown), data must be appropriately JavaScript-escaped AND HTML-escaped.
**Prevention:** Always use dedicated `_escapeHtml` and `_escapeJs` methods when inserting variables into webview templates, keeping nested contexts in mind.
## 2025-04-19 - [Fix Arbitrary Command Execution via VS Code Webview IPC]
**Vulnerability:** The webview handler in `SidebarProvider.onDidReceiveMessage` blindly executed `vscode.commands.executeCommand(data.command)` directly from webview IPC without validation. If an attacker achieved XSS in the webview, they could execute arbitrary VS Code commands.
**Learning:** VS Code Webviews must be treated as untrusted boundaries. Even if the webview HTML is generated locally, incoming IPC messages must be strictly validated against a static allowlist before execution to prevent arbitrary command execution vulnerabilities on the host machine.
**Prevention:** Always implement an `ALLOWED_COMMANDS` Set in webview message handlers and verify `typeof data.command === 'string' && ALLOWED_COMMANDS.has(data.command)` before calling `vscode.commands.executeCommand()`.
