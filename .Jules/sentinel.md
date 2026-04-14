## 2025-03-25 - [Fix XSS in VS Code Webview]
**Vulnerability:** XSS vulnerability in VS Code Webview where malformed file paths were incorrectly escaped.
**Learning:** Webview Content Security Policy allows 'unsafe-inline' scripts; all dynamic data must be rigorously HTML-escaped before interpolation into HTML strings. For inline JavaScript event handlers (e.g., onclick, onkeydown), data must be appropriately JavaScript-escaped AND HTML-escaped.
**Prevention:** Always use dedicated `_escapeHtml` and `_escapeJs` methods when inserting variables into webview templates, keeping nested contexts in mind.
## 2025-04-14 - [Fix Arbitrary Command Execution in Webview IPC]
**Vulnerability:** Untrusted IPC messages from VS Code Webviews (`onDidReceiveMessage`) were passing a `data.command` string directly to `vscode.commands.executeCommand` without validation.
**Learning:** Webviews must be treated as untrusted boundaries. Passing unfiltered IPC payload data directly to sensitive APIs like `vscode.commands.executeCommand` allows for arbitrary command execution vulnerabilities on the host machine.
**Prevention:** Always strictly validate `data.command` against a static allowlist of expected extension commands (e.g., using a `Set`) before executing it from a Webview IPC message.
