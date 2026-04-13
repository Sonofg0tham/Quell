## 2025-03-25 - [Fix XSS in VS Code Webview]
**Vulnerability:** XSS vulnerability in VS Code Webview where malformed file paths were incorrectly escaped.
**Learning:** Webview Content Security Policy allows 'unsafe-inline' scripts; all dynamic data must be rigorously HTML-escaped before interpolation into HTML strings. For inline JavaScript event handlers (e.g., onclick, onkeydown), data must be appropriately JavaScript-escaped AND HTML-escaped.
**Prevention:** Always use dedicated `_escapeHtml` and `_escapeJs` methods when inserting variables into webview templates, keeping nested contexts in mind.
## 2026-04-13 - Prevent Arbitrary Command Execution in Webview IPC
**Vulnerability:** Untrusted messages originating from Webview UI were passing arbitrary command strings directly to `vscode.commands.executeCommand(data.command)`.
**Learning:** Even though Webview scripts were internal, any Cross-Site Scripting (XSS) or injected content could post valid-looking messages, leading to arbitrary extension/VS Code command execution on the host machine.
**Prevention:** Always maintain a static Set allowlist (`ALLOWED_COMMANDS`) for all acceptable commands triggered via Webview IPC, and strictly validate the incoming `command` string before execution.
