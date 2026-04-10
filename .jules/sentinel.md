## 2025-04-10 - Secure Webview Message Handling
**Vulnerability:** The Webview message listener `onDidReceiveMessage` was passing `data.command` directly to `vscode.commands.executeCommand` without validation. This allowed an untrusted webview (potentially vulnerable to XSS) to execute arbitrary VS Code commands on the host machine.
**Learning:** In VS Code extensions, webview content must be treated as untrusted. Directly executing commands from webview IPC messages without an allowlist enables remote code execution risks via standard VS Code commands.
**Prevention:** Always implement a strict allowlist (e.g., using a `Set` of approved commands) and type-check inputs before executing actions derived from webview messages.
