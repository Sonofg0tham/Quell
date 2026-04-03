# Sentinel's Journal

## 2025-04-03 - Webview Arbitrary Command Execution
**Vulnerability:** The webview message handler in `SidebarProvider.ts` passed `data.command` directly to `vscode.commands.executeCommand()` without any validation. This meant if an attacker could execute an XSS payload inside the webview, they could issue any VS Code command, potentially leading to privilege escalation, file system access, or arbitrary code execution via the extension host.
**Learning:** Even if CSP restricts external scripts, `executeCommand` is a critical boundary. All VS Code extensions must treat webview messages as untrusted input. The architecture using `quell.` prefixes for all legitimate commands provided a straightforward way to secure this boundary.
**Prevention:** Always strictly validate or whitelist the `command` string before passing it to `vscode.commands.executeCommand()`. Ensure commands originate from the expected namespace (e.g., checking `command.startsWith('quell.')`).
