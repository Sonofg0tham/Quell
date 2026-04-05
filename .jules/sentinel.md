## 2024-05-24 - Arbitrary Command Execution in Webview
**Vulnerability:** The webview message handler in `SidebarProvider.ts` passed `data.command` directly to `vscode.commands.executeCommand` without validation.
**Learning:** Webviews can be a source of XSS. If a webview executes a malicious script (e.g. via unsanitized data reflection), it could send an arbitrary command to the extension host, executing terminal commands or accessing local files.
**Prevention:** Always strictly validate IPC messages from webviews. Check both the type and value of the command. Using a consistent prefix like `quell.` for all internal commands allows for simple but robust prefix validation.
