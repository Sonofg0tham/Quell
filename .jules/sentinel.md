## 2024-05-20 - Missing HTML Escaping in Webview (XSS)
**Vulnerability:** User-controlled input (`f.file`) was injected directly into a VS Code Webview HTML template without HTML-escaping, allowing potential Cross-Site Scripting (XSS) if file paths contained malicious payloads.
**Learning:** VS Code Webviews use innerHTML-like string construction. Even if the CSP allows `unsafe-inline`, dynamic data like file names injected into HTML attributes (`title`) or inline JavaScript handlers (`onclick`, `onkeydown`) must be correctly escaped. Variables inside inline JS must be JS-escaped *then* HTML-escaped to prevent sandbox escapes.
**Prevention:** Always implement and apply an `escapeHtml` function to dynamic strings injected into Webview HTML templates.
