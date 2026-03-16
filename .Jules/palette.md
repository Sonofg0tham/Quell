## 2024-05-14 - Interactive Div Accessibility in VS Code Webviews
**Learning:** Found that custom `div`-based list items in the sidebar (like `.finding-item`) were used as primary interactive elements to open files, but lacked keyboard accessibility. Only mouse clicks were supported via `onclick`.
**Action:** Always verify that interactive elements that are not native `<button>` or `<a>` tags include `role="button"`, `tabindex="0"`, and `onkeydown` event handlers to capture `Enter` and `Space` key events, ensuring full access for keyboard-only users in custom VS Code webviews.
