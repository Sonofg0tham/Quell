## 2024-05-14 - Interactive Div Accessibility in VS Code Webviews
**Learning:** Found that custom `div`-based list items in the sidebar (like `.finding-item`) were used as primary interactive elements to open files, but lacked keyboard accessibility. Only mouse clicks were supported via `onclick`.
**Action:** Always verify that interactive elements that are not native `<button>` or `<a>` tags include `role="button"`, `tabindex="0"`, and `onkeydown` event handlers to capture `Enter` and `Space` key events, ensuring full access for keyboard-only users in custom VS Code webviews.

## 2024-05-15 - Stateful Toggle Button Accessibility in Webviews
**Learning:** Toggle buttons (like "AI Indexing Shield") visually indicated their state via CSS classes (`.on`/`.off`) and text ("ON"/"OFF"), but lacked semantic `aria-pressed` states for screen readers. Furthermore, while primary buttons (`.btn-cta`, `.btn-tool`) had `:focus-visible` styles for keyboard navigation, the smaller `.toggle-btn` elements did not, making keyboard tabbing invisible.
**Action:** Always ensure custom toggle buttons include dynamic `aria-pressed="true|false"` attributes and that ALL interactive elements receive explicit `:focus-visible` styling to support keyboard navigation in custom VS Code webviews.
