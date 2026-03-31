## 2024-05-24 - Parallelize I/O-bound tasks in workspace scans
**Learning:** Sequential `for` loops reading files block the event loop and increase latency for workspace scanning tasks. Since file reading and secret scanning don't depend on sequential execution order, they can be processed concurrently.
**Action:** Parallelize I/O-bound tasks in workspace scans (like file reading and secret scanning) using `Promise.all` with `.map()` instead of sequential `for` loops to significantly reduce execution time.

## 2024-11-06 - Avoid redundant RegExp recompilation in hot paths
**Learning:** Compiling configuration-driven regex patterns (like user custom patterns or whitelists) repeatedly inside a frequently called function (like `SecretScanner.redact`) causes severe performance overhead, especially during mass file scans (e.g., workspace scans).
**Action:** Cache these compiled `RegExp` objects locally (e.g., using a `WeakMap` keyed by the original configuration array) so they are only compiled once per unique configuration, bypassing massive overhead during workspace scans.