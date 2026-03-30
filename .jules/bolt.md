## 2024-05-24 - Parallelize I/O-bound tasks in workspace scans
**Learning:** Sequential `for` loops reading files block the event loop and increase latency for workspace scanning tasks. Since file reading and secret scanning don't depend on sequential execution order, they can be processed concurrently.
**Action:** Parallelize I/O-bound tasks in workspace scans (like file reading and secret scanning) using `Promise.all` with `.map()` instead of sequential `for` loops to significantly reduce execution time.

## 2024-05-25 - Cache compiled RegExp objects for SecretScanner
**Learning:** In hot paths like `SecretScanner.redact`, recompiling config-driven regex objects repeatedly causes severe performance degradation.
**Action:** Cache these compiled `RegExp` objects locally and invalidate them only when the configuration array physically changes to prevent massive overhead during entire workspace scans.
