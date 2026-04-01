## 2024-05-24 - Parallelize I/O-bound tasks in workspace scans
**Learning:** Sequential `for` loops reading files block the event loop and increase latency for workspace scanning tasks. Since file reading and secret scanning don't depend on sequential execution order, they can be processed concurrently.
**Action:** Parallelize I/O-bound tasks in workspace scans (like file reading and secret scanning) using `Promise.all` with `.map()` instead of sequential `for` loops to significantly reduce execution time.

## 2024-05-25 - Cache configuration-driven regular expressions
**Learning:** Recompiling custom and whitelist regular expressions from configuration arrays within the `SecretScanner.redact` hot path causes severe performance degradation, especially during full workspace scans where it's called per file.
**Action:** Use a `WeakMap` tied to the configuration array reference to cache the compiled `RegExp` objects, ensuring they are compiled once per config change rather than per redaction call.
