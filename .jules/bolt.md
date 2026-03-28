## 2024-05-24 - Parallelize I/O-bound tasks in workspace scans
**Learning:** Sequential `for` loops reading files block the event loop and increase latency for workspace scanning tasks. Since file reading and secret scanning don't depend on sequential execution order, they can be processed concurrently.
**Action:** Parallelize I/O-bound tasks in workspace scans (like file reading and secret scanning) using `Promise.all` with `.map()` instead of sequential `for` loops to significantly reduce execution time.

## 2024-06-03 - Batched concurrent processing for I/O-bound tasks
**Learning:** Unconstrained `Promise.all(files.map(...))` for processing a large number of files can cause EMFILE/OOM errors on large workspaces.
**Action:** Use batched concurrent processing (e.g., `for` loop with sliced batches and `Promise.all`) instead of unconstrained `Promise.all` to prevent EMFILE/OOM errors and to allow CancellationToken checks between batches.
