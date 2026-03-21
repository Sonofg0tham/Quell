# Bolt's Journal - Critical Learnings

## 2025-02-27 - Initial Setup
**Learning:** Initializing journal for performance learnings.
**Action:** Document future codebase-specific bottlenecks here.

## 2025-02-27 - Pre-allocated Shared Static Array for High-Frequency Token Analysis
**Learning:** The `calculateEntropy` method is called repeatedly for many tokens during a full file/workspace scan. Allocating and zeroing a new `Int32Array(256)` for every token check creates significant memory pressure and allocation overhead.
**Action:** For high-frequency string processing or calculations in TypeScript (like `calculateEntropy`), utilizing a pre-allocated, shared static `Int32Array` and lazily resetting only the modified indices provides a significant performance gain over repeatedly allocating and zeroing new arrays.
