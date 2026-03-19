## 2024-05-18 - Optimized `calculateEntropy` with Pre-allocated Array
**Learning:** For high-frequency calculations (like checking entropy on thousands of tokens), allocating a new `Int32Array(256)` on every call has significant garbage collection and memory allocation overhead.
**Action:** Use a pre-allocated static `Int32Array(256)` and lazily reset only the used indices inside the loop. This can boost performance of ASCII-heavy text scans by over 3x.
