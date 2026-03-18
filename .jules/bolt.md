
## 2024-05-20 - Pre-allocating Arrays for High-Frequency String Processing
**Learning:** In TypeScript, allocating new `Int32Array` objects within high-frequency inner loops (such as token evaluation during entropy scanning) causes significant overhead and memory pressure. Creating `new Int32Array(256)` thousands of times per second acts as a major bottleneck due to constant garbage collection and initialization time.
**Action:** For static text analysis or high-frequency character counting, use pre-allocated, static `Int32Array` buffers. Accompany them with a secondary tracker array (`modifiedIndices`) to lazily reset only the elements that were modified instead of zeroing the entire 256-element array, providing a massive speed boost.
