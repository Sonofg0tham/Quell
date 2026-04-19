## 2026-04-19 - O(1) Lookups and replaceAll in Hot Paths
**Learning:** In performance-critical hot paths involving text replacement, using `.split().join()` creates intermediate arrays, and performing linear  lookups over Map entries creates significant overhead during loops.
**Action:** Replaced linear map searches with  reverse-lookup Maps, and substituted `.split().join()` with `.replaceAll()` using a callback to safely apply placeholders without invoking special replacement patterns, significantly reducing processing time.
## 2024-05-24 - O(1) Lookups and replaceAll in Hot Paths
**Learning:** In performance-critical hot paths involving text replacement, using `.split().join()` creates intermediate arrays, and performing linear O(N) lookups over Map entries creates significant overhead during loops.
**Action:** Replaced linear map searches with O(1) reverse-lookup Maps, and substituted `.split().join()` with `.replaceAll()` using a callback to safely apply placeholders without invoking special replacement patterns, significantly reducing processing time.
