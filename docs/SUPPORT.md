# Candidate support and limits

Candidate: Ghidra12.1.3, maintained GhidraBoy mapping schema2, GhiGBC mapping adapter1/native ABI1/checkpoint2/profile API1, optional GBW3 profile1.0.0. Exact source manifests, dependency hashes and archive checksums accompany the packages.

Validation targets: macOS arm64/Python3.14.7/Java21 and Linux x86-64/Python3.13.15/Java21. Linux execution is in a Debian13 runtime-only container; virtual-display results establish a narrower claim than physical GUI/Steam Deck acceptance. No glibc minimum is advertised solely from symbols or the Zig cross-build target. Actual Deck acceptance is M5 and remains pending.

Runtime mapper scope: ROM-only/MBC1/MBC3/MBC5; not MBC2 merely because static tools model it. Unknown mapper state, RTC-selected/device bytes and uncovered static ranges remain explicit. CPU-origin access watches cover attempted accesses plus final instruction-boundary bytes; DMA/HDMA watches and exact per-internal-access commit timing are unclaimed.

No audio, reverse execution, battery-save import, full reconstructed stack, new commercial revisions, or verified GBW3 far-call over/out. Known HP writer attribution is an observed store, not proof of damage computation or caller. Profile code is trusted installed code, not a sandbox; ROM detection never downloads code.

Publication is pending explicit authorization. The existing 12.1.2 student bundle remains rollback; its historical results do not validate this candidate, and this candidate does not claim a Deck installation is complete.
