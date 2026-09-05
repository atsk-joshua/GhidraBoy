# Bounded static analysis

`BankAnalysis.preview` evaluates existing defined instructions. `AnalysisResult`
is typed and versioned: start points, explicit assumptions, configuration,
completion, explored-state count, diagnostics, candidates and evidence fingerprint.
`AnalysisResult.read` rejects incompatible engines. Only COMPLETE runs can contain
PROVEN conclusions. STATE_LIMIT, CANCELLED and INPUT_CHANGED preserve useful
candidates without publishing confidence. The default bound is 4096 distinct
explored address/state/constant combinations; duplicate queued states do not
consume that count. Unknown alternatives prevent proof at the affected byte site.

Evaluation (`PcodeConstants`, `MapperKnowledge`), aggregation (`AnalysisCandidates`),
result validation, application (`AnalysisApplication`) and ownership
(`AnalysisOwnership`) are separate units. Analysis uses compiled p-code, not a
second instruction interpreter. It expands memory accesses to little-endian bytes
with 16-bit wrap. SLEIGH exposes architectural ordering for SP loads and pushes.
Unmodeled values and relevant unknown writes invalidate knowledge conservatively.
ROM register knowledge does not imply reset SRAM/RTC/VBK/SVBK state.

Every fallthrough is checked against the CPU execution window. Same-window
physical context is reused only while consistent with known mapper registers.
Cross-window fallthrough, relative branches and wrapped PC resolve through actual
Program views. Cross-boundary fetch stops if identity or bytes cannot be proven.
Undefined code and data markings stop traversal; analysis does not sweep bytes.
Unknown calls invalidate return-state knowledge. No general interprocedural
summaries or runtime bank switching are provided.

Fingerprints cover mapping, initialized bytes, defined data, instructions and flow
overrides in canonical order. Renaming and reopening no longer changes the hash
merely by changing native iteration order. Applying a saved result or discovering
functions requires a current engine and matching dependencies. Rerun preview after
patching code, remapping or changing assumptions. Assumptions remain explicit in
the result; a new preview establishes a new assumption set.

# Owned enhancements

Preview is separate from application. Apply/remove/reapply receipts persist native
identities and original states for references, bookmarks, functions and supported
far-call fallthrough overrides. Removal checks the current object still matches
what GhidraBoy added. A later user edit or another component's object is preserved.
New applied runs remove unchanged old additions before replacement, avoiding stale
bookmarks. Transactions and cancellation roll back partial mutations. Installed
separate-process tests verify save/reopen and lifecycle, not only in-memory calls.

Function discovery is seed based: existing entry points, explicitly declared code
and proven direct calls. It uses defined instructions and preserves existing
functions, bodies, prototypes, storage, overrides and marked data. Labels and
vectors do not automatically become functions. Incomplete results contribute no
proven call seeds; stale results are rejected.

References are supplemental navigation information. They do not redirect p-code
memory, select a live bank or promise rewritten decompiler indirect flow.

# Exact supported far-call convention

The opt-in ordinary-MBC3 trampoline pops the RST return, reads bank:u8/target:u16,
pushes the return advanced by three payload bytes, then transfers through a
pushed target and RET. It **changes the ROM bank without restoring it**. Therefore
accepted callers, payloads and return sites must be proven fixed ROM0 below 4000.
Switchable-ROM callers are rejected. Explicit SP must keep all four stack bytes
within fixed WRAM0 or HRAM. Body bytes, payload bounds, mapper/view identity,
existing overrides and target code are validated before mutation.

Compiled-p-code fixtures check target entry, return address/SP and fixed caller
physical identity. Preview, application and unchanged-owned removal are exposed
in the tools script. Default RST behavior remains unchanged. This is not universal
Game Boy Wars 3 support, an arbitrary MBC1 convention, or a runtime debugger.
