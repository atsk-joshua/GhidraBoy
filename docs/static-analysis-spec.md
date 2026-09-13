# Static accuracy specification

Status: planned requirements, revision 1, 2026-09-07. This document specifies the
static-analysis work prioritized by the [roadmap](roadmap.md). It does not change
SLEIGH language 1.0, mapping schema v2, AnalysisResult, compiler IDs or current
support claims. Any implementation change to those surfaces needs its own
versioning and migration decision. Current behavior is in [analysis](analysis.md)
and [static contract](static-contract.md); source evidence is in
[research](static-analysis-research.md) and [references](references.md).

The [implementation handoff](static-analysis-implementation.md) maps these
requirements to concrete work and validation commands without weakening them.

## Accuracy and evidence contract

**S-01 — State the claim and its execution conditions.** Each conclusion must
identify the image, physical location, CPU execution window, hardware/mode,
mapper wiring/geometry and relevant entry assumptions. Distinguish reset/boot
entry from an arbitrary routine entry, original file bytes from patches and RAM
images, and a mapper's raw selector from its effective physical selection.

Record initial RAM/save/RTC/peripheral assumptions, interrupt policy and relevant
code-image lifetime. A valid-gameplay domain, arbitrary save contents and a
controlled debugger entry are different analyses. An observation must never
silently become a universal precondition. The objective is exact semantics and
complete recovery for the declared requirements, not warning suppression.

**S-02 — Separate proof, observation and hypotheses.** Keep hardware facts,
compiler-version facts, proven code-derived summaries, observed edges and user
assumptions distinct. A finished bounded worklist does not prove whole-ROM
reachability or the absence of other writers. Required unknowns, unsupported
hardware and exhausted bounds remain open requirements with reasons. A claimed
complete result must close its relevant call, writer, indirect-flow and entry
dependencies; known counterexamples must fail it.

**S-03 — Make results reproducible and invalidate every consumed dependency.**
Record source/dependency hashes, language and engine versions, configuration,
assumptions, roots and evidence origins. Fingerprint consumed flow references
(including kind, endpoint and primary state), instruction/context/override data,
fixups, prototypes, memory/mutability, mapping and summary dependencies. Change
only a consumed reference or callee contract in negative tests. Reject stale
results before application. Refresh the native decompiler's caches when its
inputs change. Analysis-generated references cannot validate themselves.

## CPU, bus and memory interpretation

**S-04 — Maintain one architectural instruction definition.** SLEIGH remains
the instruction authority. Reuse Ghidra operation behaviors where suitable;
test any abstract evaluator against the p-code operation contract, including
widths, signedness, extension/truncation, oversized shifts and overlapping
register bytes. Evaluate raw p-code and validated overrides coherently; do not
combine incompatible instruction effects and stored flow without an explicit
policy. Keep raw execution checks separate from injected/high p-code and native
C checks. Constructor changes require saved/fresh compatibility and the proper
language-version transition.

**S-05 — Resolve accesses by state and access kind.** Reads, writes and fetches
at the same CPU address may have different meanings. Model selector writes for
direct, indirect, word, stack and read-modify-write forms with architectural
ordering and 16-bit wrap. Resolve banked reads/fetches using justified state;
retain ordinary RAM propagation and immutable-ROM properties. Preserve unknown,
disabled, device, blocked and open-bus behavior without substituting zero or FF
where hardware does not establish that value. A reference alone is not a bus
model. Do not make all ROM writable or all memory volatile to hide errors.

**S-06 — Keep address and storage identities distinct.** A CPU pointer remains
16 bits even if an analysis representation uses a wider physical address.
Represent aliases without inventing independent storage. Track byte-accurate
sources for copied/decompressed RAM code and distinguish later replacement or
self-modification. A RAM image is not a permanent writable alias of its source
ROM. Instruction decode requires justified bytes at the execution location.
Different images at one address must not be merged into one unconditional body.

**S-07 — Represent asynchronous effects.** Account for interrupt entry/return,
delayed interrupt enabling, HALT/STOP boundaries and relevant DMA/device effects
when they affect a static claim. Derive or require interrupt-handler register,
bank and memory summaries. Shared RAM flags may require per-data volatility;
I/O-only volatility is insufficient. Timing-dependent values may remain symbolic,
but any resulting required flow uncertainty remains visible. Avoid treating a
wait for external activity as an ordinary proven infinite loop/nonreturn.

## Calls, dispatch and discovery

**S-08 — Model software conventions explicitly.** Each helper summary describes
recognition/version, entry premises, target extraction, inline payload layout,
stack writes/pops, continuation, register/flag inputs and outputs, memory effects,
mapper transitions and return/nonlocal-exit possibilities. Recognize restoring,
constant-bank-on-return and nonrestoring helpers separately. Use the actual
effective bank relationship; do not assume a RAM shadow equals the physical bank.
Match a helper by verified semantics/bytes and context, not title or RST number.

Choose callfixups, prototypes and flow/reference overrides according to their
Ghidra meaning. CALL/CALLIND p-code supplies a transfer, not an implicit push.
Preserve conditions when using overrides. Prove both target and continuation;
do not infer nonreturn from a truncated listing, bounded execution or a missing
ordinary RET. Correct summaries must work with normal automatic analysis.

**S-09 — Recover dispatch from producers and domains.** Classify indirect calls,
pointer dereferences, tail transfers, return-based transfers and actual tables
before selecting a recovery mechanism. Propagate justified ROM lookup values,
finite sets/ranges/bit constraints and call results. Include byte-width wrap,
duplicate/default cases, zero-input paths, bank identity and pointer layout.
Prove state-derived bounds through all relevant writers, aliases, callees and
initialization/save paths. Neither native ValueSetSolver nor jumpassist supplies
those global premises automatically. Test returned C and target/case mapping,
not merely successful decompilation or absence of diagnostics.

**S-10 — Discover code and data together.** Start from justified entry points,
interrupt paths, declared code and metadata; extend through proven direct and
indirect flow, software helpers, script callbacks and initialized RAM images.
Repeat discovery and summaries until dependencies stabilize or are explicitly
unresolved. Separate speculative decoding from committed instructions. Preserve
imported/user labels while allowing justified function creation; a named address
is neither automatically a function nor automatically ineligible to become one.

Classify inline payloads, pointer tables, scripts, encoded text, graphics/maps,
compressed assets, RAM code and padding through their consumers or verified
metadata. Keep native and script control-flow identities distinct. A valid opcode
sequence, entropy score or nearby pointer is candidate evidence, not proof.

## Compiler, cartridge and saved-work contracts

**S-11 — Use versioned compiler and format knowledge.** Keep assembly as the
default where no ABI is established. Evaluate Ghidra parameter-allocation rules
before expanding custom allocation. Verify scalar/aggregate/variadic/packed
storage, cleanup, multi-register results and flag effects against emitted code.
Cover current/legacy banked helpers and multiple far-pointer layouts. Import
versioned RGBDS symbols/maps/object or linker metadata, SDCC debug information
and relevant WLA-DX bank/slot metadata when available. Preserve source/line maps,
relocation/execution locations and scratch-storage lifetimes. A reconstructed
disassembly's modern build system is not evidence of the original toolchain.

**S-12 — Describe cartridges as wiring and devices.** Separate controller,
board variant, detected/requested geometry, reachable windows, control decode,
power-on state, persistent state and device endpoints. Cover ordinary ROM-only,
MBC1/2/3/5 and plan MBC1M, MBC30, MBC6/7, MMM01, M161, HuC1/HuC3, Camera,
TAMA5 and identified unlicensed variants. Include coupled ROM/RAM constraints,
non-power-of-two ambiguity, nibble/EEPROM storage, flash, alternate header/reset
locations and one-way configuration. Do not implement new geometries by merely
adding an enum under the current fixed-window assumptions. Resolve conflicting
sources with targeted evidence; unknown hardware requires research, not guessed
certainty. See the [cartridge research matrix](static-analysis-research.md#cartridge-requirements).

**S-13 — Repair annotated work through reviewable migrations.** Preserve original
artifacts and inventories. Separate decoder migration, topology changes, listing
repair, prototype changes and user annotation edits. Produce an explicit preview
and disposition for disproven boundaries, references, thunks and functions;
preservation must not freeze incorrect annotations forever. Keep the original
and repaired denominators visible. Verify cancellation/rollback and actual
save/reopen. Do not shrink function bodies or remove failed entries solely to
improve diagnostics.

## Acceptance matrix

These are future gates, not results of the documentation update. Existing
[CPU validation](cpu-validation.md), [GUI checks](gui-validation.md) and the
source checkout's `docs/validation.md` establish only their stated scopes.

| Gate | Required coverage and evidence |
| --- | --- |
| A-CPU | Compiled SLEIGH families, flags/overlap/wrap and evaluator conformance; raw versus override/injected semantics checked separately; full required opcode coverage identified rather than inferred from sampled vectors |
| A-BUS | Equivalent direct/indirect/stack/RMW selector operations; ordered boundary writes; bank-dependent read/fetch; aliases, disabled/device modes and ordinary RAM behavior |
| A-CALL | Restoring/nonrestoring/constant-bank helpers, inline payload lengths, manual continuations, nested calls, flags, return/no-return/nonlocal paths and unknown premises |
| A-FLOW | Real pointer calls versus tables; helper-derived ranges, zero/default and wrap paths; target identities/case values plus semantic native C checks |
| A-STATE | ROM tables, RAM shadows, interrupt-shared data, save-derived values, memory aliases and RAM-code lifetime; counterexamples invalidate purported invariants |
| A-DISCOVERY | Fresh import closure from justified roots and all required callback/helper paths; all bytes accounted for as proven classifications or explicitly unresolved requirements; speculative bytes never silently become proof |
| A-ABI-DATA | Exact compiler fixtures and metadata formats; packed/aggregate/variadic storage; far-pointer layouts, script-native links, encoded data and overlapping storage lifetimes |
| A-CART | Controller/board/mode matrix and reset geometry, including exotic windows/devices; independent expectations and explicit source-conflict resolution |
| A-GHIDRA | Normal auto-analysis does not reassert disproven nonreturn or clear valid continuations; normal Decompiler window matches qualified headless semantics; no private reflection or custom-script-only success substituted |
| A-DEPENDENCIES | Reference-only, context-only, prototype/fixup, mutability and image changes invalidate results; own generated evidence cannot circularly establish confidence |
| A-MIGRATION | Saved/fresh decoding, byte/source identity, complete knowledge inventory, reviewed repair, cancel/rollback, separate-process save/reopen and old-reader/version policy |
| A-CORPUS | Self-authored edge cases, pinned compiler builds, independently reconstructed game patterns and optional private fresh/annotated corpora; every warning family and semantic failure has a disposition; no excluded failures hidden in aggregate counts |

Every claimed gate needs exact source/artifact/configuration identity, commands,
expected observations, results and retained failures. Emulator agreement is
supporting evidence; hardware-backed references and independent expectations
remain necessary. Observed edges establish occurrence, not exhaustive coverage.
Warning-free C, a complete bounded run, or a successful build cannot close this
matrix. Any required unresolved case keeps full static qualification open.

## Conditional call-site relation

A conditional call-site result must bind its physical source and Program identity
to explicit execution premises. Unknown registers, valid flag relationships,
memory values and constrained affine SP must remain symbolic. It must derive
hardware successors from raw semantics, preserve byte/pair origins and ordered
frame/data effects, and distinguish dispatch RET, callee return, matched call
completion and analysis exit. The continuation consumes the matched outgoing
state under the same invocation authority. A scope endpoint does not authorize a
fabricated source return or a claim about an unanalysed tail.

An owned stock native view may end at an actual proved cleanup RET while exposing
the following bounded state through a validated linked explanation and physical
navigation. Existing canonical annotations remain preserved. Memory identity and
runtime values are distinct; explicit stack/data physical disjointness is required.
Unsupported accesses, nonlocal frames or stale authority remain obligations.
The [effectful call decision](decisions/effectful-call-continuation.md) specifies
the implemented bounded subset and its observation/compatibility contract.
