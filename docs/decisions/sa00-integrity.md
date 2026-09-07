# SA-00: analysis integrity and reproducible baseline

Scope: SA-00, S-03/S-04 and the bounded integrity portions of S-01/S-02/S-13.
This does not qualify SA-01 through SA-07 or the full static-accuracy matrix.
Evidence is in the source checkout at `docs/evidence/sa00-20260907/README.md`.

## Instruction interpretation

The engine uses `getPcode(false)` for architectural effects and `getDefaultFlows()`
for decoded destinations only after rejecting all `FlowOverride` values other than
NONE. (Ghidra 12.1.3's default-flows API itself responds to RETURN overrides.)
Ordinary stored flow references must agree with decoded destinations and flow kind.
They can corroborate the listing's consistency but cannot create a new proven edge.
Missing ordinary references do not erase the encoded transfer. Stored primary state
is a dependency, not authority to substitute a destination.

Flow overrides, reference overrides, altered instruction lengths, fallthrough
overrides and target callfixups stop interpretation at that instruction with an
explicit UNKNOWN finding. A fixup at the same CPU address in any physical bank is
conservatively rejected because the mapper can select that bank. Unmodified direct
conditional transfers retain both alternatives; effects on internal conditional
p-code paths remain conservatively unknown under the existing bounded evaluator.

`getPcode(true)` can rewrite transfer operations without supplying architectural
stack effects; CALL p-code does not push. The modified-call/branch fixtures compare
raw and overridden transfers and stack writes. Applying an override is therefore
not a validation of its software-call convention. In particular the existing
far-call application may still create its owned continuation/navigation annotations,
but the bounded analyzer reports that annotated instruction unresolved. A complete
frame/payload/callee-return summary is SA-01, not supplied by SA-00.

## Dependencies and ownership

Canonical fingerprints cover mapping, initialized bytes, defined data, instruction
lengths/overrides/fallthrough, raw p-code (including its decoded/context effects),
language/compiler identities, all consulted flow/override reference endpoints,
types, operands, sources and primary states, and function callfixup names/entries.
Non-callfixup prototypes and memory mutability are not used by this bounded engine:
it does not propagate memory contents or callee summaries. They will need additional
dependencies when SA-03 consumes them. Compiler/language code changes require an
engine/language release change; runtime replacement of provider code is not supported.

Ordinary supplemental DATA/READ/WRITE references are neither traversal inputs nor
fingerprinted. Applying bank analysis therefore does not invalidate itself. Generated
far-call CALL references and overrides are checked as modifications and cannot become
circular proof. Later edits that turn an ignored reference into flow are fingerprinted.
Preview captures dependencies before and after traversal and checks the Program
modification number within that preview, detecting edits even if restored. The
modification number is not persisted. INPUT_CHANGED results reject even if the
current content hash matches again. Application and discovery
reject stale results. Application revalidates on entry to its mutation transaction.
Application/discovery perform a final cancellation check before commit. Transactions
provide rollback, not general multi-writer isolation: callers must serialize Program
editing while applying/discovering, as with other Ghidra Program mutations.

Engine identity advances to `20260907-sa00`; result JSON schema stays 2. Older engine
results are rejected, with ownership receipts retained for conservative cleanup.
Ownership envelope 3 rejects older readers that would ignore primary state;
current readers accept envelopes 1/2 conservatively. Individual function receipt
version remains 2, with no re-baselining. Reference receipts now record nullable primary status. Missing historical primary
evidence or a later primary edit prevents deletion. Saving another group does not
upgrade missing reference proof. The older `analysis.ownedReferences` option is also
retained without destructive cleanup because its records cannot establish unchanged
primary state. No legacy user annotation is silently re-baselined.

## Evaluator contract

The evaluator delegates context-free integer unary/binary operations to the pinned
Ghidra operation behaviors, masks inputs/results to their declared byte widths, and
tracks register/unique bytes so overlapping writes invalidate only the affected bytes.
Values wider than eight bytes, unsupported operations and unknown inputs remain unknown.
Division/remainder by zero are unknown even though Ghidra's emulation fallback returns
zero. PIECE uses the low input width required by its behavior; invalid SUBPIECE extraction
is rejected before host-language shift masking can wrap its offset.

General evaluator tests use constructed p-code and independent expected values;
compiled-SLEIGH tests separately establish actual instruction effects. These do not
claim a full opcode/hardware campaign or new memory/interprocedural analysis.

## Baseline and reproduction

`tools/sa00_baseline.py` creates `sa00-generic-mbc3-v1`, a self-authored 64 KiB MBC3
fixture with valid header checksums, bank selection/direct call and computed JP HL.
It uses a fresh disposable distribution and profile and records each process command,
exit code, fixture hash and extension hash. It refuses existing work paths.

The first process inventories the loader result before fixture annotations, then a
separate annotated listing with explicit roots, a user function/comment and unchanged
ROM bytes. Both inventories retain assumptions, language/engine, function bodies,
physical file byte code/data sets, unresolved byte ranges/edges, warning categories
and named semantic checks/failures. Listing coverage is classification, not execution
proof. The denominator always remains all 65,536 file bytes. The third inventory
retains an intentionally edited unsupported flow instead of concealing it.

The second process reads the saved result, compares an independent preview, preserves
a primary-only reference edit through removal, reapplies, and rejects a reference-only
mutation for application/discovery. The third process reopens that mutation and checks
staleness plus preservation of the user's flow annotation. Existing installed lifecycle
checks additionally exercise old saved instructions and ownership behavior.

The test tuple uses JDK 21 and pinned Ghidra 12.1.3. On this macOS host the official
archive lacks the native decompiler; the selected disposable copy uses the separately
versioned patched `12.1.3+ghidraboy.switch-recovery.2` companion, with exact hashes in
the environment receipt. Missing-native and intermediate failed test runs are retained.
