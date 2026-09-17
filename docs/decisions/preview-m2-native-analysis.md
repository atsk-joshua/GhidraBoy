# PREVIEW-M2 native Ghidra integration

Status: implemented local candidate; target-platform headed acceptance remains open.

## Decision

Use one stock `INSTRUCTION_ANALYZER`, `GhidraBoyBankAnalyzer`, at
`AnalysisPriority.LOW_PRIORITY`. Its supplemental results do not need stock reference
consumers, and the late priority lets instruction notifications coalesce after stock
code/function/reference recovery stabilizes. It is a public nullary
ExtensionPoint whose class name ends in `Analyzer`, is enabled only for
`SM83:LE:16:default`, registers normal Auto Analysis options, supports Ghidra's
one-shot action and delegates to the existing `BankAnalysis`/application/ownership
services.

The adapter builds one sorted root set from external entries, user/imported non-owned
Functions and local/currently-uncontained notified code ranges. It does not treat every stock DEFAULT
Function as an independent entry premise. One shared worklist consumes Ghidra's
`AddressSetView`, so analysis is not multiplied into one 4096-state session per
instruction. The manager instance unions subsequent scheduler batches after the
initial broad notification and clears them in `analysisEnded`; the distinct one-shot
instance stays range-local. Only complete results are applied. Justified Function discovery is a
later phase of the same analyzer; GhidraBoy-owned Functions cannot seed a later run.
Generated supplemental references remain excluded from the interpretation
fingerprint and cannot circularly establish a result.

`AnalysisResult` advances to schema 3 and engine
`20260916-m2-native-analysis-2`. Every root records its unique physical identity,
partial mapper knowledge and topology provenance. For MBC5 ROMX, the physical bank
derives only the low selector and, when geometry requires it, the ninth bit.
Unrelated RAM enable/select, VBK, SVBK, RTC and register facts remain unknown.
Explicit state that contradicts the physical view refuses. Mapping schema v2,
SM83 language v2, constructors, compiler IDs and CPU pointer width do not change.

## Legacy preparation

`LegacyPreparation` is the single post-open service. It reconstructs cartridge
metadata from immutable FileBytes and recognizes RAM only as part of a coherent
historical GhidraBoy family. Recognition requires exact ROM family coverage and
each candidate's address space, range, permissions, uninitialized/file/mapping
provenance and expected historical name. The full descriptor/anchor plan is
preflighted before one transaction. Conflicts, near matches and ambiguity refuse
before mutation; cancellation rolls back; a successful rerun performs no semantic
change. Existing SRAM0 may be recognized, but absent declared SRAM banks are never
created. OAM, I/O and IE remain device/unresolved regions.

`GhidraBoyProgramPlugin` supplies Tools → GhidraBoy → Program Status... and Prepare
Legacy Program... through supported ProgramPlugin/DockingAction APIs. Status is a
compact cartridge/physical/migration/analysis summary, not a replacement analysis
dashboard.

## Pre-upgrade primacy boundary

Pinned 12.1.3 source establishes that `ProgramDB` replaces the language and calls
`CodeManager.reDisassembleAllInstructions` during construction. The only translator
Program callback, `fixupInstructions`, follows redisassembly; LANGUAGE_CHANGED and
ProgramPlugin callbacks occur later. Redisassembly retains/recreates DEFAULT flow
references and can make them primary, demoting surviving USER_DEFINED references.
The exact old primary booleans are no longer inferable afterward.

Therefore migration remains an outer operation. `UserReferencePrimacy` retains the
PREVIEW-M1 mechanism: bind the source Program/input/language/compiler/domain,
snapshot the complete USER_DEFINED tuple and primary state, preflight exact identity
after upgrade, accept only generated-DEFAULT displacement, change primary bits only,
verify all tuples, and record preservation. `migrate_legacy_program.py` combines
snapshot, project copy, normal language upgrade, restoration, structural preparation,
new GZF output and separate-process verification. No direct upgrade/downgrade claim
is made for the immutable original.

## Alternatives rejected

- A script-only analyzer path fails A-GHIDRA and the intended user workflow.
- One BankAnalysis invocation per instruction duplicates work and makes bounds
  meaningless.
- Reset MapperState defaults invent unrelated entry facts.
- Translator/plugin post-upgrade repair cannot reconstruct information already lost
  before its callback.
- Names alone are insufficient evidence for legacy RAM identity.
- Creating all header-declared SRAM banks would fabricate Program topology.

## Remaining obligations

The actual Linux/Steam Deck Ghidra 12.1.3 headed workflow, full private-target
preservation inventory, normal Auto Analyze dialog execution, ordinary Decompiler
inspection and separate-JVM reopen remain required before ENGINEERING-PREVIEW can be
READY. General hardware/device, arbitrary pointer/state, whole-ROM completeness and
unsafe automatic RST/JumpTable recovery remain open roadmap scope.
