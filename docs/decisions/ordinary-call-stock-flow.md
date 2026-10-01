# Ordinary returning CALL stock flow (WUX-1A)

This bounded integration consumes the [WUX-1P certificate](ordinary-call-proof-certificate.md).
It does not change the evaluator, raw SM83 p-code, mapper premises, conditional
CALL or software-call admission. JP HL remains a separate obligation.

## Selected representation

A current complete result with an exact OrdinaryCallProof can replace precisely
one decoded DEFAULT unconditional CALL reference with one ANALYSIS unconditional
physical CALL. The replacement uses the decoded operand index and becomes primary.
Generic singleton Findings are insufficient. Competing flow, an existing target
reference at that operand, or a competing primary DATA reference refuses publication.
USER_DEFINED, IMPORTED and edited references remain intact.

The physical reference transports the proven target through stock Listing,
Instruction.getFlows(), block CFG and overridden p-code. The alternative of only
making the physical CALL primary was rejected by [WUX-0](proven-stock-flow-integration.md):
the retained DEFAULT CPU reference adds a false second stored CFG edge. No SLEIGH,
override type or custom native transport is introduced. Coincident static physical
and CPU target addresses still use the same reversible reference contract.

## Compatibility and ownership

Ownership envelope 6 adds a separate `ordinary-call-flow` group with receipt
version 1. Existing envelopes 1–5 remain readable; they cannot acquire ordinary
CALL displacement authority through an envelope upgrade. Old reference/function
receipt deletion rules remain unchanged. The receipt uses AnalysisOwnership.Point,
records all three certificate static/physical identities, engine/basis fingerprint,
source bytes, and exact installed/displaced reference tuples including source,
type, operand, primary state and symbol identity. No language, compiler, mapping
or AnalysisResult schema/engine identity changes.

Removal undoes an exact unchanged physical tuple and restores the exact original
DEFAULT tuple when its original decoded source still matches. An edited physical
reference or a competing restoration tuple is preserved. If source semantics
changed, the unchanged owned physical tuple can be retired but the obsolete
DEFAULT is not recreated; current decoded/user references are retained. Stock
Functions are not owned or removed by this group.

## Dependencies and architectural evidence

Only the AnalysisResult fingerprint path normalizes an exact unchanged owned
physical CALL plus its displaced DEFAULT receipt back to the original DEFAULT
representation. Shared ProgramFingerprint component contracts still hash stored
references. Additional/edited flow remains visible, invalidating currentness.
Structural receipt matching is separate from basis comparison to avoid recursive
fingerprints. Architectural interpretation ignores only that exact receipt-owned
CALL while its original normalized proof basis is current. Fresh certificates
still require the original raw byte/stack/mapper/matched-return exploration.
Generated/native flow without correspondence cannot establish proof.

Every preview retires stale derived flow before capturing the modification number
and new fingerprint, including previews that subsequently reach STATE_LIMIT.
An unchanged original basis remains installed during a smaller incomplete invocation.
This retirement is a reversible preview-side Program mutation, not a new incomplete
result publication. Retirement happens on analysis invocation, not immediately on
arbitrary external edits without analysis.

## Stock scheduling and bounded verification

Actual publication changes notify AutoAnalysisManager.codeDefined at the exact
source addresses. Idempotent apply sends no notification. A session token containing
sources, normalized fingerprint and receipt identities consumes only unchanged
publication feedback; source, flow or ownership changes cannot suppress another
relational pass. analysisEnded clears the token. The incumbent analyzer remains
an INSTRUCTION_ANALYZER at LOW_PRIORITY. No stock analyzer is invoked manually.

Pinned Ghidra 12.1.3 InstructionDB, InstructionPcodeOverride, PcodeEmit,
ReferenceDBManager, FunctionAnalyzer and AutoAnalysisManager source confirms the
mechanisms linked in [references](../references.md). Focused tests cover Java stock
flow/high p-code, raw equivalence, admission, edits/restoration/currentness,
stale/incomplete controls, real same-session scheduling and packed save/reopen.
The native DecompInterface test requires the pinned platform executable and reports
an explicit skip when it is unavailable. Detailed commands and source/dependency
identities are indexed in [evidence](../sa/evidence-index.json).

Full provider, separate-JVM persistence matrix, Docker, installed/headed, release,
Steam Deck, debugger, Wyatt and whole-ROM qualification remain unrun here. Native
C transport still needs execution on a pinned native-capable distribution when
that executable is absent. WUX-1B / JP HL does not begin with this integration.
