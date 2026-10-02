# Architectural instruction flow beneath Ghidra presentation

RAW-FLOW-VIEW-1 implements FLOW-OVERRIDE-RAW-SEMANTICS-1 for bounded
BankAnalysis hardware/state reasoning. This supersedes the BankAnalysis enum
veto in the historical SA-00 interpretation decision; its shared validators
retain their representation-aware contract.

## Decision and alternatives

The package-private `ArchitecturalInstructionView` obtains `getPcode(false)` and
`InstructionPrototype.getFlowType/getFlows/getFallThrough` using the current
`InstructionContext`. Successors, predicates, CALL classification, matched CALL
continuation and JP HL recognition consume this view. No decoder or SLEIGH
change is involved. Raw stack effects and physical mapper resolution remain the
hardware authority.

Using instruction `getFlowType`, `getDefaultFlows` or `getFallThrough` would mix
saved presentation with raw effects. Switching to overridden p-code would invent
or erase transfer classification without establishing hardware stack effects.
Refusing all non-NONE enums also rejects ordinary stock Shared Return Calls
Programs. None of BRANCH, CALL, CALL_RETURN or RETURN has class-wide hardware
authority; an idempotent override remains harmless at its particular opcode.

The BankAnalysis gate permits raw-target ordinary reference retyping explained
by the enum. Stock CALL/JUMP references omit terminal bits, and RETURN can retain
a preceding ordinary CALL/JUMP reference; retained directness and conditionality
must agree with the decoded transfer. SourceType is not ownership evidence.
Foreign destinations, explicit reference overrides, length/decode changes,
explicit fallthrough and unsupported callfixups or unsafe software contracts
retain conservative refusal. Exact owned physical CALL correspondence remains
subject to the existing independent receipt/basis gate.

## Preservation and compatibility

Material discrepancies use existing AnalysisResult diagnostics with address,
enum, raw kind and presentation kind. They create no Program annotation.
Overrides, references, symbols, comments, bookmarks, Function bodies and
prototypes remain preserved by raw traversal. Existing exact owned stale-CALL
retirement remains a separate preview lifecycle operation; raw traversal does
not adopt unowned presentation or confer publication authority.

Engine `20261002-raw-flow-view-1` advances once; schema remains 4. Prior engine
results require recomputation and cannot authorize publication/application.
Known obsolete exact owned receipts retain only retirement authority.
Fingerprints retain saved enums, relevant reference endpoint/type/source/primary/
operand state, explicit fallthrough/length, raw p-code, bytes and decoded context.
Unowned overrides are never normalized away. Stock publishing still uses the
unchanged shared representation-sensitive validators.

## Qualification boundaries

Self-authored fixtures cover enum matrices, real CALL push/RET pop, RST push and
architectural continuation, exact branch predicates, finite four/eight loops,
mapper-changing banked callees, physical returns, 16-bit pointers and unsafe
annotations. RST retains the incumbent non-CD composition fallback; this change
does not add a new RST return solver, CALL depth or device model.

Current evidence, separate-process self-authored save/reopen and bounded unseeded
private-study replay are indexed under RAW-FLOW-VIEW-1 in the evidence index.
These controls do not establish arbitrary annotation safety or whole-ROM
completeness. The first downstream semantic frontier remains a separate task;
WUX-1B, complete provider aggregate, installation and release qualification are
outside this bounded acceptance.
