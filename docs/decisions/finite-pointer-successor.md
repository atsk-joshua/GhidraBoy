# Exact ordinary JP HL successor (N8)

N8 connects the incumbent BankAnalysis exact register-byte domain to one physical
executable successor. It extends the N1 ROM-value and N2/N3 RAM foundations while
preserving the [N4](ordinary-returning-call.md), [N5](nested-returning-call.md),
[N6](conditional-call-ret-microflow.md) and [N7](sequential-returning-call.md)
invocation contracts. It does not close SA-03, SA-04 or SA-07.

## Instruction and value boundary

Only one-byte SM83 E9 (`JP HL`) is supported. Actual compiled `getPcode(false)`
must contain exactly one BRANCHIND, with no output and exactly one architectural
two-byte HL register operand. The instruction must have computed jump flow,
no direct destinations and no fallthrough. The existing architectural policy
rejects flow, length, fallthrough and conflicting stored-flow overrides; raw and
`getPcode(true)` must agree. No mnemonic inference or generic internal-branch
interpreter is introduced. Compiled Ghidra 12.1.3 E9 is independently checked as
`BRANCHIND (register, 0x6, 2)`.

PcodeConstants requires both exact HL bytes from current ordinary state. Missing
bytes remain unknown. Existing immutable ROM LOAD propagation can establish L
and H independently and therefore compose N1 with N8. Ordinary Work registers
remain exact byte maps: the experimental AbstractValues/FiniteEntryProducer
finite domain is not an ordinary register lattice. No set expansion, table domain
or new value architecture is introduced.

## Three identities and physical validation

HL is a 16-bit CPU address, never a physical address. ScalarAccess FETCH resolves
it under current MapperKnowledge to an established ROM bank and offset.
ProgramMapping then binds current Program storage and the static execution
Address. For example CPU 4100 under MBC5 bank 2 is physical ROM bank 2 offset
0100 and static `rom2::4100`; bank 1 remains a different execution identity.
There is no contextual mapper fallback and no Function requirement.

Each source must have current file-source or loader-anchor authority, initialized
readable executable non-writable nonvolatile unmapped ROM storage and one physical
identity. Both block and space names exclude software-call and experimental
ordinary generated views. Original FileBytes, detached snapshots and generated
views do not establish values. All eligible independent physical sources must
agree. Exactly one eligible static entry at the CPU offset is required; even
agreeing duplicate execution identities do not justify choosing an alias.

The target must already have a defined instruction. Every fetched byte is checked
against its independently mapper-qualified FETCH identity, current authoritative
source agreement and instruction bytes, including window boundaries. Missing,
conflicting, ambiguous, writable, volatile, non-ROM or generated targets refuse
successor proof. Undefined bytes remain intact with an unresolved frontier reason;
N8 never decodes them or creates Functions.

## State and invocation semantics

A proved E9 produces exactly one Work with the validated target Address, current
mapper, current register bytes and current physical RAM facts. E9 has no memory
or register effect in compiled raw p-code: SP, flags and facts survive unchanged.
There is no fallthrough, stack push, synthetic return address, mapper restoration
or new CallFrame. The same enclosing exploration carries any active frame to the
target. An existing supported RET must still prove that frame using real physical
stack bytes and outgoing continuation. A root RET retains root behavior.

An unknown indirect target invalidates an active invocation even if another path
returns. All other BRANCHIND/CALLIND forms remain unsupported. Existing join,
widening, session budget, local invocation limit and cycle checks remain intact;
cycles cannot establish a containing matched return. No cyclic dispatch solver,
conditional JP/JR change or N6 microflow extension is added.

## Compatibility and boundaries

Engine `20260930-n8-finite-pointer-successor-1` rejects N7 results for read and
application. AnalysisResult schema remains 3. Work, pointers and frames stay
transient. Existing ProgramFingerprint already covers consumed source/topology,
permissions, initialization, current bytes, instructions and interpretation;
no fingerprint shape or public graph/native transport changes are required.

The selected bridge remains wholly in ordinary BankAnalysis. Experimental
FiniteEntryProducer and PredicatedCallGraph select sources for their own bounded
contracts and are not transplanted as ordinary successor authority. A second
interpreter, graph installation, custom Function and native lowering were
unnecessary alternatives.

Finite immutable pointer tables (a possible separately authorized N8b), arbitrary
pointer sets, mutable domains, dispatch/callback discovery, indirect CALL,
call-like PUSH/JP patterns, return synthesis, RST/RETI, recursive/cyclic dispatch,
general conditional or computed flow and whole-ROM closure remain open. A later
RET never retroactively makes E9 a call. No discovery or native transport is
broadened. STOP after N8; no N9.

Verification and exact source/dependency/fixture identities are recorded through
the [evidence index](../sa/evidence-index.json). Historical N4–N7 decisions retain
their original scope and receipts.
