# Ordinary direct returning-call composition (N4)

N4 is a bounded SA-03 foundation after [N3](ordinary-memory-join.md).
It reuses the ordinary BankAnalysis worklist, PcodeConstants, MapperKnowledge,
ScalarAccess and SymbolicMemory.State. There is one instruction evaluator and
one physical RAM fact store. It does not close SA-01, SA-03 or SA-07.

## Supported invocation

Only an unmodified unconditional SM83 CALL (CD) is eligible. Its decoded direct
callee must resolve to one static execution view with one established physical
ROM identity. The target, each analyzed callee instruction and the continuation
must be defined in readable, initialized, executable, non-writable ROM with
established physical fetch bytes. Unknown bank selectors, ambiguous views,
missing instructions, RAM code and unsupported interpretations refuse composition.
Existing architectural-interpretation validation rejects conflicting references,
flow/length/fallthrough overrides and incompatible callfixups. Function objects
are not return proof, and N4 creates no functions or instructions.

The caller must establish exact SP through the incumbent register domain. CALL's
actual raw p-code executes before entry. Its two high-then-low architectural
STOREs and SP decrements establish the real return word in eligible physical
WRAM/HRAM. The callee receives exactly that post-CALL mapper, register and N3
memory snapshot. There is no ABI preservation assumption or fabricated frame word.
An unknown stack pointer or unavailable stack byte refuses composition.

## Matching and completeness

Only actual unconditional RET (C9) contributes a result. Its raw LOADs reconstruct
PC and its SP increment must restore the caller's established SP. RETURN's input
must equal the encoded CALL continuation, and the physical identities of both
popped bytes must equal those written by CALL. Numeric PC/SP alone cannot match
a frame in another CGB WRAM bank. The outgoing mapper must independently establish
one available physical continuation view; RET does not restore the caller's bank.

Every explored callee path must satisfy the bounded proof. Missing instructions,
unresolved memory or computed flow, unsupported userops/instruction effects,
nonreturning exits, cycles, diversity widening, local/global exhaustion or
cancellation refuse composition. Exhausting a worklist is never a return.
Conditional jumps conservatively retain both alternatives, including when their
condition is known. Guarded architectural effects remain unsupported, so
conditional CALL/RET and RETI are excluded. Pure instruction-local condition
computations do not fabricate architectural effects.

Nested ordinary or software calls fail closed. This also refuses direct and
mutual recursion without recursively solving a summary. Even a separate valid
return arm cannot authorize an incomplete invocation. A callee has at most 128
instruction-state evaluations, and each evaluation also consumes the original
session-wide configured state limit. Sequential calls share that global budget;
no per-callee multiplier escapes it. Global exhaustion/cancellation leaves the
whole result incomplete. A local refusal leaves explicit unknown caller flow.
Incomplete callee observations receive candidate reasons, never callable proof.

## Outgoing state

Returning paths must have identical mapper knowledge and static continuation
identity. Otherwise the ordinary call uses the incumbent conservative continuation,
with mapper, registers and RAM unknown. No new mapper lattice is introduced.
Compatible returning paths retain equal register bytes and remove absent or
conflicting bytes. The incumbent exact/unknown byte map includes flags; a wider
read with a missing byte is unknown. This boundary meet does not change N3's
ordinary join key: different mapper/register states still remain separate inside
both worklists.

Memory results use unchanged N3 `joinOrdinary`: only identical exact physical
bytes on every returning path survive. Missing/conflicting bytes become unknown,
echo aliases share physical keys and WRAM banks remain distinct. Actual callee
writes update those facts; unknown/device writes invalidate them under N2 rules.
Initialized Program RAM never fills a runtime fact. Unchanged caller facts survive
only because actual callee execution and all returning paths preserve them.
Mapper writes, registers and memory are taken from returned states, never copied
back from a saved caller snapshot.

## Lifetime and compatibility

There is no summary cache. One invocation's transient Exploration and CallFrame
remain inside one preview, under its Program fingerprint and modification guard.
No frame, register snapshot or RAM facts enter AnalysisResult. Engine
`20260930-n4-returning-call-1` rejects N3 reads/application; schema 3 and fingerprint
components remain unchanged. Newly inspected executable/initialized/read/write
permissions, instruction bytes, interpretation and physical topology are already
covered. The existing raw-pcode policy continues to exclude injected p-code;
validated software-call mechanisms remain separate and their API is unchanged.
Fetch diagnostics mark composition as nonlinear so existing linear-presentation
consumers cannot mistake it for a linear instruction trace.

## Evidence and alternatives

Pinned Ghidra 12.1.3 SoftwareModeling source confirms `getPcode(false)` supplies
no override, default flows contain the direct callee and fallthrough is separate.
Its p-code documentation describes CALL as transfer with no implicit stack and
RETURN as an indirect transfer. Compiled SM83 tests independently check two CALL
STOREs, two RET LOADs, real SP/PC effects, target and continuation. Conditional
returns were excluded because the incumbent evaluator does not interpret their
guarded effects. A second interpreter, a symbolic stack, cached summaries and
Function/ABI inference were unnecessary and rejected for this slice.

`BankAnalysisReturningCallTest` derives oracles from self-authored bytes, physical
ROM/WRAM topology and independent selector/stack expectations. It covers returned
registers/flags, mapper non-restoration, common/conflicting/missing/aliased RAM,
frame corruption and physical-bank impersonation, unknown targets, overrides,
missing continuation, nested/recursive/nonreturning flows and bounded refusal.
Detailed commands, source/dependency identities, independent review and installed
separate-process persistence are retained through the [evidence index](../sa/evidence-index.json).

General interprocedural summaries, arbitrary nested calls, recursive solving,
CALLIND/computed recovery, RST/helper inference, symbolic stacks/pointers,
interrupt/device-aware summaries, discovery expansion and whole-ROM closure
remain unsupported. A later bounded extension requires separate authorization.
