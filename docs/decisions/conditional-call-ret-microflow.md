# Bounded conditional CALL/RET microflow (N6)

N6 extends the [N4](ordinary-returning-call.md) and [N5](nested-returning-call.md)
ordinary BankAnalysis contracts through the SM83 language's actual guarded
architectural effects. It supports CALL NZ/Z/NC/C (C4/CC/D4/DC, three bytes) and
RET NZ/Z/NC/C (C0/C8/D0/D8, one byte). It does not close SA-01, SA-03 or SA-07.

## Recognition and conditions

Recognition consumes `Instruction.getPcode(false)` and the instruction encoding.
One address-valued CBRANCH must skip to the actual 16-bit `inst_next`. Its prefix
must be pure, unique-only computation from the incumbent F register byte and
constants. The incumbent PcodeConstants evaluator checks that compiled predicate
against every F byte: the skip predicate must be exactly the inverse of the
architectural condition. The suffix must have two byte STOREs and two SP writes
followed by one direct CALL, or two byte LOADs, one PC write and one SP write
followed by RETURN PC. Other control operations, userops, architectural outputs
and dependence on skipped predicate temporaries refuse recognition. All other
internal p-code branches retain their conservative policy; this is not a general
CBRANCH interpreter. SLEIGH and p-code userop identities are unchanged.

| Condition | Relevant F bit | Taken when |
| --- | --- | --- |
| NZ | Z, bit 7 | Z = 0 |
| Z | Z, bit 7 | Z = 1 |
| NC | C, bit 4 | C = 0 |
| C | C, bit 4 | C = 1 |

An exact incoming F byte determines TRUE or FALSE. Missing F is UNKNOWN and
admits both outcomes. There is no default flag value, inferred predicate,
separate flag domain or path predicate lattice. Evaluation does not mutate F.
Ordinary conditional JP/JR retain their existing conservative alternatives;
N6 supplies no new predicate interpretation for them.

## Architectural outcomes

FALSE enqueues the unchanged incoming mapper, registers and physical RAM facts
at the established fallthrough view. CALL creates no frame or stack stores;
RET performs no pop and keeps the containing invocation's active frame. The
true suffix alone executes through the incumbent instruction evaluator.

A taken CALL must satisfy N4's direct, uniquely established physical target,
readable initialized executable non-writable ROM and actual continuation
requirements. Raw SP decrements and STOREs establish the return word. The frame
contains the actual return CPU address, caller SP, both physical pushed-byte
identities and physical callee identity; no word is synthesized. The callee
receives that actual post-push state.

A taken RET executes the real LOADs and PC/SP computation. RETURN PC, restored
SP, physical popped-byte identities and independently established outgoing
physical continuation must match the top active frame. RET never restores mapper
state. Conditional RET at depth two consumes the inner frame; at depth one it
consumes the outer frame. The false outcome remains within the same invocation.

UNKNOWN keeps true and false states independent before their paths complete.
Every reachable path of an invocation must satisfy the bounded proof. A valid
return cannot hide an unresolved false-RET path, and a valid false-CALL path
cannot rescue an incomplete taken callee. Failed nested proofs invalidate the
containing invocation even when another arm returns. As in N4/N5,
`AnalysisResult.Completion.COMPLETE` means the session worklist drained, not that
an invocation composed successfully. Failed composition leaves explicit frontier
reasons and the incumbent unknown caller continuation; it is not returned proof.

## Bounds and state composition

Each invocation admits at most one distinct conditional CALL/RET instruction
site, across all its reachable states. Reprocessing the same instruction after
N3 RAM weakening does not spend another site. A second site records an unsupported
frontier and invalidates the invocation. N5's separate one-nested-call-site bound
remains in force, with maximum active ordinary depth two. A reachable third-level
conditional call refuses its taken outcome; its false outcome remains queued.
Known-false calls do not consume depth or enter recursive targets. Reachable
physical self/mutual recursion still refuses without solving recursively.

Every instruction-state evaluation consumes the existing single global budget;
each callee retains the 128-state local cap. Cancellation, diversity widening,
cycles, missing instructions and unsupported effects retain N4/N5 refusal.
No Function, instruction, reference or summary is created by preview.

Actual callee register/flag, mapper and N3 physical RAM state reaches its caller
continuation. False CALL preserves pre-call state. Nested returned state resumes
A's remaining instructions before A can return to its own caller. Compatible
invocation returns require identical mapper and continuation identity, intersect
exact register/flag bytes and use unchanged N3 physical common-fact meeting.
Missing/conflicting bytes become unknown. Incompatible mapper/continuation
identities refuse composition. Ordinary worklist joins still require identical
mapper/register keys, so distinct exact states can remain separate and yield
ambiguous downstream destinations. No returning path is selected over another.

## Compatibility, evidence and alternatives

Engine `20260930-n6-conditional-call-ret-1` rejects N5 results through existing
read/currentness/application checks. AnalysisResult stays at schema 3, with
unchanged fingerprint components. Encoding, raw instructions, interpretation,
physical topology, permissions and initialization were already dependencies.
Frames, condition results, site sets, registers, RAM and worklists remain transient
within one preview. No persisted dependency, frame record or summary cache is added.

Self-authored compiled fixtures independently check all four flag meanings,
unknown splitting, actual return words, physical stack bytes, false SP/RAM/F
preservation, nested returned register/RAM/mapper effects, frame corruption and
WRAM-bank impersonation, conflicting returns, incomplete alternatives, recursion,
site reuse and local/global bounds. Scoped retained regressions, independent
review and the disposable pinned Linux installed/save/reopen witness are indexed
in the [evidence index](../sa/evidence-index.json).

A second evaluator, symbolic predicate domain, synthetic stack and language change
were unnecessary. General conditional control flow, arbitrary-depth calls,
recursive solving, CALLIND/computed/pointer calls, RST/RETI, RAM code,
software-call/ABI inference, general summaries, device/interrupt effects,
discovery expansion and whole-ROM qualification remain open. N6 stops here;
N7/N8 and broader campaigns require separate authorization.
