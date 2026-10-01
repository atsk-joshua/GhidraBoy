# Ordinary unconditional returning-call certificate (WUX-1P)

WUX-1P adds durable provenance to the incumbent N4–N7 evaluator. It does not
implement WUX-1A native CALL lowering, change stock flow, or expand call analysis.

## Admission and meaning

WUX-1A stopped because generic CALL Findings record resolved destinations before
`composeCall` establishes an invocation. A COMPLETE session and PROVEN singleton
CALL observation can therefore coexist with unknown SP or a failed matching RET.
Software-call summaries also share that observation shape. Findings remain
observations; neither their confidence nor opcode inspection authorizes lowering.

`AnalysisResult.OrdinaryCallProof` separately asserts that an architectural,
unmodified unconditional SM83 CD invocation completed the incumbent supported
matched-return contract. Its six fields are source, target and continuation static
Program execution address strings, each paired with a `MapperState.Physical` ROM
identity. CPU offsets alone are insufficient: `rom1::4100` and `rom2::4100` are
distinct. The continuation comes from the outgoing mapper and validated return,
never an assumed caller bank. No transient stack/register/RAM snapshot is saved.

The positive observation is emitted only at the end of `composeCall`, after actual
raw CALL SP decrements and STOREs established the return word, unique physical
callee execution completed, every relevant RET matched PC/SP and both physical
stack bytes, and compatible returned mapper/continuation states were reconciled.
Generated software/ordinary execution views are excluded by both block and address
space identity, including after block renaming. Encountering any excluded
instruction byte withholds the session collection, including root prefixes that
establish SP/mapper state and interior callee instructions. Checking certificate
endpoints alone would miss these consumed dependencies. Source, target and returned
continuation must each have one established physical
ROM identity consistent with their static mapping. The source also passes the
incumbent immutable executable instruction gate. No evaluator or mapper model is
added, and none of N4–N7's checks or bounds is relaxed.

## Must-proof aggregation

A preview-local session collector counts every evaluated CD encounter before
fetch, interpretation, software-summary and nested-depth refusal. Each compatible
successful composition adds one success. Any failed encounter leaves the counts
unequal; any differing six-field proof or outgoing MapperKnowledge permanently
conflicts the static source. Returned register/RAM differences retain the incumbent common
must-fact interpretation; no state snapshot is persisted.
Any incomplete callee exploration conservatively suppresses the entire session
certificate collection: its unexamined frontier may reach a previously successful
site under a conflicting state, including through a non-CD predecessor. This may
withhold independent successful inner/site proofs; it never promotes partial
observations. Only sites with equal encounter/success counts and no conflict
enter the final collection, ordered by static Program Address. Compatible repeated
observations deduplicate without choosing a first successful path. Joined snapshots
that weaken are evaluated again and can veto earlier success.

Each nested or sequential invocation has its own source identity. A successful
inner proof cannot certify an outer invocation whose remaining paths fail. A
refused inner invocation prevents its dependent outer composition from succeeding.
Independent inner proofs are retained only when no callee exploration is incomplete. Recursion and
third active depth remain refused. Conditional C4/CC/D4/DC and software summaries
never emit this type, even when their generic CALL observation is PROVEN.

STATE_LIMIT, CANCELLED and INPUT_CHANGED produce an empty final collection.
The result constructor also suppresses certificates for these dispositions and
obsolete schema/engine identities, including direct Gson deserialization. A future
consumer must additionally require current Program fingerprint, complete result,
matching configuration/root premises and the exact typed certificate. Mere saved
presence does not establish current authority.

## Persisted compatibility

AnalysisResult advances from schema 3 to schema 4 and engine
`20261001-wux1p-ordinary-call-proof-1`. The reader and currentness guard reject the
preceding N8/WUX-0 result. Recompute from actual architectural dependencies; never
infer missing certificates from old Findings, Functions, opcodes or references.
The old source constructor overloads construct empty proof collections.
AnalysisOwnership remains envelope 3 with its existing contract and option key;
Program mapping, language and compiler IDs remain unchanged. The fingerprint
adds `ordinaryCallProofEligibility` for the generated-storage discriminator at each
block, including mapped aliases otherwise absent from `romReadEligibility`. This
augmentation lives only in `ProgramFingerprint.capture`, the AnalysisResult
fingerprint/currentness path. Shared `components`/`coreComponents` keep their
preceding shapes so software-call and ordinary-entry persisted dependencies do
not become stale merely from this certificate-specific policy; those maps are
the shared dependency projection, not the complete AnalysisResult hash preimage. Rejection does not mutate saved Program or user annotations. The
legacy Finding reader in application serves bookmark cleanup only, never admission.

## Non-circularity and future owned flow

The collector consumes only current evaluator encounters. Prior `analysis.latest`,
certificates, generated Functions and supplemental navigation references cannot
supply a success. Existing generated-Function root exclusion and architectural
interpretation remain conservative. Consumed instruction bytes, permissions,
physical topology, raw effects, flow annotations and software configuration retain
the incumbent fingerprint and modification guard. Changing a consumed dependency
rejects stale results; fresh analysis must establish the invocation again.

Future WUX-1A must retain the direction:

    raw architecture + mapper/state/stack/RET proof
        -> current certificate -> owned native-flow artifact

An owned native-flow artifact must never become proof input. A physical CALL
reference currently differs from raw decoded CPU-space flow and therefore causes
an interpretation veto and fingerprint change. This task changes neither rule.
A future narrowly specified exception may recognize an exact, current, unchanged
GhidraBoy-owned derived-flow artifact as non-evidence, while preserving independent
conflicting annotations and later user edits. It must bind exact ownership,
artifact identity, dependency generation and unchanged state; historical ownership
or ANALYSIS source alone is insufficient. Ignoring all flow/ANALYSIS references is
not acceptable. Displacement/restoration, stale retirement, primacy and scheduler
feedback require their own authorized lifecycle work.

JP HL, conditional/indirect/software calls, RST and arbitrary computed-flow proof
classes remain future work. This certificate foundation alone claims no Wyatt
workflow improvement, native transport capability or whole-ROM completeness.

## Qualification boundary

Focused semantic and compatibility checks and actual separate-process persistence
are recorded in the evidence index. Overall WUX-1P qualification is blocked by
an existing native carrier fault-test failure: StockRouteFaultTest's paired
`__ghidraboy_state_entry_v1` recovery capture has zero byte chunks where its
unchanged oracle requires one. The same failure reproduces on the exact starting
baseline. No native code or test expectation is changed to force acceptance.
This remains a separate unresolved obligation; WUX-1P is not capability PASS and
WUX-1A is not resumed automatically.
