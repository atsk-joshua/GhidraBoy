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
fourth active depth remain refused under [2C](three-level-ordinary-call.md). Conditional C4/CC/D4/DC and software summaries
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

Historical WUX-1P design requirement, now retained by qualified WUX-1A:

    raw architecture + mapper/state/stack/RET proof
        -> current certificate -> owned native-flow artifact

An owned native-flow artifact must never become proof input. At the WUX-1P
checkpoint, a physical CALL reference differed from raw decoded CPU-space flow
and therefore caused
an interpretation veto and fingerprint change. WUX-1P changed neither rule.
The then-future narrowly specified exception would recognize an exact, current,
unchanged
GhidraBoy-owned derived-flow artifact as non-evidence, while preserving independent
conflicting annotations and later user edits. It must bind exact ownership,
artifact identity, dependency generation and unchanged state; historical ownership
or ANALYSIS source alone is insufficient. Ignoring all flow/ANALYSIS references is
not acceptable. Displacement/restoration, stale retirement, primacy and scheduler
feedback require their own authorized lifecycle work.

JP HL, conditional/indirect/software calls, RST and arbitrary computed-flow proof
classes remain future work. This certificate foundation alone claims no Wyatt
workflow improvement, native transport capability or whole-ROM completeness.

## CALL-STACK-LIVENESS-2B read coverage

Ordinary exploration now distinguishes transient `ReadOutcome.value` (nullable byte
knowledge) from `ReadOutcome.coverage` (`SUPPORTED` or `UNRESOLVED`). Its
`Exploration.structuralComplete` admits composition only when control and effect
coverage is complete. A supported read may produce unknown data without vetoing
coverage: exact immutable ROM values, canonically backed ordinary WRAM/HRAM, and
the bounded CGB FF70 selector read are supported. FF70 stays unknown even when
mapper SVBK is known; reading it does not infer a sampled selector value. Other
devices, unknown addresses, unresolved physical identities and unavailable ROM
reads remain refusals. Each byte of a multi-byte read must be supported.

Unknown registers and memory remain unknown through PUSH/POP and returned-state
composition. Using them as a write target, return operand, SP or required mapper
selector still invokes the existing conservative checks. Exact return slots,
physical identity, restored SP, established executable continuation, exhaustive
compatible returns, cancellation and resource/cycle/depth bounds remain required.
The collector still withholds session authority after actual incomplete callee
exploration. No durable callee summary or new persisted field is introduced.

Engine `20261001-call-stack-liveness-2b-1` retains schema 4. Pre-repair engine
`20261001-wux1p-ordinary-call-proof-1` results cannot authorize proof or application,
even on unchanged bytes/fingerprint; recomputation is required. Existing owned
CALL receipts retain exact retirement/restoration authority but cannot exempt
old physical flow as current proof. Language, mapping and ownership formats are
unchanged. WUX-1A remains CLOSED / QUALIFIED for its recorded candidate; this
repair requires its own focused verification and makes no campaign completion
claim. Device-write liveness (1A), depth (1C), broader Wyatt proof and WUX-1B remain
outside this change.

## Qualification boundary

WUX-1P is CLOSED for its bounded provenance contract.

The implementation commit is
`83cc5a621ea379fec7c474f3f5650c3facf72d04`. Focused semantic/currentness
qualification passes 178 tests. Three separate JVM phases prove exact persisted
certificate identity/currentness, recomputation agreement, preceding schema-3
rejection, preservation of unrelated user annotations and stale refusal after a
consumed RET dependency changes.

The initial broad provider run exposed one pre-existing `StockRouteFaultTest`
oracle failure. The investigation at that time on the exact starting baseline
and WUX-1P candidate concluded that the deliberately substituted
`__ghidraboy_state_entry_v1` convention rejects missing state-entry authority
through its `uponentry` protocol before the native decompiler requests carrier
bytes. The test was split so ordinary carrier faults retain their one-byte recovery
requirement while the state-entry case explicitly requires zero byte requests and
the semantic state-entry rejection. No production code or native transport changed.

The qualified checkpoint is
`3bff09e4a4afeb1d486d4dd08b44845db9b209f9`
(tree `43059ddb0a9641345bf6f721d751e69434857e6c`). Final
`./gradlew test ktlintCheck buildExtension` passes with 1,098 tests, zero failures,
errors or skips.

This qualification establishes only the typed ordinary-CD admission authority.
At that checkpoint, WUX-1A native CALL lowering, DEFAULT displacement/restoration,
owned generated-flow non-evidence handling and scheduler convergence remained
separate obligations. The [WUX-1A contract](ordinary-call-stock-flow.md) now records
CLOSED / QUALIFIED bounded ordinary CALL integration. Broader Wyatt workflow
acceptance remains separate.

**Qualification oracle erratum (Q1-D1/R1).** Pinned Linux comparisons establish
the same one-byte `c9` debug acquisition at the qualified WUX-1P checkpoint and
all later WUX-1A commits, while semantic missing-state-entry rejection remains
correct. The historical zero-byte ordering conclusion above was incorrect. Q1-R1
removes only that non-semantic assertion; historical receipts remain preserved.
This is an oracle erratum, not a WUX-1P production regression.
