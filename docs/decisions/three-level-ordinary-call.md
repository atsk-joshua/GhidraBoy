# Three active ordinary calls (CALL-STACK-LIVENESS-2C)

The fixed internal maximum is three active ordinary invocations. Both admission
checks use the existing single `ORDINARY_CALL_DEPTH` constant. A fourth active
call still refuses. This supersedes the historical depth-two scope in N5–N7;
sequential calls spend capacity only while active. No public depth option,
summary cache or arbitrary-depth capability is added.

The accepted 1C diagnostic classified the old bound as FIXED_DEPTH_TOO_LOW:
self-authored depth-three paths succeeded under a diagnostic bound of three,
and the recorded source-derived Wyatt paths require three active calls. Keeping
two would retain that demonstrated refusal; removing the bound or choosing a
higher bound would expand beyond the established requirement. Synchronous
exploration remains bounded by three as well as the independent local/global
resource controls.

Raw CALL STORE ordering, physical frame identities, actual RET LOAD/RETURN and
restored 16-bit SP, mapper-qualified continuations, complete callee coverage,
physical recursion refusal, CFG cycles, cancellation, state limits and unanimous
current proof remain unchanged. Device writes retain 2A semantics; supported
unknown reads retain 2B coverage/value semantics. Conditional calls still issue
no OrdinaryCallProof themselves. No WUX-1B work is included.

Engine `20261001-call-stack-liveness-2c-1` advances compatibility once. Schema
remains 4 because transient frames and persisted result shape do not change.
Pre-2C results, including packed results, require recomputation; old engine
receipts retain exact retirement authority without proof/publication authority.
Consumed dependency fingerprints and WUX-1P/WUX-1A currentness are unchanged.

`BankAnalysisCallDepthTest` promotes self-authored depth 1–3 stack/return witnesses,
depth 4 and conditional depth 4 refusals, recursion, missing callee code, CFG
cycle, local/global limits, cancellation, deepest-level 2A/2B controls and packed
prior-engine recomputation. Retained ordinary-call and publication tests cover
incompatible returns, continuation identity and stale owned-flow retirement.
Detailed execution receipts belong in the external batch
`CALL-STACK-LIVENESS-2C-20261001`; final integrated qualification and evidence-index
closeout remain separate. The read-only Wyatt replay is a bounded internal
source-premise check, not public workflow or whole-ROM qualification. FF42 and
any later frontier remain unresolved obligations; no device repair is authorized
by this decision.
