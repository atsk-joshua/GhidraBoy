# Bounded adversarial investigation

Independent worker ownership: new `SoftwareCallAdversarialTest.kt` and this note.
The primary owns implementation, shared contracts, builds and installation
campaigns. This is an adversarial investigation receipt, not SA-01 completion
certification or independent approval of this worker's own tests.

## Baseline identity and reproduced failures

The investigated `SoftwareCallEffects`, `SoftwareCallExecutionView`,
`SoftwareCallValidation`, and `FarCallConvention` source SHA256 hashes matched
`../sa01-production-20260907/handoff-manifest.json` before the primary's fixes:

| Source | SHA256 |
| --- | --- |
| SoftwareCallEffects.java | df033ccc99375bc7cf909db7c131bcf05674143b8cf1e3d399a0794a10ef4170 |
| SoftwareCallExecutionView.java | 282f4a9fbd3ebe1a73b1847addf9e89bf1330a308120a531182ae894a2340b2a |
| SoftwareCallValidation.java | 6acb83b9f33a5866ec8801b8713f92be815d329a865916fc6370ae298b0b6c2d |
| FarCallConvention.java | 2612438ddc407f4790e892f576396ad283d8098fd97f274a38dd7ac785fd1274 |

The first eight new tests reproduced five failures during the primary's
`focused-2` campaign (see its retained XML):

1. A user-defined primary `CALL_OVERRIDE_UNCONDITIONAL` to the wrong fixed helper
   was accepted at initial application preview.
2. An imported primary ordinary CALL reference to the wrong helper was accepted.
3. Actual legacy `FarCallConvention.apply` produced a supplemental physical
   target CALL reference which production preview accepted without an explicit
   endpoint migration. Stamping that state would not establish its native
   helper semantics.
4. A caller at CPU `3ffd` returned to fixed-ROM `3ffe`; NOPs at `3ffe`/`3fff`
   then reached physical bank 2 at CPU `4000`. The first continuation was in
   the caller's space and preview created zero required execution views.
5. Raw nested ordinary callee execution had an actual matched RET witness and
   balanced stack/register/flag results, but imported noReturn and CALL_RETURN
   metadata prevented reviewed repair before application.

Three negative tests passed: unrelated BRANCH overrides remain vetoes, and
missing helper/callee instructions explicitly reject without Program mutation.
The latter two are evidence of unresolved instruction discovery, not fresh-import
closure. Manually prepared instruction boundaries and absent Functions are
separate fixtures and claims.

## Integration observations

The primary added initial reference rejection, complete finite continuation
scanning, and matched caller-site/physical-target return witnesses for specific
metadata repairs. `focused-3-xml/TEST-fi.gekkio.ghidraboy.SoftwareCallAdversarialTest.xml`
shows initial-reference and later-window tests passing. Canonical and execution
view direct DecompInterface requests both pass the later-window test.

The additional canonical continuation test also passed in focused-3. It uses
three callee flag patterns to exercise both JR NZ outcomes and both RET C
outcomes across the `3ffe`→`4000` window boundary. It compares independently
executed raw architectural caller/helper/callee/continuation p-code against the
installed canonical payload with Ghidra's PcodeExecutor. The assertions cover
physical target, the actual hardware-pushed `3ffe` continuation, one bank-selector
write, A/F/BC/DE/HL/SP/PC, and two distinct live external return words (`3456`,
`6789`). Native canonical and alias roots also produce the target call and RET.
Physical instruction selections are explicit fixture assumptions; this executor
comparison is not a mapper-discovery or all-input proof.

Focused-3 retained two failures. The nested repair passed application assertions
but normal native decompilation rejected its returning-target marker with
`No current code-derived returning path for rom2::4120`. The writable initial
continuation was already rejected correctly by the raw boundary gate; only the
new test's expected diagnostic was wrong. The test now asserts that actual
boundary diagnostic while retaining rejection and no-mutation requirements.

Further tests distinguish mutable later instructions and mutable instruction
operand bytes from the already-protected first continuation boundary. Each
requires raw first-boundary compatibility before expecting complete continuation
validation to reject. The primary was advised to check every consumed byte,
including physical ROM identity, initialization and write/volatile permissions.

The source review of canonical local lowering found no branch-displacement
problem: address edges become local relative edges, and original instruction
micro-operations remain one-to-one. Conditional RET preserves real stack loads
and PC rather than borrowing a fabricated outer return word. These source
observations are supplemented by the executed branch/RET comparison above;
remaining unsupported continuation calls, bank writes and general repeated
same-CPU/different-bank paths remain obligations.

## Review constraints and remaining evidence

Exact nested noReturn/CALL_RETURN repairs need explicit public review inventory,
per-field edit-preserving removal, strict post-apply revalidation and separate
save/reopen evidence. Matched raw RET is necessary; it must not exempt unrelated
references, inline/thunk/fixup contracts, custom purge or a different endpoint.
The new BRANCH negative guards one such unrelated interpretation.

Legacy supplemental references currently receive safe preservation and rejection.
This does not implement their reviewable migration into the production workflow.
No existing test expectation was weakened to manufacture successful application.

This worker ran no shared build, formatter, installed campaign or GUI mutation.
Exact commands, current source/package identities, later test outcomes and final
requirement-by-requirement disposition belong to the primary receipt. Earlier
failures remain retained; the historical 531-test pass does not qualify these
changes. Renewed independent correctness review is required after integration.

## Executed follow-up: focused-5

`focused-5.log` and `focused-5-junit.json` record 91 focused tests, zero failures,
errors or skips, with lint passing. The adversarial class contributes 11 tests,
all passing in its retained XML. The primary serialized the build and formatting;
this worker inspected the retained results. The formatted test-file SHA256 at
this checkpoint is `c052b63a720aa8aaf1b8b8b340cad63cc1fdee84133c8e77f48de33c3c0c75a3`.

The nested failure was traced to evaluating `getDefaultFallThrough()` while
CALL_RETURN was still active. That API yielded null, leaving a removed
fallthrough after the flow enum was repaired. Application now uses the actual
architectural successor; the test asserts strict installed effect compatibility,
matched nested return evidence, normal native CALL/RET, and restoration of the
original imported noReturn/CALL_RETURN state on removal. It also checks the
new pre-apply nested repair inventory field by field, including witness provenance.

The paired canonical/execution identity test now edits a CALL override reference
on each member in turn. Both registry resolution and installed payload generation
must reject either member's drift; removing only the added reference restores
both paths. This covers direct paired-entry revalidation. A nested caller that
would otherwise borrow an alias configuration is additionally guarded by the
same `current()` pair check by source inspection; no separate installed nested
alias-drift execution is claimed here.

The mutable-first-boundary test now matches its preexisting rejection diagnostic.
The added later-fetch test separately proves that raw first-boundary compatibility
passes before complete continuation validation rejects a writable later RET or
a writable second byte of `LD A,55`. These checks passed without widening accepted
mutable-code semantics.

Focused success does not close the missing discovery/migration/general banking
obligations identified above. Full provider, exact new package, separate-process
installed lifecycle and normal Decompiler-window qualification remain separate
primary-owned gates.

## Later adversarial additions and retained native failure

Three further tests increase this class to 14 cases:

- One DecompInterface stays open while an actually consumed inline target byte
  changes the physical target from `rom2::4100` to `rom2::4120`. Both canonical
  and alias decompiles must reject stale semantics. Public removal, preview and
  reapplication must restore both native paths with the new physical CALL and
  a changed constant write (`11`→`22`) to WRAM `c200`. There is no explicit cache
  flush or native-process reset in the test.
- A synthetic saved registry is marked version 3 and lacks the new canonical
  identity field. Resolution and injection must reject incompatibility, while
  public removal and reviewed reapplication install current semantics. This is
  a negative schema-compatibility and recovery test, **not** save/reopen of an
  actual archived version-3 Program or qualification of every old ownership record.
- A real decoded DEFAULT DATA operand reference on view `LD (c200),A` is refined
  into an ANALYSIS WRITE reference to the same operand/address. Both entry
  paths must remain current and decompile. An unrelated DEFAULT reference must
  still invalidate them; an added user reference must invalidate both and survive
  removal with the edited view preserved. This reproduces the default-to-analysis
  reference transition identified in the installed constant-view campaign without
  treating arbitrary DEFAULT references as harmless analyzer output.

The stronger mutation test exposed a real additional canonical native failure.
Initial C called the expected target but then wrote `rst00 = 0x11` and emitted
`halt_baddata`, rather than storing to `c200` through the validated continuation.
The incorrect `rst00` write corresponds to decoding the inline payload's `02`
byte as `LD (BC),A` with BC zero. Consequently the failed test was retained and
its correct memory/target expectations were not weakened.

The retained [native dump](canonical-tail-before-native.xml) proves that the
software-call payload contained the intended continuation branches, direct write
to `c200`, stack loads and RETURN. Its nested direct-write callback also emitted
correct `STORE(space ram, c200, A)` operands. This excludes a simple wrong callback
parameter or wrong STORE-space explanation. Native relative-flow resolution can
lose a branch target whose CALLOTHER operation is removed during injection,
then fall back to the original caller instruction's fallthrough. The primary
correlated this dump with the pinned native `FlowInfo::findRelTarget` code.

The correction gives each lowered instruction entry a stable scratch COPY
anchor before its raw operations. Relative branches target those anchors instead
of operations removed by nested injection. It also applies a reviewed canonical
CALL_RETURN/no-fallthrough transport role, preventing initial native flow decoding
from treating inline payload or unmapped old-bank continuation bytes as code.
Architectural callee `MAY_RETURN` remains separate: raw caller p-code is unchanged,
and the canonical expansion itself executes the validated continuation's RET.
Mapped alias flow retains the execution-view path. This is an explicit native
transport contract, not a claim that the software callee never returns.

The primary reported focused-7's 15 selected tests passing (the 14 adversarial
cases plus the retained banked canonical test). That run preceded removal of the
temporary native-debug hook and the final assertions on structured review fields.
The final test now also requires canonical and alias C to exclude bad-instruction,
truncation and `halt_baddata` diagnostics while preserving exact physical target
and constant-memory-output checks. Preview assertions distinguish
`canonicalTransport = TERMINAL_CONTINUATION_EXPANSION`,
`appliedCanonicalFlow = CALL_RETURN` and architectural `exit=MAY_RETURN`.
Final execution of these assertions is recorded separately below when available.

## Final bounded test checkpoint: focused-8

The retained [focused-8 log](focused-8.log), [aggregate](focused-8-junit.json)
and [adversarial XML](focused-8-xml/TEST-fi.gekkio.ghidraboy.SoftwareCallAdversarialTest.xml)
show 94 focused tests with zero failures/errors/skips and successful lint.
All 14 adversarial tests pass; their XML timestamp is `2026-09-07T10:32:34.734Z`.
The formatted adversarial test-file SHA256 is
`9f73c0bcecbac2340c1f0587736015ac7693ec7deb7eb8c57813b3338bee6964`.
The temporary debug hook is absent from this qualified test source. The structured
canonical role, explicit architectural MAY_RETURN, exact changed target/output,
and no-bad-instruction/no-truncation assertions all execute in this checkpoint.

Expected stale-injection errors from the two deliberately invalidated decompiles
remain in the captured test output. Their accompanying failed-decompile and
registry-rejection assertions distinguish them from accepted native output; no
log-suppression mechanism was added. Installed campaign error classification and
its complete lifecycle are independently owned by the primary receipt.

This completes the assigned bounded adversarial tests and their executable
follow-through. It does not close the original discovery, legacy migration,
general banking, installed persistence or normal-window obligations listed above,
or convert a focused subset into whole-provider or SA-01 completion certification.

## Operand-specific reference follow-up: focused-9

The refinement regression now checks a narrower counterexample: a DEFAULT
primary DATA reference to the correct `c200` destination attached to operand 1
of `LD (c200),A`. That operand is explicitly verified to be register A. Matching
the direct write's destination alone does not establish that this reference is
decoder output; the memory destination is operand 0. Both registry entry paths
reject the wrong-operand reference. Deleting only the added reference restores
both; re-adding it before public removal preserves its destination, operand,
DEFAULT source, DATA type and primary status with the edited view.

The retained [focused-9 log](focused-9.log), [aggregate](focused-9-junit.json)
and [adversarial XML](focused-9-xml/TEST-fi.gekkio.ghidraboy.SoftwareCallAdversarialTest.xml)
record 94 passing focused tests, including all 14 adversarial tests, with zero
failures/errors/skips and successful lint. The adversarial XML timestamp is
`2026-09-07T10:39:17.476Z`. This strengthens the existing test rather than adding
a fifteenth case. Earlier full-provider results predate the narrowed production
reference predicate and do not qualify it by themselves.
The formatted test SHA256 at this follow-up is
`81beeeffaf0a0945d99e7d820a6060fc4f381b71808239c60b58fd0a81d18d96`.

## Backwards relative-edge probe

A final independent test directly exercises the negative relative-displacement
case missing from the earlier forward-branch/conditional-RET fixtures. The callee
executes `LD B,3; XOR A; RET`; the transported bank-2 continuation executes
`INC A; DEC B; JR NZ,-4; RET`. The raw callee proof establishes B=3 and A=0,
and the payload is required to contain an actual backwards local CBRANCH.
Both canonical and mapped native roots must retain the physical target CALL
and RETURN and contain no bad-relative, bad-instruction, truncation or
`halt_baddata` output.

The retained [one-test log](backward-edge.log) and [XML](backward-edge.xml)
show this test passing unchanged with zero failures/errors/skips. The existing
relative-edge encoding therefore passed this concrete native negative-offset
probe; no provider change or altered expectation was needed. This adds a
fifteenth adversarial test. Its native assertions qualify the loop's transport
and terminator, not a separately executed all-input loop summary or arbitrary
same-CPU multi-bank loop semantics. The earlier raw-versus-injected execution
fixtures remain separate evidence.

The primary owns subsequent formatting/full-provider qualification and final
artifact identities. This worker made no additional provider changes or builds.
