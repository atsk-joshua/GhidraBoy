# SA-01 pinned Ghidra mechanism inspection

This is source inspection and a bounded mechanism experiment, not SA-01
completion evidence. No production call model is selected by this receipt.
The primary verification receipt owns executed test outcomes.

## Identity and method

Inspected the downloaded `ghidra_12.1.3_PUBLIC_20260817.zip` directly with Python
`zipfile`, and byte-compared the relevant extracted source artifacts against
`/private/tmp/ghidraboy-sa00/ghidra_12.1.3_PUBLIC`. Archive SHA256 is
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`, matching the
repository pin. These source artifacts match the stock archive exactly:

| Artifact relative to distribution | SHA256 |
| --- | --- |
| `Ghidra/Features/Base/lib/Base-src.zip` | `a18a8650132670230cd12fdcfaa3e20605a1e1d24c07d033d20986fea2cff2d2` |
| `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip` | `fed5e47f0578b04597ead75fef77e2316a0458b9dbeeb1eb2cfa3d01472411b3` |
| `Ghidra/Features/Decompiler/src/decompile/cpp/flow.cc` | `bde7bed05b3cd01b0032610b517533e0414f2bb008cf87d81b7c9e577ad860ad` |

The macOS native executable used by SA-00 was the separately patched
`12.1.3+ghidraboy.switch-recovery.2` companion, SHA256
`5b736c3e9236667d35a732f226c99f0014736b9fe506147886a7f15ccb94939a`.
The official archive supplies no macOS executable. This source inspection does
not independently qualify a native executable or promote historical SA-00 results.

## Mechanism findings

Paths below are stock source entry paths inside the named source archives, or
native source paths relative to `Ghidra/Features/Decompiler/src/decompile/cpp`.

- `ghidra/app/plugin/core/analysis/FindNoReturnFunctionsAnalyzer.java:376-452`
  skips targets whose named callfixup payload exists and `isFallThru()` returns
  true. This is a supported way for a verified may-return helper to resist the
  heuristic; it is not a proof of unconditional return. The same analyzer marks
  `Function.noReturn` at line 209 and installs `CALL_RETURN` at lines 231-233.
- `ghidra/program/model/lang/InjectPayloadSleigh.java:190-210` computes
  fallthrough from the last template op. An unconditional BRANCH, BRANCHIND or
  RETURN suppresses fallthrough; CALL/CALLIND permits it. A dynamic payload must
  supply a truthful may-return property and must not use an always-fallthrough
  marker to conceal nonlocal or nonreturning paths.
- `flow.cc:1268-1286` injects a callfixup in place of the original CALL operation.
  It does not replace architectural ops preceding that CALL. Original SM83
  CALL/RST `push16(inst_next)` stores therefore remain and must not be duplicated.
  Injection context `nextaddr` is set equal to `baseaddr`; obtaining the actual
  payload-adjusted continuation requires the validated site model.
- `flow.cc:1155-1187` splices the supplied p-code into native control-flow
  processing, so inserted calls are real native call sites, not navigation refs.
  `flow.cc:683-697` applies prototypes and suppresses recursive self-injection.
- `ghidra/app/plugin/processors/sleigh/PcodeEmit.java:231-324` converts BRANCH,
  BRANCHIND and RETURN to CALL/CALLIND when a CALL override is applied, preserving
  preceding raw effects. Conditional external branches receive a guarding local
  conditional branch. CALL_RETURN additionally emits a null RETURN. None of
  these conversions synthesizes a hardware return-address push.
- `PcodeEmit.java:173-201` adds a branch for a fallthrough override after emitted
  p-code. A payload continuation can therefore coexist with a callfixup; its
  stack value and listing destination still need explicit consistency checks.
- `ghidra/program/model/pcode/FunctionPrototype.java:137-178` transfers fixup,
  noreturn and extrapop information. Stack purge and compiler stackshift feed
  extrapop. Native prototype stack recovery is not an executable architectural
  push/pop; raw execution and high-level stack recovery require separate checks.
- `ghidra/program/model/lang/PcodeInjectLibrary.java:404-409` publicly restores
  and registers XML injection. `registerInject` and `registerProgramInject` are
  protected. Production dynamic callfixups can extend the existing
  `CartridgeBusInjectLibrary.allocateInject`, while an isolated test can use
  `restoreXmlInject` for a static exact-site specialization.

## Bounded executable experiment

`src/test/kotlin/fi/gekkio/ghidraboy/SoftwareCallInjectionTest.kt` builds a
self-authored flat-memory RST helper with a two-byte inline target. Its raw helper
pops the hardware return, reads the target, pushes the adjusted continuation,
pushes the target and transfers by RET. The experiment checks stack bytes and SP
at helper entry, target entry and return, plus callee A/F results. A supported
XML callfixup models the known site's helper effects and calls the target;
separate assertions inspect native CALL and post-payload memory-store recovery.
A negative control first invokes the stock nonreturn analyzer on three real
RSTs followed by inline payload, requiring its actual noReturn/CALL_RETURN
decision. One repair installs the returning model and correct continuations.
Repeated `AutoAnalysisManager` runs then check the listing continuation and
absence of recreated disproven helper noReturn/CALL_RETURN. A separate physical
overlay fixture checks the explicit physical reference and raw/overridden CALL
endpoints before probing native decompilation. The first executed expansion
(focused-5) found that the decoded ordinary primary CALL reference masks the
newer `CALL_OVERRIDE_UNCONDITIONAL` reference: the Java endpoint remains base
`4000` despite the explicit `rom2::4000` override. Stock `PcodeEmit.java:819-840`
confirms this backward-compatibility precedence. The revised experiment records
that state, removes only the competing decoded reference primary flag, and
then checks the physical Java endpoint and ordinary native transport. Focused-6
**disproved the expected native failure**: the ordinary Decompiler produced
`physical_callee(); return;`. Therefore the source constraints below are not a
blanket blocker for inter-function cross-overlay calls. The current test promotes
this to a positive native CALL endpoint and symbol-identity assertion. It adds a
separate mixed-space function body API negative, which concerns intrafunction
representation rather than a call between two functions. Primary logs own the
revised execution outcomes; failed initial hypotheses remain recorded failures.

The experiment additionally executes the hardware RST, the actual injected
`PcodeProgram`, and callee p-code through Ghidra's public `PcodeExecutor` with
`BytesPcodeExecutorState`. Independent architectural expectations check every
frame byte, SP, PC, HL, DE, BC, and callee A/F results. Primary logs own the
execution result.

This exact-site specialization is deliberately not production recognition,
mapper-aware execution, ownership/persistence validation, or SA-01 acceptance.
SA-00 `InstructionInterpretation` must continue rejecting it as unsupported.
Public `restoreXmlInject` registration in this experiment is in-memory; it
does not demonstrate saved compiler-spec extensions or saved fixup availability.
The primary build/test log records whether the experiment passes; this file
makes no unexecuted pass claim.

A helper-level fixup also affects every call to that helper. A reusable dynamic
implementation must reject unknown/stale call sites and account for helper-wide
entry premises: validation of one caller does not validate all callers. The
nonreturn analyzer asks the global payload `isFallThru()` property without a
site argument, so this declaration cannot honestly encode target-specific
conditional return behavior by itself.

## Executed bounded result

The primary's `focused-7.log` reports a successful focused build/test command.
The resulting `SoftwareCallInjectionTest` JUnit XML reports two tests, zero
failures/errors/skips. Both the raw/injected execution comparison and repaired
ordinary-analysis checks pass. Native diagnostic output records physical CALL
`rom2::4000`, address-space ID `785`, matching the expected Program overlay ID;
the function symbol-ID assertion also passes. The mixed-space function-body
negative passes and preserves the original body. This receipt does not turn
these two mechanism tests into general SA-01 acceptance.

## Scope of the remaining SA-02 question

The executed cross-overlay CALL experiment succeeds in normal native transport
once competing primary-reference precedence is resolved. Do not present that
case as architecturally blocked. A correct call target reference and C name
still require the high-pcode physical endpoint checks in the updated test.

A distinct intrafunction representation constraint remains:
`FunctionManagerDB.java:219-223` requires a function body in one address space.
The test attempts to add a physical overlay continuation to a fixed-bank
function body, expects the public API to reject the mixed-space body, and checks
that the original body remains. This is a concrete representation requirement
for paths whose nonrestoring bank transition resumes at another physical
continuation; it does not imply all nonrestoring helpers are blocked.

Further source findings inform comparative prototypes rather than deciding their
outcome: `DecompInterface.java:898-909` selects an overlay encoder from function
entry; `PackedEncodeOverlay.java:53-69` remaps that selected overlay to its
underlying space; `funcdata.cc:150-163` bounds native processing to entry space;
`flow.cc:222` handles an out-of-range destination. The successful CALL result
shows why these facts must not be extrapolated to an untested blanket failure.
SA-02 must compare full intrafunction transitions, bank-sensitive memory and
continuations under normal native analysis. No repository-wide redesign is
selected by this bounded mechanism experiment.
