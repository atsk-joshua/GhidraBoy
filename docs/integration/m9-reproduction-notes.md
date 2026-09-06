# M9 bounded restore/repeat experiment

Completed source-level conformance on 2026-09-06. The real Trace RMI experiment passes **85 assertions**, including an independent Java observation reader and direct mGBA API rejection. This supplies controlled-reproduction evidence for the declared experiment; it is not installed GUI acceptance, a general replay system, or full M9 release qualification.

## Declared experiment

The self-authored `debugger/tests/fixtures/banks.asm` fixture uses an MBC5 cartridge without RTC (header type `0x19`). Its bank-1 entry at CPU `0x4029` executes `LD A,0x11`; the observed three instruction bytes are `3e 11 c9`. The setup reaches this physical bank using the existing `--fixture-ready` path, then deletes the setup breakpoint before saving a checkpoint. Deleting that breakpoint is part of the recipe: otherwise checkpoint restoration correctly re-arms its stop before the opcode executes.

The measured sequence is:

1. Capture the paused bank-1 boundary and save a SameBoy checkpoint. Verify its exact ROM, loaded boot, native state, model/core/config/patch and input-policy identities.
2. Execute one retired opcode using the real `step_into` RMI method.
3. Restore that exact backend-specific checkpoint and capture the restored boundary in a new epoch.
4. Execute one retired opcode again. Compare all six register pairs, captured instruction bytes, and the emulated-tick delta against the first interval.
5. Reject a deliberately incompatible checkpoint config, then verify the captured registers remain unchanged and controls remain usable.

Observed results in both intervals: `AF 0180 → 1180`, `PC 4029 → 402b`; `BC=0000`, `DE=ff56`, `HL=000d`, and `SP=cffc` remain unchanged. Bytes `3e 11 c9` remain unchanged. Each interval advances exactly one retired SameBoy instruction and **16 ticks at 8,388,608 ticks/second**. Instrumentation tick/instruction counters remain monotonic across restore; the experiment compares interval deltas, not absolute counter equality. Both initial/restored baselines and both resulting observations are exported, allowing the independent reader to verify these deltas directly.

No input transitions occur between the checkpoint and either measured step. The recipe records an empty input sequence and the explicit release-on-restore policy. The fixture has already executed `DI` and disabled the LCD at the selected boundary; its cartridge has no RTC, and no host-duration run or input request is made during the measured intervals. This controls the declared one-opcode result. It does not claim to control every source of nondeterminism in arbitrary software.

## Byte and source provenance

The experiment exports the CPU-visible range `0x4029..0x402b`, captured at every stop, with captured `ROMX=1`. Every persisted static source reference is independently reversed using the authoritative Program mapping and must resolve to physical `rom`, bank 1, offsets `0x29..0x2b`. Each observation includes its exact trace/session/epoch/capture/snapshot, register values, byte states, static mapping envelope/generation, backend/core/config/model/timebase, and loaded boot hash/policy.

This choice preserves the actual evidence: immutable physical ROM overlays are published once, and an exact-snapshot memory-state lookup may conservatively report their later snapshots UNKNOWN. The experiment does not relabel those unknown physical-overlay states as observed; it uses fully captured CPU bytes plus explicitly verified bank/source coordinates. The general observation-state behavior remains a separate implementation/qualification consideration.

`experiment-recipe.json` and each SameBoy observation retain the source assembly/ROM/runner hashes, exact checkpoint envelope and state hash, sequence, empty recorded inputs, declared clock/counter semantics and limits. Hypotheses remain separately empty. The conclusion is only that the two controlled intervals produced the same declared observations. An observation file itself still states that replay is unavailable because no executable state is embedded. The separate `state.sbs` is engine-specific; no portable checkpoint, reverse execution, call-stack inference, or cross-backend state conversion is implied.

A deliberately modified checkpoint config is a negative test fixture, labeled `incompatible-checkpoint`. Real RMI restore rejects it with `Checkpoint metadata mismatch`; it is not treated as a usable checkpoint. A separate modified observation fixture exercises `Different setting Config` diagnostics without claiming another actual emulator run.

## mGBA limits

A real mGBA RMI session reaches the same bank-1 fixture boundary and exports its observation. The connection does not advertise checkpoint/restore, and captured capabilities omit checkpoint support. The runner also calls the real mGBA backend API directly: it raises `mGBA (experimental) does not support: checkpoint`, creates no payload directory, and leaves the observed PC unchanged. No restore/repeat or SameBoy parity claim is made for mGBA.

## Reproduction and evidence

Run from the GhidraBoy root with built static-provider artifacts, both local backend libraries, and the self-authored fixture. Use a new evidence directory per run because a checkpoint directory must not already exist.

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
GHIDRA_INSTALL_DIR=/tmp/ghidraboy-switch-recovery2-mac-final/distribution \
GBC_EVIDENCE_DIR=/absolute/new/evidence-directory \
bash debugger/scripts/test_research_experiment.sh
```

The runner compiles current generic Java sources plus existing test helpers, uses an isolated project/home and owned local agent processes, and invokes a second Java process to read the exported recipe/observations without initializing a Ghidra application, trace, emulator, or optional profile. Real RMI uses local AWT/loopback facilities, so this host required execution outside sandbox restrictions. It does not display or automate the GUI and does not count as GUI acceptance.

Final run: exit **0**, `RESEARCH_EXPERIMENT_PASSED`, `RESEARCH_EXPERIMENT_REOPEN_PASSED`, and the direct mGBA rejection PASS. Both owned RMI processes exited; no uncaught asynchronous errors were recorded. The SameBoy agent log contains only the expected incompatible-config diagnostic; the mGBA agent log is empty. Existing Java deprecation warnings are retained. Initial isolated attempts documented a sandbox AWT abort and the two fixture/observation-semantic issues described above; those attempts are not counted as passing evidence.

Evidence directory: `debugger/build/research-experiment-20260906-v4/`. Log: `debugger/build/research-experiment-test-v4.log`. The runner and harness are source-only additions; they do not modify package scripts, the base real-trace harness, production plugin classes, or the shared milestone register.

| Input/evidence | SHA-256 |
| --- | --- |
| `debugger/tests/ghidra/ResearchExperimentTest.java` | `e309117de1b24be7588da98b1977fb81c764daf1c9a24630b835f9b8bd84e172` |
| `debugger/scripts/test_research_experiment.sh` | `b70ae746e2f8d727af817b45311e843231c03ac8fb19a9e212851fb2d4978fbd` |
| Final test log | `eb59a8d984f1b6fcd998f66348c2df6384a9a34a357092d533109fe05cc97ef0` |
| `experiment-recipe.json` | `1fd557524876e02a5845ffd08c6b8f2e02fd6f6b3fe7a67c82980d191215ce9a` |
| `initial-observation.json` | `7ac3911bb3b7296869e76ed55cc447c7b8687275231b6650a710bdd047871d17` |
| `first-observation.json` | `de73ed8995493e58a23a2b3f09364d4f077ee9b8a96d50eff25699c34beecbe9` |
| `restored-observation.json` | `4f61c3e86b28f92696da925ceec573c063794191c514cddc270c23a3a4213e35` |
| `repeat-observation.json` | `dfab87636a2a85e14168671981833d112cc7331769f1f966fae3c6e06c34ba8a` |
| `bank1-checkpoint/metadata.json` | `06371edfb738ee3f0e74beaea2fad09a506008273ffc439a791457fc3c2b6938` |
| `bank1-checkpoint/state.sbs` | `6756b39935fe68ca4fe5ca004a97092752bec9dc8adbf072cc6d56b8e4a0aa6d` |
| `mgba-observation.json` | `0fec679ba1f35476cc0dc675a12a6e75b5bf105e1daf33d132724a52daa1796c` |
| `mgba-checkpoint-rejection.json` | `81d8614a1ef8aaf4165b8af1d8639dfe9356bfdc7f282a67839434c54bde8b2d` |

Remaining work is broader installed/platform/GUI qualification and final artifact-matched acceptance. Physical Steam Deck verification remains deferred by the user until other work is solid. General-purpose input-timeline replay, controlled clocks for arbitrary RTC cartridges, and portable backend state remain outside this bounded proof.
