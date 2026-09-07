# Independent review of the normal-window comparison

Date: 2026-09-07. Scope: compare the six requested caller entries and two
physical targets with the retained installed run 7 native C. This worker made no
UI actions, builds, source edits or Program mutations.

## Evidence access and attribution

The delegated conversation did **not** contain the primary worker's inline GUI
screenshots. No screenshot files were supplied. This review therefore cannot
independently certify the displayed windows, selected addresses, warnings or
session identity. The primary worker reported that canonical entries returned
pointer-labelled `rom1` values while aliases returned scalars. That observation
is compared below with independently read retained artifacts; it is not presented
as this reviewer's own visual observation. The subsequent file-backed primary
transcription, [observations.json](gui-window/observations.json), was independently
compared against all six retained C files. Every recorded function name, call,
write and return expression occurs in its corresponding baseline; the recorded
warning categories also match. This is review of the primary's observation record,
not independent screenshot inspection.

The retained baseline is
`../sa01-production-20260907/installed-runs/resume-run-7/`.
Its script and fixture SHA256 values were recomputed and match `run.json`:

- Script: `e002e88c9812846ab5dd044d676512bd7a3efbb9f3f5240dd9083a0db1865c79`.
- Fixture: `b7e0403c9c8c6cfb182be91bb771016b4c588f4793e8e271c330f57f988bd5b8`.

Live process/installation identity and GUI close/reopen observations belong to
the primary worker. The retained identity/runtime records were reviewed below.

## Six-entry comparison

| Entry | Retained native C behavior | Comparison with primary-reported GUI observation |
| --- | --- | --- |
| Canonical `rom1::4200`, `banked_source` | Writes `param_1` to mapper address `0x2000`, calls `banked_destination()`, returns `undefined *` value `&DAT_rom1__4300`. | Primary record matches the listed function, call, writes and return; screenshots not independently inspected. |
| Paired `4200` execution entry, `banked_source_software_call` | Same mapper write and named call; returns `undefined2` scalar `0x4300`. | Primary record matches the listed function, call, writes and return; screenshots not independently inspected. |
| Canonical `rom1::4500`, `banked_inline_source` | Writes bank `2`, calls `banked_destination(2)`, returns `undefined *` value `&DAT_rom1__4506`. | Primary record matches the listed function, call, writes and return; screenshots not independently inspected. |
| Paired `4500` execution entry, `banked_inline_source_software_call` | Same mapper write and named call; returns `undefined2` scalar `0x4506`. | Primary record matches the listed function, call, writes and return; screenshots not independently inspected. |
| Canonical `rom1::4800`, `constant_banked_source` | Writes `param_1`, calls `policy_target(3,0x48)`, writes bank `3`, assigns `DAT_c103 = 3`, returns `undefined *` value `&DAT_rom1__4400`. | Primary record matches the listed function, call, writes and return; screenshots not independently inspected. |
| Paired `4800` execution entry, `constant_banked_source_software_call` | Same mapper writes, named call and `DAT_c103` assignment; returns `undefined2` scalar `0x4400`. | Primary record matches the listed function, call, writes and return; screenshots not independently inspected. |

The canonical and execution-view C are **not textually or type-identically
equal**. In particular, `&DAT_rom1__4300` must not be described as proof that the
physical CALL goes to bank 1. It is the canonical native return expression.
The retained script checks the actual high-pcode CALL endpoint separately:
file `0x8300` (ROM bank 2, CPU `0x4300`) for canonical `4200`/`4500`, and file
`0x8400` (ROM bank 2, CPU `0x4400`) for canonical/alias `4800`.

The retained `banked_source` alias path checks its named call, saved registry and
physical continuation mapping; the inline alias path additionally checks ordered
payload banks `[1, 2, 2]`. Those assertions differ from `verifyNative`'s explicit
high-pcode endpoint check. A GUI symbol label by itself cannot replace either
kind of evidence.

## Physical target and diagnostic limits

The primary record identifies `banked_destination` at `rom2::4300`, displaying
`RET`, and `policy_target` at `rom2::4400`, displaying `LD A,0x5b; SCF; RET`.
The retained driver expects those physical addresses. Independently read fixture
bytes at file `0x8300` are `c9`; at file `0x8400` they are `3e 5b 37 c9`, matching
that instruction transcription. This does not turn the reported Listing
navigation into independent visual observation.

All six retained C files contain the expected software-call and may-return
injection warning comments. The three canonical files additionally contain
`Removing unreachable block (ram,0x4200)`, `(ram,0x4500)` or `(ram,0x4800)`.
These comments must remain visible in evidence accounting: a completed
decompile is not a warning-free result. None of the six retained files contains
an unresolved-software-call, bad-instruction, truncation or unimplemented
diagnostic. The retained [GUI application log](gui-window/application.log)
contains 25 lines and zero `WARN`, `ERROR` or `Exception` matches. This independently
checks the supplied log snapshot; it is not a claim about unrecorded later logs.

## Reopen and runtime record review

The primary record reports closing CodeBrowser with Save Program disabled, then
reopening the same saved Program through the project tree and rechecking
canonical `4200` and alias `4800`. Their visible code and Listing identities
reportedly match the first observations. This is a bounded GUI close/reopen
check of two entries, not evidence of a new GUI edit/save round trip or all six
entries rechecked after reopen. Separate installed lifecycle evidence owns the
actual saved mutation/removal qualification.

The retained wrapper configuration starts stock `ghidra.Ghidra` with
`ghidra.GhidraRun`, the disposable project and isolated profile. Its classpath
points into installed campaign 7. [identity.json](gui-window/identity.json)
records the same package, provider JAR and native companion hashes as the
qualified campaign. The primary owns verification that its recorded PIDs were
the live processes driving the windows.

[runtime-comparison.json](gui-window/runtime-comparison.json) records exact
Java `release` and `lib/modules` matches, while jpackage's signed native libraries
have different raw hashes. Stripped diagnostic copies of `libjava` and `libjli`
match. `libjvm` remains different after stripping; the separate
[section comparison](gui-window/libjvm-section-comparison.json) records equal
length/hash for all 16 reported sections and the residual byte interval
`[1801,1803)`, identified by the primary as `__LINKEDIT` vmsize. The records do
not justify calling the bundled runtime byte-identical to the original JDK or
all native-library differences signature-only. This reviewer inspected the
comparison records but did not independently regenerate the Mach-O analysis.

## Artifact identities

SHA256, computed directly from the retained files:

| File | SHA256 |
| --- | --- |
| `native-banked-canonical.c` | `6acb313c56f2a8f40f397da4455b6d8be6e256118db96af093430ee5f827e7a5` |
| `native-banked.c` | `228da106a77c549f9dc9b879a520e35a80a6054a74d33d04b64cc478276975f0` |
| `native-inline-canonical.c` | `c605c05b37430cd40ffead835a40a621177eae412c76258f737847a4c8296c7a` |
| `native-banked-inline.c` | `26b1be95570f1b7437d1c22aa39410b057090b53e44e91697b32632aea90fb19` |
| `native-policy-canonical-18432.c` | `469d6c0151fb1a7c774b518e49e3a838cf4c485e25fe1f9797de16cc38c1b7d4` |
| `native-policy-alias-18432.c` | `976044ea8c35679a6faeb867e61eb7315340399fb6ee2c3fc8979ca5b0aa743f` |

Reviewed primary evidence snapshot SHA256:

- `observations.json`: `47d435894f8c1d56bf68122e48534f988de46b702e4bce3a5ed8edf80127b9f8`.
- `identity.json`: `0e537d2e1204eaebf3b0f425e96ae9ab8196b1e7a3559d7a4564c45a06ab832b`.
- `application.log`: `816ccf1771b04e6be2e3280e7673dd15e2ffae0aabbc32d8704e5ab6ab849dab`.

## Conclusion

All six primary-recorded visible functions, calls, writes, return expressions
and warning categories match their retained native baseline. The recorded
physical target instructions match the retained fixture bytes. The canonical/alias
return distinction must not be erased when comparing GUI output.
This review is an independent artifact comparison with an explicit screenshot
access limitation. It does not establish GUI PASS or completion of SA-01/SA-02.
General same-CPU/different-bank paths, later continuation effects and genuinely
fresh missing-instruction discovery remain outside these finite observations.
