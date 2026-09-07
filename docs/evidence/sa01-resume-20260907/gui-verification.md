# Normal Decompiler-window check: finite cases verified

## Earlier blocked attempts (retained)

The authorized disposable GUI was launched only after verifying no other Ghidra
GUI process. Initial PID 57733 was observed running JDK21.0.12.1 from the exact installed
campaign5 copy with package SHA2560bbea54f5c497c3c586d55987e001dcdb61a8bdc1b06546ec1c9cdeb3d4719e3.
All 55 extension members match. GUI profile:
`/private/tmp/ghidraboy-sa01-resume-gui-profile`.
Disconnected repaired Program copy:
`/private/tmp/ghidraboy-sa01-resume-run-5/gui-projects/sa01-production.gpr`,
Program `production-mbc3-v2.gb`. Headless campaigns used a separate project path.

CUA initially inventoried no Ghidra GUI. After launch it reported:
“The Mac is locked and automatic unlock could not unlock it.” A manual-unlock
request was sent to the user. No UI content or Decompiler window was observed,
so this check is blocked, not passed. That initial process had exited before the final attempt. Final PID 59041 was
observed using installation 7 and profile
`/private/tmp/ghidraboy-sa01-resume-gui-profile-final` with disconnected
`/private/tmp/ghidraboy-sa01-resume-run-7/gui-projects/sa01-production.gpr`.
Final archive is a18bc013d93c2815d4e929e814e9ec18248eb357c7c185f060ac1ffbed5cdd98;
its 55 installed members match. CUA again reported the Mac locked.
Reverify process/installation identity or relaunch before resuming;
do not assume this PID or temporary environment still exists later.

After unlock, use normal CodeBrowser/Decompiler navigation on canonical
`banked_source` rom1::4200 and its paired execution function, then
`banked_inline_source` rom1::4500 and `constant_banked_source` rom1::4800 with
aliases. Compare physical target and actual continuation/output against retained
installed C. Record normal-window observations and any diagnostics; headless
success and successful GUI launch are not substitutes.

## Resumed normal-window verification

After the desktop was unlocked, the bare Java process could not be selected by
CUA. A fresh, disposable JDK `jpackage` app wrapper made the stock Ghidra launcher
selectable as `fi.gekkio.ghidraboy.sa01.window`. It launches `ghidra.Ghidra` /
`ghidra.GhidraRun` with the absolute Utility.jar from the verified installation;
it does not substitute a custom CodeBrowser, callback, or decompile script.
The user explicitly approved accepting the first-run Ghidra User Agreement.

The primary observed normal Decompiler windows after double-clicking these entries
in CodeBrowser's Symbol Tree:

| Canonical entry | Execution entry | Observed return expressions |
| --- | --- | --- |
| rom1::4200 / banked_source | gb_call_view_291_4200_1::4200 | canonical &DAT_rom1__4300; alias 0x4300 |
| rom1::4500 / banked_inline_source | gb_call_view_291_4500_1::4500 | canonical &DAT_rom1__4506; alias 0x4506 |
| rom1::4800 / constant_banked_source | gb_call_view_291_4800_1::4800 | canonical &DAT_rom1__4400; alias 0x4400 |

All six visible calls, selector writes, return expressions and diagnostic categories
match retained installed C. The constant-bank pair also displays selector write3
and DAT_c103=3. Normal Listing navigation confirms banked_destination at rom2::4300
(RET) and policy_target at rom2::4400 (LD A,5b; SCF; RET). Alias Listing comments
show the shared physical source ranges, including bank3 continuation4803 for the
constant-bank case. Canonical listing shows the reviewed CALL_RETURN/no-fallthrough
representation; original bytes remain visible.

The original injection-replacement comments and canonical unreachable-block comments
remain visible. No missing-site injection, missing-address, bad-instruction or
truncated-control-flow failure appeared. The captured application log has no
WARN/ERROR/Exception. Pointer-labelled canonical returns and scalar alias returns
remain different native inference presentations, not a new proof of bank-sensitive
pointer identity.

CodeBrowser was closed with Save Program disabled, then the same saved Program
was reopened through the project tree. Canonical4200 and alias4800 were rechecked
and displayed the same code. This is a saved-Program reopen check, not a new GUI
edit/save or mutation/reapplication campaign. The existing installed campaign
separately covers those operations. The disposable GUI remains open at canonical4200
for review; reverify identity before any later interaction.

Evidence: [observations](gui-window/observations.json),
[exact session/runtime identity](gui-window/identity.json),
[application log](gui-window/application.log), and
[independent comparison with retained artifacts](independent-gui-review.md).
CUA screenshots are retained inline in this task conversation; no separate PNG or
full-C export is claimed. The independent reviewer could inspect the recorded
observations, artifacts and log, but did not receive the screenshots.

Jpackage re-signs copied JDK native libraries. Release and Java modules match the
pinned JDK21.0.12.1. Runtime hashes and comparisons are retained: libjava/libjli match
after removing signatures from diagnostic copies; all libjvm sections match, with
one remaining stripped-file difference in __LINKEDIT virtual size. The GUI runtime
is recorded explicitly rather than called byte-identical to the original JDK.
The actual child native decompiler and all55 installed extension members match the
qualified artifact. No active installation or private original was modified.

This closes the normal Decompiler-window comparison for these finite fixtures.
SA-01/SA-02 remain incomplete; the broader original requirements are not waived.
