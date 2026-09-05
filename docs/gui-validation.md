# Installed GUI acceptance checklist

Status on 2026-09-05: **BLOCKED — not accepted**. A disposable 12.1.3 profile
started successfully after the user allowed the native `decompile` helper.
Computer use resolves Java windows through `net.java.openjdk.java` and selected a
concurrent 12.1.2 instance used by another agent. A retained foreground process,
distinct dock name and unique `.app` wrapper did not yield a separately selectable
app. The other instance and its project must not be used for these tests.

Next action: when the other GUI session is finished, rerun with an isolated 12.1.3
profile, or use computer control that can select a specific process ID. Record the
actual operated dialogs and screenshots. Headless installed script compilation,
execution and database persistence are separate passing gates.

Use only self-authored synthetic inputs and a disposable project. Install the
current ZIP cleanly (remove the previous extension first). Record its hash,
Ghidra/JDK versions, platform, project location and each observed outcome:

| Interactive check | Required observation | Current status |
| --- | --- | --- |
| Install and restart | One SM83 extension, expected dev version | Unverified |
| Automatic import | Game Boy recognition, options/warnings, successful load | Unverified |
| Manual import | CARTRIDGE/SALVAGE/DMG_BOOT/CGB_BOOT choices; hardware selection | Unverified |
| Cancellation | Cancel file/mode/preview dialogs; no partial Program or additions | Unverified |
| Script discovery | All three public scripts visible in Game Boy category | Unverified |
| Navigation | File/physical/CPU navigation; multiple-view chooser works | Unverified |
| Symbols | Preview filters, local parents, boundary choice; import two source claims | Unverified |
| Source lifecycle | List, reload changed source, remove in both orders; user edits retained | Unverified |
| Analysis lifecycle | Preview/save/apply/remove/reapply; candidates visible on incomplete run | Unverified |
| Stale analysis | Patch code; old preview/discovery rejected; new preview accepted | Unverified |
| Far-call convention | Valid fixed caller preview/apply/remove; switchable caller rejected | Unverified |
| Per-function ABI | Preview storage, apply to selected function; other functions unchanged | Unverified |
| Hardware/manual | Register descriptions/masks; native processor manual opens local index | Unverified |
| Export/repair | New destinations, SHA256 shown, explicit repair; original remains intact | Unverified |
| Legacy enhancement | Known hardware retained, explicit RAM identification; annotations unchanged | Unverified |
| Save/close/reopen | Sources, ownership, mapping and annotations persist; safe removal works | Unverified |

A passing receipt for `--gui-evidence` must identify the artifact and retain
observations for these checks. Merely starting Ghidra or seeing its menu does not
pass this gate. Do not replace this list with a generic PASS from headless tests.
