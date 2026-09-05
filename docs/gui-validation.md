# Installed GUI acceptance checklist

Status at dev3 packaging on 2026-09-05: **not yet accepted**. The user has
confirmed the other agent is no longer running and authorized GUI testing on this
desktop. Before interaction, verify a single Ghidra GUI process, its 12.1.3 install
path, and every installed extension member against the exact dev3 ZIP. A renamed
Java wrapper alone is not identity evidence. Use a disposable profile and project.

Final observed workflows, screenshots, artifact SHA256 and any remaining blockers
belong in `docs/evidence/` and the generated validation receipts (excluded from ZIP
packaging to avoid a self-referential artifact hash). The checklist below records
requirements, not a PASS inferred from startup or headless scripts. Prior dev2
attempts were blocked by shared `net.java.openjdk.java` targeting of the other
agent's 12.1.2 instance; that instance must never be selected or terminated.

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
