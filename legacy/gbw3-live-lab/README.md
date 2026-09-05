# Game Boy Wars 3: live Python lab

This is the expanded lab for **the ROM inside your uploaded Ghidra project**. It launches its own PyBoy emulator and connects live game behavior to the addresses in your Ghidra study guide.

You can inspect units, read any physical WRAM bank, search for changing bytes, compare snapshots, record combat execution, trace confirmed HP/ammunition/experience writes, and save a checkpoint to repeat an experiment.

## Install and start

Use Python **3.10–3.12**; testing here used Python 3.12 and PyBoy 2.7.0. Extract this folder, open a terminal inside it, and create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, use `py -3 -m venv .venv`, then `.venv\Scripts\Activate.ps1` in PowerShell. The commands below work once that environment is active. Use quoted paths when filenames contain spaces.

Point the lab at **the same .gbc file you imported into Ghidra**:

```bash
python gbw3_lab.py "your-student-rom.gbc" inspect
python gbw3_lab.py "your-student-rom.gbc" shell --window SDL2
```

The game starts paused. At the `gbw3>` prompt:

```text
play
```

Click the game window to play. Arrow keys move; the keyboard **A** key is the Game Boy A button, **S** is B, Enter is Start, and Backspace is Select. Return to the terminal and press **Ctrl+C** to stop advancing the game and inspect it. `play 600` instead runs for about ten seconds.

The window processes input while frames run. While waiting for a terminal command it may appear unresponsive; `play`, `run` or `step` resumes processing. Use this lab's checkpoint commands instead of PyBoy's built-in Z/X state hotkeys. Avoid PyBoy's separate P pause toggle; if used, toggle it again to resume.

For a terminal-only session, omit `--window SDL2`:

```text
run 900
press start
run 120
screenshot title.png
help
```

`press a 3` holds A for three frames, then releases it and advances one additional frame. Commands are case-sensitive except button names.

## Get the exact ROM from Ghidra if needed

The supported SHA-256 fingerprint is:

```text
e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451
```

The earlier standalone ROM has a different fingerprint. This lab deliberately rejects it. The embedded AG RCKT armored-target rating, for example, is 18 here rather than 20 in the earlier upload.

If you only have the `.gzf`, import/open it in Ghidra, then use the included **ExportGBW3ROM.java**:

1. Open **Window → Script Manager** in CodeBrowser.
2. Add this extracted folder to the script search directories and refresh.
3. Run `ExportGBW3ROM.java` with your program open.
4. Choose a **new** filename ending in `.gbc`.

The exporter reads the 64 mapped ROM banks, verifies the fingerprint and writes the file. It preserves the Ghidra program and refuses to overwrite an existing output. It was tested against the actual uploaded GZF with Ghidra 11.3.1 and GhidraBoy. The Python lab does not parse GZF databases itself.

## First experiment: identify one unit

Navigate to an active battle, then pause in the terminal:

```text
units
unit 3
where unit_address
peek wram3::d030 16
```

Replace slot 3 with a unit actually shown by `units`. The table displays side, name, coordinates, HP, fuel, both ammunition counts and experience. `unit` also gives each field's byte offset and exact Ghidra address.

A unit at slot 3 starts at `wram3::d030`; its HP is at `wram3::d034`. Compare this with the pointer calculation at **`rom18::4029`** in Ghidra. Static templates are separately accessible:

```text
template 1
weapon 2
```

These show the Grunt template and rifle definition. Template maxima live in ROM; a damaged unit's current values live in RAM.

Outside an active battle, unit RAM can be empty, stale or used by other game states. `units` excludes packed-type-zero slots; `units all` shows all 100. An “implausible” marker is a basic sanity check, not a battle-state detector. Unknown fields and partially decoded flags remain explicitly named as such.

## Capture a before/after change

With a unit selected in the game:

```text
save-state before-attack.gbwstate
snapshot before.json
trace on
watch wram3::d034 1
play
```

Perform one attack, then return to the terminal and press Ctrl+C:

```text
snapshot after.json
diff before.json after.json
events 20
trace save attack-trace.jsonl
```

`diff` reports which unit fields changed and the first 50 changed raw WRAM bytes. Snapshots contain all eight WRAM banks, so the original files preserve every changed byte even when the terminal display is shortened.

To repeat the experiment:

```text
load-state before-attack.gbwstate
watch wram3::d034 1
play
```

Loading a checkpoint clears memory-watch and scan baselines. Trace events remain, with an explicit `state_loaded` event separating timelines. Use `events clear` for a fresh recording. Checkpoint saves require a new filename so a later trial cannot replace your original checkpoint by accident.

The emulator never automatically writes back to your ROM or cartridge save. Checkpoints include cartridge RAM. To begin from an existing **raw 128 KiB battery save**, pass `--ram /path/to/save.ram`; this reads it into the emulator without overwriting it. Other emulators' savestates cannot be loaded. `.gbwstate` is this lab's metadata plus a PyBoy 2.7.0 savestate.

## Three different kinds of evidence

| Tool | What it observes | What it cannot establish |
|---|---|---|
| `watch ADDRESS LENGTH` | Differences between frame-end samples | Writes that change back within one frame; the instruction that wrote them |
| `trace on` | Instruction hooks at identified combat branches and confirmed unit-writer stores | Every memory write in the game, or proof that a calculation was a committed battle |
| `until order 600` | Exact registers and combat scratch when the named instruction is reached | A CPU paused at that instruction: execution finishes the current frame |

**`step` advances frames, not individual CPU instructions.** Use Ghidra for static instruction analysis, and a full emulator debugger such as [SameBoy](https://sameboy.github.io/debugger/) when you need CPU single stepping or arbitrary write watchpoints.

PyBoy's supported APIs provide frame execution, register access, banked memory and execution hooks. The lab uses those rather than private emulator internals. Hooks instrument only known instruction boundaries and are removed when tracing is disabled. [PyBoy API documentation](https://docs.pyboy.dk/)

## Read a write trace

A confirmed write event contains information like this:

```json
{
  "kind": "unit_write",
  "address": "wram3::d004",
  "slot": 0,
  "field": "hp",
  "before": [10],
  "after": [7],
  "confirmed": true,
  "registers_before": {
    "executed_hook": "rom18::40b5",
    "B": 7,
    "HL": 53252,
    "wram_bank": 3
  },
  "caller": {
    "verified_far_call_site": "rom12::4bac"
  }
}
```

This shortened example was exercised by an isolated integration test. It is not a recorded real-map battle.

At `rom18::40b5`, the instruction is `LD (HL),B`. `53252` decimal is `D004` hexadecimal. The hook before the store records the old value and registers; the hook afterward confirms the value actually written. Word writes at `rom18::40d0`–`40d2` are captured together, including the two bytes of experience.

A `verified_far_call_site` appears only when the known dispatcher stack layout and the original ROM bytes both match. Follow that address in Ghidra to see where the write originated. Otherwise the event reports only the immediate CPU return address. This is not a general call-stack unwinder.

Only writes through the identified byte/word helpers are covered. Direct stores elsewhere can still appear in frame watches or snapshot diffs without a corresponding `unit_write` event.

The event buffer holds the latest **10,000** entries. Exported JSONL begins with the ROM fingerprint and dropped-event count. Clear or export it between experiments. Tracing can slow emulation, and combat calculations may also be used by previews or AI; corroborate them with actual HP/ammunition writes.

## Explore combat execution

```text
points
trace on
until order 600
combat
events 10
```

`until` requires the game to reach that point within its frame budget. Set up an action first; it does not make a battle happen automatically. Use `play` with tracing to perform actions interactively, or `press a` and `until` when the game is waiting for an attack confirmation.

Useful points:

| Name | Ghidra address | Meaning |
|---|---|---|
| `attack` | `rom12::43cf` | Ordinary attack routine entry |
| `order` | `rom12::4b0a` | Compare initiative bands |
| `attacker_first` | `rom12::4b18` | Attacker-first path |
| `defender_first` | `rom12::4b35` | Defender-first path |
| `simultaneous` | `rom12::4b52` | Both results use original working HP |
| `commit` | `rom12::4b67` | Combat commit routine entry |
| `initiative` | `rom12::484a` | Small initiative-grouping function |

An `until` hit stores registers and scratch values from the hook. A later `regs` or `combat` command reads the state **after the frame finished**, which can differ. Scratch RAM also remains populated after combat ends; reading it alone does not prove a battle is in progress.

## Discover an unknown byte by observation

Start broad, then filter after a meaningful in-game action:

```text
scan start wram3 10
play
scan decreased
```

This finds bytes that were 10 and decreased since the last scan. If you damaged a 10-HP unit, its HP byte should be among the candidates. Filter again after another observation:

```text
play
scan same
scan value 7
```

Every filter updates the baseline and retains only matching candidates. Values are unsigned bytes; “increased/decreased” compares numeric values and does not account for wraparound. This is a hypothesis-building tool, not an automatic field identifier. Coordinate bytes, counters and unrelated data can match too.

## Read memory and translate addresses

```text
peek wram3::d000 64
peek wram4::dbc8 48
peek vram0::8000 32
peek xram0::a000 32
peek ff90 9
where rom18::4029
where order
regs
```

Addresses are hexadecimal. Bank suffixes, slots, lengths and values are decimal unless prefixed with `0x`. `rom18::4029` becomes emulator bank notation `12:4029`, with file offset `048029`. This explicitly handles the decimal-overlay versus hexadecimal-bank trap.

`peek` with an explicit ROM overlay reads the original uninstrumented ROM. A raw CPU-space ROM read may show temporary PyBoy hook opcodes while tracing. Physical RAM-bank inspection does **not** switch the game's active WRAM bank.

`regs` reports the actual WRAM selector from FF70. `rom_bank_shadow` reads the game's FF80 bookkeeping byte because the pinned public PyBoy API does not expose the MBC's current ROM selector directly. Consequently, `pc_ghidra_hint` is a hint. An event's `executed_hook` has the bank established by the registered hook. SRAM bank addresses are physical banks; the uploaded Ghidra project contains one generic xram block, not 16 matching xram overlays.

## Run the self-contained teaching demo

```bash
python gbw3_lab.py "your-student-rom.gbc" demo --out demo-output
```

This executes three experiments using the **actual ROM calculation routines**, with synthetic HP/attack/defense inputs. It produces before/after snapshots, decoded differences, and confirmed write events:

| Firing order | Final attacker HP | Final defender HP |
|---|---:|---:|
| Equal initiative | 5 | 5 |
| Attacker first | 8 | 5 |
| Defender first | 5 | 8 |

Both sides begin at 10 HP, attack rating 10, defense rating 10 and zero modifiers. The test driver applies the calculated results through the game's unit writer. It does not execute a complete map battle, weapon selection or the full combat commit routine. The visualized unit records are synthetic Grunt records; these imposed ratings are not the Grunt/rifle's normal matchup statistics.

Open `demo-output/events.jsonl` beside Ghidra's `ResolveCombatOrder` function. Find the branch event, then the two HP writes. Explain why first strike leaves the faster side with eight HP.

A small output sample is included in `examples/verified-demo-summary.json` and `examples/verified-demo-events.jsonl`. Full snapshots are generated locally by the command above.

## Repeatable command files and Python use

Run terminal commands from a text file:

```bash
python gbw3_lab.py "your-student-rom.gbc" shell --commands examples/boot-and-inspect.txt
```

Blank lines and lines beginning with `#` are ignored. The first error stops a command-file run with a nonzero exit status. File paths in command scripts are relative to the shell's current directory.

For your own Python experiments:

```python
from pathlib import Path
from gbw3_lab import Lab, check_rom

lab = Lab(check_rom(Path("your-student-rom.gbc")))
try:
    lab.load_state("before-attack.gbwstate")
    before = lab.read("wram3::d000", 1600)
    lab.trace(True)
    lab.p.button_press("a")
    lab.advance(3)
    lab.p.button_release("a")
    lab.advance(120)
    print(lab.units())
    lab.save_events("experiment.jsonl")
finally:
    lab.close()
```

Keep emulator API calls on the main thread, particularly with SDL windows. The source deliberately keeps address parsing, unit decoding, snapshots, hook handling and terminal commands separate so you can study or extend one part at a time.

## Validation and files

```bash
python gbw3_lab.py "your-student-rom.gbc" verify
python test_lab.py "your-student-rom.gbc"
```

The first command checks 256 initiative inputs, 150 generated damage cases, eight modifier cases and three firing-order cases. The second runs 11 integration tests, including bank boundaries, exact byte/word writes, the verified far-call origin, snapshot diffs, scan filtering, frame watches, hook cleanup, checkpoint restore and wrong-ROM rejection.

The actual game was also booted and navigated with scripted input; checkpoint restore and screenshot capture were exercised. The SDL2 backend was smoke-tested with a dummy video driver, so interactive desktop focus/keyboard behavior was not manually validated here. See `validation.json` for the recorded scope.

| File | Purpose |
|---|---|
| `gbw3_lab.py` | Interactive lab, address handling, memory tools and tracing |
| `gbw3_core.py` | ROM table decoding, integer combat model and isolated execution harness |
| `test_lab.py` | Tests using your own matching ROM |
| `ExportGBW3ROM.java` | Read-only export from the supplied Ghidra program |
| `requirements.txt` | Pinned PyBoy dependency |
| `examples/` | Command-file starter and verified synthetic trace |
| `validation.json` | Test results and limitations |

For the first session: run the demo, inspect one real unit, capture one attack, and follow one confirmed HP write back into Ghidra.
