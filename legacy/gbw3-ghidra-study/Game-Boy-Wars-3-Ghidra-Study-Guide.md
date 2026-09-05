# Give your Game Boy Wars 3 project meaning

This walkthrough is tailored to your uploaded **Game Boy Wars 3.gbc.gzf**, opened with Ghidra 11.3.1 and GhidraBoy. Your SM83 processor selection and banked memory layout are already in place. Your controller labels and WRAM bank-save helpers provide useful starting points.

The goal is to turn each discovery into three things: a name that explains its purpose, a comment explaining the evidence, and a connection to something you can observe in the game. The suggested names below are our descriptive names, not recovered developer symbols.

## First, understand the address names

Press **G** in the Listing to open Go To and enter the full address, such as `rom18::4029`. If address entry is ambiguous, select the named memory block in the Program Tree and navigate within it.

| Address in your project | Meaning |
|---|---|
| `rom18::4029` | ROM bank **18 decimal**, CPU address **4029 hexadecimal** |
| `rom12::484a` | ROM bank **12 decimal**, CPU address **484A hexadecimal** |
| `wram3::d000` | Work RAM bank 3, CPU address D000 |
| `wram4::dbd3` | Work RAM bank 4, CPU address DBD3 |
| `04d2` | Address in the default, unbanked space |

**A trap when using the earlier ROM notes:** hexadecimal bank `12:4029` corresponds to **`rom18::4029`**, while hexadecimal `0C:484A` corresponds to **`rom12::484a`**. The numbers after the double colon remain hexadecimal.

The CPU can see only the currently selected bank at a given banked address. Ghidra uses overlays to show all the alternatives. Consequently, an operand containing `D000` or `4037` does not, on its own, tell Ghidra which overlay to use. GhidraBoy documents both this limitation and imperfect register-parameter inference. Keep the assembly Listing alongside the decompiler. [GhidraBoy documentation](https://github.com/Gekkio/GhidraBoy)

## 1. Improve two discoveries you already made

At **`036f`**, your label currently says `JP[0x03ec]_at_0xc005:c007`. Follow its call to `0360`: that function loads **DE = C008** and writes three bytes there. The destination in the label should be **C008–C00A**.

Suggested names:

| Address | Suggested name | Evidence |
|---|---|---|
| `0360` | `SetVBlankJumpTarget` | Writes opcode C3, then L and H, at C008–C00A |
| `036f` | `InstallDefaultVBlankHandler` | Supplies HL=03EC to that writer |
| `c008` | `VBlankJumpStub` | Interrupt vector 0040 jumps here |
| `04d2` | `WaitForNextFrameIfLCDEnabled` | Tests the LCD shadow, then waits for FF8E to change |
| `ff8e` | `VBlankFrameCounter` | Incremented at 04C4 in the handler reached through the VBlank stub |

Your `checkBit7` name at `04d2` describes one instruction. The proposed name describes the whole routine. Trace the path: if C00F bit 7 is clear it returns; otherwise it saves FF8E, executes HALT, and loops while FF8E is unchanged.

**Question to answer:** Why is a RAM location holding the bytes `C3 EC 03` useful? It lets the game change where an interrupt goes by rewriting a small RAM jump stub. Those three bytes are an instruction, not a three-byte game statistic.

Your `set_SVBK_7_c100` and `set_SVBK_7_c101` labels at `rom3::5092` and `rom3::50a8` correctly identify save-and-switch helpers. Keep them. Their paired restore routines make good examples of preserving global machine state.

## 2. Discover what one live unit looks like

Go to **`rom18::4029`**. Rename the existing function to `GetUnitInstanceAddress` using the function's rename action.

The important instructions are:

```asm
LD L,A
LD H,0
ADD HL,HL
ADD HL,HL
ADD HL,HL
ADD HL,HL
LD DE,0xD000
ADD HL,DE
```

Each doubling multiplies by two. Four doublings multiply by sixteen:

```text
HL = 0xD000 + 16 * unit_slot
```

Add a function comment: `Input A: unit slot. Output HL: CPU address of 16-byte unit record. Preserves DE. Does not select WRAM bank; unit data lives in bank 3.`

Do not immediately force this into a normal C function signature. The input is in **A** and the result is in **HL**; an inferred stack argument or A return value would misdescribe it.

The live array is **`wram3::d000` through `wram3::d63f`**: 100 records, with two groups of 50. Give its start the label `UnitInstances`.

Create a `UnitInstance` structure in the Data Type Manager. Disable automatic alignment/packing changes and check that the total length is **0x10**. Enter these exact offsets; retain unknown bytes:

| Offset | Type/length | Suggested field |
|---|---|---|
| 00 | byte | `packed_type_and_side` |
| 01 | byte | `map_x` |
| 02 | byte | `map_y` |
| 03 | byte | `flags_partial` |
| 04 | byte | `hp` |
| 05–06 | byte[2] | `unknown_05` |
| 07 | byte | `fuel` |
| 08 | byte | `ammo_primary` |
| 09 | byte | `ammo_secondary` |
| 0A–0B | word | `experience` |
| 0C–0F | byte[4] | `unknown_0c` |

Apply it at `wram3::d000`, then make an array of 100 elements. Packed type zero marks an inactive slot; otherwise shifting it right once yields the template index, and its low bit distinguishes sides.

**Checkpoint:** slot 3 starts at D030 and its HP is D034. Slot 50 starts at D320. If your structure disagrees, fix the layout before continuing.

RAM appears uninitialized in this static project because it is filled while the game runs. Applying a structure describes its layout; it does not provide a saved battle's contents.

## 3. Separate a unit's template from its live state

A template says what a Grunt can normally do. An instance says where this particular Grunt is and how much HP and ammunition it currently has.

| Region | Contents | Suggested label |
|---|---|---|
| `rom18::4a43`–`rom18::4aac` | 53 little-endian words containing template CPU addresses | `UnitTemplateAddresses` |
| `rom18::4aad`–`rom18::5255` | 53 records, each 0x25 bytes | `UnitTemplates` |
| `rom18::4ad2` | Grunt template, index 1 | `GruntTemplate` |
| `rom18::5256`–`rom18::5297` | 33 weapon address words | `WeaponTemplateAddresses` |
| `rom18::5298`–`rom18::54a7` | 33 records, each 0x10 bytes | `WeaponTemplates` |

These counts include placeholder/special entries; they are not counts of ordinary buildable units and usable attack weapons.

At first define the address tables as **word arrays**. A two-byte CPU address does not encode a ROM bank. When adding references to their targets, explicitly select the `rom18` overlay instead of accepting a pointer into an unrelated space.

Create this packed **0x25-byte `UnitTemplate`**:

| Offset | Type/length | Suggested field |
|---|---|---|
| 00–09 | byte[10] | `name_glyphs` |
| 0A | byte | `max_hp` |
| 0B | byte | `max_fuel` |
| 0C | byte | `movement` |
| 0D–0F | byte[3] | `unknown_0d` |
| 10–11 | word | `funds_raw` |
| 12–13 | word | `materials_raw` |
| 14 | byte | `weapon_primary_id` |
| 15 | byte | `max_ammo_primary` |
| 16 | byte | `weapon_secondary_id` |
| 17 | byte | `max_ammo_secondary` |
| 18 | byte | `unit_class` |
| 19–1D | byte[5] | `unknown_19` |
| 1E–22 | byte[5] | `defense_by_attacker_class` |
| 23 | byte | `base_initiative` |
| 24 | byte | `initiative_step_cost` |

Apply an array of 53 at `rom18::4aad`. Name bytes use a custom glyph encoding: 80 is space, and 8B–A4 represent A–Z. Defining them as ordinary ASCII strings would be misleading.

**Checkpoint:** the Grunt has maximum HP 10, movement 3, primary weapon ID 2, and primary ammunition 9. Its template HP is at `rom18::4adc`; its live HP is at `wram3::d000 + 16*slot + 4`. These are different kinds of information.

For a packed **0x10-byte `WeaponTemplate`**, use `name_glyphs[8]`, `range_min`, `range_max`, `attack_by_target_class[5]`, and `unknown_0f`, in that order. The five attack entries correspond to armored land, soft land, air, ships and submarines. These class names are descriptive interpretations supported by the roster and lookup code.

**Question:** Why does the rifle at `rom18::52b8` contain attack values **2, 10, 2, 1, 0** instead of one damage number? Its effectiveness depends on the target class. Actual HP loss also depends on the combat calculations.

## 4. Turn unknown bytes into a small function

At **`rom18::4037`**, rename the existing function to `ReadUnitTemplateByte` and comment: `A = packed type; C = byte offset; returns selected byte in A; preserves BC and HL.`

Immediately afterward, **`rom18::4043`–`rom18::404e`** is undefined in your uploaded listing. Disassemble from 4043 and create a function there. Suggested name: `ReadUnitTemplateWord`.

It calls the byte reader twice. The first result goes into E, C is incremented, and the second result goes into D. Thus DE contains a little-endian word. Comment that **C increases by one** and **A finishes holding the high byte**. This exercise teaches both function discovery and register side effects.

## 5. Fix one custom call that stopped analysis

Go to **`rom12::47cc`**. The bytes are:

```text
Address           Bytes       Meaning
rom12::47cc       EF          RST 28h
rom12::47cd       12          ROM bank 0x12 = 18 decimal
rom12::47ce       37 40       Target CPU address 0x4037
rom12::47d0       EA D5 DB    LD (0xDBD5),A
```

The game uses the three bytes after RST as inline arguments to a cross-bank call. Your existing **`FUN_rst28` at `3b06`** is the dispatcher. At `3b16`, it adds three to the saved return address. It also reads the bank/address bytes and changes the ROM bank.

Make these annotations:

1. Keep EF as the real RST instruction. Define 47CD as a byte and 47CE–47CF as a word.
2. Comment the RST: `Far call to rom18::4037; three inline argument bytes; returns at rom12::47d0.`
3. Add an explicit data reference from the target word to **`rom18::4037`**, using the References action. Preserve the RST's real reference to its dispatcher.
4. Disassemble at **`rom12::47d0`**. The first instruction stores the returned value into DBD5.

This manual reference is a navigation aid; it does not teach the decompiler the entire custom calling convention. Repairing automatic flow and function bodies across every such call is a later project. Work on this one occurrence first.

**Checkpoint:** explain why treating `12 37 40` as three CPU instructions produces nonsense. Then identify the next far call at `rom12::47d6` yourself.

## 6. Explain initiative with one tiny routine

At **`rom12::484a`**, rename the function `GroupInitiative`.

Its behavior for an unsigned input byte A is:

```python
result = max(1, (A // 10) * 10)
```

It groups initiative into bands using repeated subtraction. Work through A=9, 10, 19 and 20; the results are **1, 10, 10 and 20**. A=0 also produces 1.

This is useful game knowledge: two different initiative values can belong to the same firing-order band. Do not equate every increase in raw initiative with a change in who fires first. Eligibility checks elsewhere still determine whether a side can fire.

## 7. Find the rule that makes first strike matter

Rename **`rom12::4b0a`** to `ResolveCombatOrder`. Open its Function Graph and label the branch destinations:

| Address | Suggested label | Behavior |
|---|---|---|
| `rom12::4b18` | `AttackerFiresFirst` | Update defender's working HP before calculating its return fire |
| `rom12::4b35` | `DefenderFiresFirst` | Update attacker's working HP before calculating its attack |
| `rom12::4b52` | `SimultaneousExchange` | Calculate both results before changing either working HP |

The first comparison loads attacker initiative from DBCF into B, loads defender initiative from DBE4 into A, and compares **defender against attacker**. Pay attention to this operand order when interpreting the carry flag.

At 4B52, find `PUSH AF` and `POP AF`. They preserve the first calculation's result while the second calculation still sees the original HP. That is how sequential CPU instructions implement simultaneous firing.

The two damage functions are **`rom12::4a26`** (`CalculateDefenderRemainingHP`) and **`rom12::4a98`** (`CalculateAttackerRemainingHP`). They return **remaining HP**, not damage dealt.

Label a few scratch bytes in **WRAM bank 4**:

| Attacker address | Defender address | Suggested field pair |
|---|---|---|
| `wram4::dbc8` | `wram4::dbc9` | `attacker_slot` / `defender_slot` |
| `wram4::dbcb` | `wram4::dbe0` | `attacker_original_hp` / `defender_original_hp` |
| `wram4::dbcc` | `wram4::dbe1` | `attacker_result_hp` / `defender_result_hp` |
| `wram4::dbcf` | `wram4::dbe4` | `attacker_initiative_band` / `defender_initiative_band` |
| `wram4::dbd3` | `wram4::dbe8` | `attacker_working_hp` / `defender_working_hp` |
| `wram4::dbd4` | `wram4::dbe9` | `attacker_attack_rating` / `defender_attack_rating` |
| `wram4::dbd5` | `wram4::dbea` | `attacker_defense_rating` / `defender_defense_rating` |

A label on an overlay may not automatically appear in an instruction whose reference targets the default space. Confirm that WRAM bank 4 is active and repair the reference to the correct overlay; do not create duplicate RAM blocks to hide the problem.

Here is an isolated teaching example verified by executing this project's ROM routines: both sides start with HP 10, attack rating 10, defense rating 10 and no modifiers.

| Initiative bands, attacker/defender | Final attacker HP | Final defender HP |
|---|---:|---:|
| 10 / 10 | 5 | 5 |
| 10 / 1 | 8 | 5 |
| 1 / 10 | 5 | 8 |

**Question:** Why does the faster side keep eight HP? Return fire uses the slower side's reduced strength. This is a synthetic routine test, not a claim about a particular unit matchup on a map.

## 8. Connect the calculation to the game on screen

Follow **`rom12::4b67`**, the combat commit routine, to calls into **`rom18::40a1`**, the live-unit byte writer. For HP writes, C is 4, A selects the unit slot, and B supplies the value.

With a Game Boy emulator debugger, make a save state before a simple attack. Inspect WRAM bank 3 and identify a unit using its coordinates and packed type. Watch writes to its `D000 + 16*slot + 4` address. Confirm the bank when the watchpoint fires: the same CPU address exists in several WRAM banks. Correlate the writing PC and current ROM bank with the matching Ghidra overlay.

Record one before/after HP change and trace it backward to the commit routine. Then compare primary ammunition at record offset 8. This closes the loop from a visible game event to an address, a structure field and a function.

For an emulator with a documented debugger, see [SameBoy's debugger documentation](https://sameboy.github.io/debugger/). These exercises do not require attaching Ghidra's native debugger to an emulator.

## Optional bookmark script

The accompanying `GBW3StudyBookmarks.java` adds 18 **GBW3 Study** bookmarks containing these exercise prompts. It leaves your names, comments, data types, functions and ROM bytes intact. Running it again does not duplicate the bookmarks or replace an existing bookmark in that category.

Unzip the study pack. In Ghidra's CodeBrowser, open **Window → Script Manager**, add the extracted script folder through the script-directory manager, refresh, select `GBW3StudyBookmarks.java`, and run it. Open **Window → Bookmarks** and filter for `GBW3 Study`.

The script checks the actual ROM bytes in all 64 mapped banks before adding anything. It is intended for the uploaded GZF; if it refuses a different ROM, use the guide to verify that version's addresses manually. Tested twice against an imported copy using Ghidra 11.3.1 with GhidraBoy.

For Ghidra's navigation, labels, structures and Function Graph controls, use its [official beginner guide](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html).

## What was verified, and what remains open

The uploaded project contains 79 memory blocks and 1,792 recognized functions. Its mapped ROM SHA-256 is:

```text
e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451
```

This differs from the earlier standalone ROM. The ordinary combat code and unit-template records discussed here match between the two, but not every byte does: for example, the AG RCKT weapon's armored-target attack field at `rom18::54a2` is **18** here and **20** in the earlier ROM. Do not transfer all extracted balance values indiscriminately. The earlier lab command checks the earlier ROM's fingerprint and will reject this one by design.

I re-ran isolated checks against the ROM embedded in this GZF: all 256 initiative inputs, 150 generated damage cases, eight modifier cases and three firing-order cases passed. This verifies those routines under the tested conditions; it is not a complete recovery of the game's AI, movement, terrain system or special attacks. Unknown structure fields above remain deliberately unnamed.

For a first session, finish exercises **1, 2 and 6**. You will have explained a frame wait, discovered the live unit layout, and recovered a combat arithmetic rule. Each is small enough to prove from the instructions in front of you.
