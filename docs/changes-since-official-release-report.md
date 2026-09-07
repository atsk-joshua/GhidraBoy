**GhidraBoy: What we’ve improved since the last official release**

Updated September 7, 2026; historical validation remains attributed to its original campaign

GhidraBoy helps Ghidra turn a Game Boy game’s machine code into something a person can study. Our changes make that translation more accurate, help follow code through a cartridge’s memory banks, and add tools for organizing discoveries while protecting the work already done.

This report compares locally recorded upstream release **20250830**, commit
`42032f9d97e9e502dc10a14743bdb3d1b9388588`, with integrated HEAD
`16752093dce0147afd28762a2f8918144ec571c2` and the reviewed cleanup working tree.
The local release commit's message is `Release: 20250830`, dated August 30, 2025;
it is an ancestor of HEAD. This is a local Git comparison, not a new download or
remote release verification. The earlier report stopped at `b30c925` before the
integrated debugger. Current builds require **Ghidra 12.1.3 / JDK 21**. These
additions remain a development preview.

1. **More accurate Game Boy CPU behavior**

   We fixed errors in how GhidraBoy models addition and subtraction with carry, including the little status flags that tell the program whether a calculation produced zero or overflowed. We also rewrote DAA, the instruction used to adjust decimal arithmetic, into operations Ghidra can directly understand.

   Stack operations now handle byte ordering and the edge where the address space wraps from `FFFF` back to `0000`. Restoring the CPU’s flag register also clears the bits that should be unused.

   **Why it matters:** a wrong flag can make Ghidra misunderstand which branch a game takes. These fixes give analysis and decompilation a more accurate foundation. [CPU changes and validation](cpu-validation.md)

2. **A much better model of banked cartridges**

   Larger games contain more data than the Game Boy can address at once. A cartridge’s mapper switches which bank is visible—like changing which page of a book is open.

   The old release could already load banked games. We added explicit models for ordinary ROM-only, MBC1, MBC2, MBC3, and MBC5 cartridges, including mapper-specific RAM behavior, bank-zero cases, and Game Boy Color memory-bank selections. New navigation tools connect a location in the ROM file with its physical bank and its CPU address.

   **Why it matters:** the same CPU address can refer to different game code in different banks. These tools make that relationship easier to inspect and reason about. Unusual cartridge wiring remains explicitly unsupported. [Cartridge support](input-policy.md)

3. **New tools for following code across banks**

   GhidraBoy can now examine already-defined instructions, track known bank selections, and propose references to the code or data they reach. Function discovery uses existing entry points and proven calls. There is also optional support for one precisely checked MBC3 cross-bank calling pattern.

   The analysis records its assumptions and whether it finished. If it runs out of information or stops early, it keeps possible answers without presenting them as proven. Changes to relevant code or mappings invalidate saved results.

   **Why it matters:** more of the navigation work can be assisted, and uncertainty stays visible. General runtime bank switching and arbitrary cross-bank calls are still outside its scope. [Analysis behavior](analysis.md)

4. **Stronger protection for your discoveries**

   Analysis now has preview, apply, remove, and reapply workflows. GhidraBoy keeps a record of the references, bookmarks, functions, and supported overrides it adds. Removal checks that those objects still match what it created.

   User edits receive special protection: functions with local variables, meaningful types, comments, or other changes are conservatively retained when ownership is uncertain. Tests also exercise cancellation and saving, closing, and reopening a project.

   **Why it matters:** you can refine the analysis while preserving the names, notes, and function details you have worked out yourself. [Preservation rules](analysis.md)

5. **Better names and hardware explanations**

   We added RGBDS `.sym` support, so names from a game’s development files or a reverse-engineering project can be imported, previewed, reloaded, removed, and exported. The tools handle Unicode names, local labels, and ambiguous boundary markers. If two symbol files claim the same label, removing one source preserves the other’s claim.

   Hardware information now includes sourced register descriptions and bit-mask definitions, plus a bundled processor reference index.

   **Why it matters:** meaningful names and explanations help turn a screen of addresses into code you can understand. [Symbol and hardware workflows](user-workflows.md)

6. **Better support for games written in C**

   We added verified profiles for selected older and newer SDCC/GBDK compiler conventions. These describe where a function receives its arguments, where it returns its answer, and how it cleans up the stack. They can be applied to individual functions, including functions with different conventions in the same project.

   **Why it matters:** Ghidra can produce more useful function signatures when these details are supplied correctly. The profiles were checked against real compiler output, but they still require deliberate selection and do not cover every compiler or calling pattern. [Compiler support](compiler-support.md)

7. **Safer ROM import, export, and sharing of project knowledge**

   Strict import checks cartridge geometry. An explicit salvage mode preserves incomplete or unusual files, including extra bytes, without silently padding or truncating them. Export can produce the original ROM, a version containing supported edits, or a separate copy with repaired checksums.

   The latest addition exports project knowledge—memory blocks, symbols, function signatures, structures, and comments—to JSON for use by related tools. It reads the project without modifying it and requires a new output file.

   **Why it matters:** original bytes remain available, and discoveries can be carried into other workflows. The integrated debugger now consumes this general knowledge contract. It is an inventory and interchange format, not a complete Program backup. [ROM workflows](user-workflows.md), [knowledge exporter](../src/main/java/fi/gekkio/ghidraboy/ProgramKnowledge.java)

8. **Much stronger testing and upgrade checks**

   We modernized the build for Ghidra 12.1.3 while retaining the language identity, register layout, default compiler identity, and 16-bit pointers used by existing projects. Java 21 was already required by the official release and remains the target.

   The retained dev3 validation records **428 tests passing with no failures, errors, or skipped tests**, plus **21,000 external CPU test cases across 21 selected instruction files**. Separate exhaustive checks cover many arithmetic and bit-operation inputs. Installed-package checks exercise persistence, and a migration test upgrades and reanalyzes a copied Ghidra 11.3.1 project while verifying that the original remains unchanged. Two clean package builds produced identical hashes.

   Those results belong to the recorded dev3 validation commit `b4d3b60`, before the latest knowledge-export addition. This report reviews the saved evidence; it does not claim a fresh test run of the current checkout. The external cases cover selected instruction files, not every possible CPU behavior. [Recorded validation](evidence/dev3/README.md)

9. **An integrated live debugger**

   The optional `debugger/` module now brings SameBoy execution, physical-bank
   breakpoints, captured event history, checkpoints and trace workflows into the
   same repository. An experimental mGBA adapter has a smaller capability set.
   Game-specific consumers remain external to the generic runtime.
   Read the [debugger support contract](../debugger/docs/SUPPORT.md) for exact
   capabilities and limits. The installed `GhiGBC` extension ID, `ghigbc` Python
   and Java namespaces, launcher/schema identities and old saved-work readers
   are retained; renaming them would affect installation and persistence surfaces.

10. **Clearer source and package ownership**

   One maintained `ghidra_scripts/ExportGbcKnowledge.java` preserves the callable
   script name; the duplicate debugger source is removed, and packaging copies
   a regular file to the historical packaged script path. Static `src/`, `data/`, `ghidra_scripts/` and the root Gradle
   build retain the familiar upstream layout. Generic regressions stay here;
   exact-game conventions and annotated corpus evidence remain outside this repository.

**Remaining limits:** interactive GUI defects and acceptance gates remain open.
General arbitrary runtime bank effects, asymmetric indirect cartridge accesses
and complete hardware/interrupt semantics are not established by the static
analysis checks. Integration adds live execution; it does not prove complete
semantic decompilation of a game. Saved-Program compatibility retains inherited
language/compiler/register identities and existing migration tests; it does not
mean the current build runs on older Ghidra runtimes. See [validation suites and
qualification scope](validation.md). No new migration or GUI campaign was run
for this cleanup.
