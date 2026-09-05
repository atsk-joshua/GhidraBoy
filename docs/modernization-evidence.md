# Modernization evidence — development preview

This is substantial working software, but **not completion of every requested
modernization requirement**. Remaining items are explicitly listed below.

## Baseline and provenance

- Clean initial checkout: upstream 42032f9d97e9e502dc10a14743bdb3d1b9388588;
  origin atsk-joshua/GhidraBoy. Branch `modernization`; no other project touched.
- Cherry-picked with `-x`, preserving ptthess authorship, in requested order:
  ac77201 → local 937253d; a3ade39 → 94ececd; 91169cd → e8ad870.
- No overlapping DohmBoy/pbiswal patch or dual Ghidra 11/12 source-set refactor.
  Java toolchain consistency was implemented directly; Kotlin tests and wrapper retained.
- Verified existing ADC H decoding and WRAM0; those claims were not current bugs.
- Initial port-only tests passed. Five new arithmetic regression tests failed
  against original p-code before fixes (ADC, SBC, overlap, DAA callback, POP AF).
- Additional execution regression demonstrated POP word-load wrap failure at FFFF; fixed with explicit wrapped byte reads.
- Language/register/compiler default identifiers remain unchanged. Language 1.0
  retained under Ghidra's p-code-only versioning rule. Installed old-language
  persistence checked independently, not inferred from a version number.

## Exact environment

- Primary: Ghidra 12.1.3 PUBLIC. Official asset
  `ghidra_12.1.3_PUBLIC_20260817.zip`, SHA256
  `93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`.
  Local archive matched the official GitHub release API digest.
- Local Java/decompiler tests: Homebrew Ghidra 12.1.3 with macOS native components.
  Installed loader/persistence: separately extracted official distribution under
  `/tmp/ghidraboy-installed`, isolated profiles/projects, no checkout language paths.
- OpenJDK Homebrew 21.0.12.1; Gradle wrapper 9.0.0; Kotlin 2.2.10; JUnit 5.13.4;
  ktlint plugin 13.1.0 / ktlint 1.7.1. Official Gradle distribution SHA256 pinned.
- GBDK 4.5.0 official macOS arm64 archive; SDCC 4.5.1 #15267. Exact archive
  digest/command and emitted fixtures documented in compiler-support.md.
- SingleStepTests f9c30210245dd691661db39f5ace022c465ecc2f (MIT): 168 committed
  samples, plus locally executed complete 21 selected files / 21,000 vectors.
- gbdev/hardware.inc 189324b77f99cf287f4153e0001830e8738a4068, version 5.3.0, CC0.
- 12.1.2, Ghidra 11 database upgrades, Windows and Linux are not local support claims.

## Acceptance ledger

| Requirement | Implemented and executed evidence | Remaining / not established |
| --- | --- | --- |
| Build/package | Clean `./gradlew clean build`; 366 tests, zero failures/skips; compiled SLEIGH, Java 21/Kotlin 21, deterministic archive settings; doctor validates contents | Remote CI has not run; cross-platform execution not claimed |
| Installed extension | `tools/installed_smoke.py`: separate distribution/profile, original-language create then maintained-language reopen; installed script discovery; automatic loader detection of generated ROM | GUI startup observed; menu/accelerator interaction did not advance through CUA, so full interactive workflows remain unverified |
| CPU corrections | Actual p-code exhaustive ADC/SBC (131072 each), DAA (2048), POP AF, overlapping A operands; all CB value/carry cases (131072); signed SP (131072), HL wrap, exhaustive ADD/SUB/logic/CP/ADD HL,HL and stack FFFF wrap; 21,000 external vectors | Not every instruction family has independent exhaustive semantic tests; bus/cycle behavior outside scope |
| Decode/assembler | All valid base instructions and 256 CB opcodes: operands, lengths and assembler round trips; invalid bytes deliberate; existing relative/control-flow tests preserved | Dedicated overlay-relative target/boundary suite remains incomplete; STOP retains historical one-byte static model |
| Header/boot | Pure bounded Cartridge parser, checksum separation, asymmetric 1234 value/endian survives save/reopen; readable boot, CGB hole, no fabricated header; manual and strong automatic paths | Legacy cartridge option serialization is represented by persisted metadata strings; GUI option persistence itself not exercised |
| Loader failures | Partial/truncated/oversized/unknown-size rejection; transaction cancellation leaves no memory/FileBytes; required failures propagate | Injected conflicting hardware block abort/rollback also passes |
| Mapper geometry | ROM-only, MBC1, MBC2, MBC3, MBC5 pure translation; zero-before-mask, nine ROM bits, 8 MiB/512 actual blocks, RTC/device selection, rumble and MBC2 nibble helpers | MBC1M not modeled/detected; MBC30 and exotic geometry RAW; non-power-of-two wiring unresolved; MBC2 static bytes do not enforce nibble masks |
| Maps/aliases | Versioned JSON/API; source-based ROM identity after rename/split, physical↔static and file↔static, CPU explicit state, ROM alternate views and shared echo bytes; WRAM3/4 distinct | Joined source mapping tested; legacy RAM without anchors requires explicit identification |
| Symbols | Grammar, UTF-8/CRLF, comments, wide banks, BOOT/ANY, local attachment, dedup, metadata; installed idempotence; current/retained export; reload/removal preserves edited user labels | Boundary/end markers conservatively retained with diagnostics; no companion auto-discovery or rich preview table |
| Analysis | Bounded known constants incl. direct-memory p-code outputs; explicit states and candidate sets; known bank2 target, ambiguous branch merge, user-reference preservation; seed-only functions | Same-window instruction context implemented; no interprocedural summaries; all conclusions don't have decompiler fixtures; removal/ownership coverage incomplete for functions/bookmarks |
| Far calls | Exact opt-in MBC3 trampoline byte validation and explicit sites; inline-return override; actual p-code fixture checks target and adjusted return/SP | No arbitrary conventions; override removal workflow remains manual; no automatic GBW3/RST assumptions |
| ROM export | Original/current identity, exact patch placement after split/rename; source conflict checks and detached-view rejection; explicit checksum repair to new file | Detached conflicting ROM copy rejection and explicit repair tested; arbitrary detached/custom mappings not exportable |
| Compiler specs | Four explicit versioned ordinary scalar variants; SDCC-generated mixed-width/32-bit/pointer/caller fixtures and actual Ghidra storage assertions | Current first-width selection is explicit; variadic/aggregate/banked calls require custom storage; historical compiler binary not executed |
| Hardware reference | Volatile I/O retained; sourced descriptions, interrupt mask enum and CC0 hardware.inc bundled | Full bit-enum application and native manual-index integration incomplete |
| Existing programs | Old language/layout fixture retains labels, function body, custom storage, type, comment, bookmark, override, ROM patch and renamed overlay in separate process; repeated metadata enhancement and selective disassembly | Actual 11.3.1→12.1.3 database migration unexecuted (no local 11.3.1 environment/artifact); never claimed equivalent |

## Executed commands

Use local environment prefixes `JAVA_HOME=/opt/homebrew/opt/openjdk@21` and
`GHIDRA_INSTALL_DIR=/opt/homebrew/opt/ghidra/libexec` for Gradle commands.

- `./gradlew test --no-daemon`: port-only baseline passed.
- `./gradlew test --tests '*ArithmeticInstructionTest'`: five tests failed before
  fixes, all passed afterward. The overlap test was corrected to avoid reusing
  an opcode address in an emulator decode cache.
- `./gradlew ktlintFormat`, then `./gradlew clean build`: full lint/build/test/package
  gate passed. `clean` removes the generated SLA so it is actually recompiled.
- `python3 tools/fetch_vectors.py --count 1000 --output /tmp/ghidraboy-vectors-comprehensive`
  then `./gradlew test --tests '*ExternalVectorTest' -Dghidraboy.vector.dir=/tmp/ghidraboy-vectors-comprehensive`:
  all 21,000 selected-file vectors passed. Larger requested count reproduced
  the same 21,000 actual vectors, not 210,000.
- `python3 tools/installed_smoke.py --ghidra /tmp/ghidraboy-installed/ghidra_12.1.3_PUBLIC --zip build/distributions/ghidra_12.1.3_PUBLIC_20260905-dev1_GhidraBoy.zip --jdk /opt/homebrew/opt/openjdk@21 --work /tmp/ghidraboy-smoke4`:
  preservation, loader discovery, persisted checksum and installed symbols passed.
- `python3 tools/doctor.py --ghidra /opt/homebrew/opt/ghidra/libexec --jdk /opt/homebrew/opt/openjdk@21 --zip build/distributions/ghidra_12.1.3_PUBLIC_20260905-dev1_GhidraBoy.zip`: passed.

Reports are in `build/reports/tests/test`, `build/test-results/test`, and retained
installed logs under `build/reports/installed`. Release checksum is in the
external `build/distributions/SHA256SUMS` sidecar (not embedded in its own ZIP).

No branch pushed, release published, external message sent, proprietary ROM
used, or GhiGBC integration/coordination performed. CI definitions now target
12.1.3 and include installed/persistence gates; the existing release job remains.
An automatic approval review rejected removing that job, so it was preserved.

See user-workflows.md for installation/first use and rollback. This preview is
useful independently, but the outstanding acceptance items above remain work.
