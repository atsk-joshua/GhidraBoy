# Logical-shift bounds in native switch recovery

`JumpBasic::getMaxValue` previously recognized immediate AND masks and merges
of those masks, but ignored bounds imposed by a logical right shift. A generic
SM83 mask/SWAP/table-dispatch fixture consequently recovered 128 entries from
a sixteen-value domain.

The combined `12.1.3+ghidraboy.switch-recovery.2` patch derives the exclusive
upper bound from an equal-width constant logical shift. Zero shifts retain the
full-domain sentinel; overshifts produce the singleton zero without undefined
host shifts. Signed, variable, unequal-width and oversized cases remain
unrestricted. Finite bounds also constrain the range stride, including AND-zero
and overshift cases. This does not depend on incomplete CFG/NZMask information.

`tools/native-tests/testjumprightbound.cc` exercises the actual native methods
at widths 8/16/32/64 with boundary and negative cases. The guarded
`src/test/scripts/NibbleSwitchRangeProbe.java` supplies the end-to-end synthetic
regression. `tools/verify_nibble_switch_fixture.py --c-only` compiles its returned
C unchanged and checks all 256 byte inputs and exactly sixteen recovered targets.
Both native dependency builds require these checks alongside the earlier
normalized-switch regression.

Optional hardware execution belongs to GhiGBC's
`tests/nibble_switch_oracle.py`. The static verifier's `--ghigbc` option invokes
that separate driver and compares its result. Static C-only builds do not import
GhiGBC or require an emulator.

Game-specific addresses, saved-reference findings and corpus deltas are tracked
in GhiBW3's `docs/decompilation/NIBBLE_SWITCH_RESEARCH.md` and `SWITCH2_REPORT.md`.
They are not embedded in the generic recovery algorithm or its fixtures.
