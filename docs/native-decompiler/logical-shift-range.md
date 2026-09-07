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

Optional hardware execution uses `debugger/tests/nibble_switch_oracle.py`
from the repository root. The static verifier's `--ghigbc` option retains its
compatible name and selects the integrated `debugger/` directory. Static C-only
builds do not import the debugger or require an emulator. These self-authored
fixtures validate the generic recovery rule; they do not establish whole-ROM
semantic acceptance for an arbitrary game.
