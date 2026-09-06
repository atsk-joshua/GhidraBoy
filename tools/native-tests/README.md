# Native jump-range boundary regression

`testjumprightbound.cc` exercises the actual `JumpBasic::getMaxValue`,
`getStride`, and `calcRange` methods with isolated native IR. It covers byte,
word, dword, and qword logical shifts, full-domain shift zero, overshifts,
signed/variable/unequal-width negative controls, and zero-only range stride.
The test constructs its bounds before any NZMask pass, so incomplete graph
knowledge cannot supply the proof being tested.

Copy this file into a **disposable, patched** Ghidra 12.1.3 source tree at
`Ghidra/Features/Decompiler/src/decompile/unittests/`. From its adjacent `cpp`
directory, build and run the existing native test runner. On Apple Silicon:

```sh
make -j8 decomp_test_dbg 'CXX=/usr/bin/clang++ -std=c++11' \
  'ARCH_TYPE=-arch arm64' 'ADDITIONAL_FLAGS=-mmacosx-version-min=11.0 -w'
./decomp_test_dbg -sleighpath /absolute/path/to/distribution unittests \
  jump_logical_right_immediate_bound jump_logical_right_negative_cases \
  jump_zero_mask_stride_singleton
```

The XML architecture test loader needs the distribution's x86 language files.
The development test runner normally links BFD, even though these tests do not
use its loader. On a host without BFD headers/libraries, this specific test can
use an XML-only runner: in the disposable Makefile, immediately after `EXTRA`
is defined, add
`EXTRA := $(filter-out bfd_arch loadimage_bfd analyzesigs codedata,$(EXTRA))`
and pass `BFDLIB=` to `make`. This local test-harness adjustment must remain
outside the production jumptable patch and the pristine source lock. It was
used for the recorded macOS boundary test. Production `ghidra_opt` builds use
the unmodified Makefile.

For the end-to-end SM83 range gate, use the guarded
`src/test/scripts/NibbleSwitchRangeProbe.java` and
`tools/verify_nibble_switch_fixture.py`. The native dependency builder runs
the public probe and its compiled-C range/value oracle; these direct IR tests
add boundary coverage independent of instruction simplification.
