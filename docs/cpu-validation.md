# CPU validation and interpretation

Pinned reference: SingleStepTests/sm83 f9c30210245dd691661db39f5ace022c465ecc2f,
MIT license in src/test/resources/vectors/LICENSE. Its vectors are generated
from Ares and may contain errors. `manifest.json` pins source and selected JSON
SHA256 values. Ordinary CI executes the first eight vectors from each of 21
listed files (168 vectors), with no network. `tools/fetch_vectors.py --count
10000 --output <temporary-directory>` downloads all vectors for those selected
instructions; full-corpus coverage is not claimed.

Comparison: all ten architectural registers and all listed final memory bytes;
F low nibble is normalized on register initialization and comparison only.
Memory bytes, including raw stack AF, are not normalized. IME, IE and cycles are
not compared as runtime hardware state. Samples contain no excluded arithmetic
vectors. Fresh emulator memory/decode state per vector avoids opcode-cache
leakage; one Program/application is shared and all helpers/programs disposed.

Independent exhaustive tests execute actual compiled SLEIGH for ADC and SBC
(131072 cases each), all A/N/H/C DAA combinations (2048), overlapping A operands,
and 256 CB operations x 256 values x 2 carry states. CB tests cover memory forms,
rotates/shifts, BIT carry preservation and RES/SET flag preservation. Historical
base decode tests plus every CB encoding check operands and lengths. Invalid
base opcodes remain undefined bytes. Ordinary assembler/decompiler and
parameterized control-flow tests remain enabled.

DAA now uses pure p-code. Expected results use independent sequential wider
arithmetic, checked against SameBoy v1.0.3's `daa` implementation. The reviewed
12.1.3 text golden exposes correction arithmetic and folds the known N=0 branch;
this is intentional semantic improvement from the former ignored userop, not
an assertion that the former arithmetic was correct.

HALT/STOP/IME remain visible userops. The unused daaOperand declaration remains
to keep existing userop indices stable. STOP retains historical one-byte decode;
this static model does not claim hardware padding-fetch, speed-switch,
interrupt-delay or HALT-bug fidelity. Tests use flat 64 KiB RAM. Runtime mapper
switching and bus/cycle timing are outside this memory model.

Language 1.0 is retained: register layout/context/IDs are unchanged, no opcode
boundaries changed, and POP's newly bound token field adds no match constraint.
Only p-code behavior changes. This follows the pinned Ghidra 12.1.3
GhidraDocs/languages/versioning.html rules. Existing code can be selectively
reanalyzed from a backed-up project; no major-version translation is warranted.

The locally executed comprehensive cross-check covered **all 21,000 vectors**
in the 21 selected upstream files (1,000 each). The corpus files contain 1,000,
not 10,000 vectors; requesting a larger count correctly retains their actual
length. Use `--count 1000 --output /tmp/gb-vectors`, then
`./gradlew test --tests '*ExternalVectorTest' -Dghidraboy.vector.dir=/tmp/gb-vectors`.
This is complete coverage of selected files, not all upstream opcode files.

Additional independent compiled-p-code checks cover all input pairs for ADD,
SUB, AND, XOR, OR and CP (393,216 vectors), every ADD HL,HL input (65,536),
and INC/DEC carry preservation. A stack word across FFFF/0000 exposed a Ghidra
word-load boundary issue: PUSH wrote both wrapped bytes, while POP read only the
low byte. POP now uses two explicitly 16-bit byte addresses; the regression,
normal control flow and decompiler goldens validate this pure p-code correction.

Additional family coverage checks all four accumulator rotates for every byte and
carry input (2048 cases), including their distinct zero-flag clearing behavior,
and all 63 LD register/memory encodings with two flag states (126 cases). The LD
matrix checks old-HL addressing when H/L are also operands, self copies, every
unaffected register, flags, SP and PC. These execute compiled p-code directly.
