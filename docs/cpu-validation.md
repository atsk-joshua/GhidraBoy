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

Encoded direct byte/word stores use Program-aware bus hooks. Native, compiled
p-code and independent SameBoy regressions cover ROM immutability, selector
changes, byte ordering, wrapping, ordinary/RAW memory behavior and bounded
context safety. See [direct bus semantics](direct-bus-semantics.md); this does not
claim general indirect-store coverage or absolute entry-SP recovery in C.

Independent exhaustive tests execute actual compiled SLEIGH for ADC and SBC
(131072 cases each), all A/N/H/C DAA combinations (2048), overlapping A operands,
and 256 CB operations x 256 values x 2 carry states. CB tests cover memory forms,
rotates/shifts, BIT carry preservation and RES/SET flag preservation. Historical
base decode tests plus every CB encoding check operands and lengths. Invalid
base opcodes remain undefined bytes. Ordinary assembler/decompiler and
parameterized control-flow tests remain enabled.

Native decompiler call-effect regressions also execute the compiled p-code of
`SCF; CALL` into a `CCF; RET` callee and then test carry. The assembly-default
model now kills F at the call: recovered F has an INDIRECT call-effect definition
instead of propagating the pre-call carry. Both explicitly set and incoming
carry cases are covered. Architectural execution checks the resulting memory
write, while the default C intentionally retains an unknown callee flag result
until a proven per-function return convention is supplied.

DAA now uses pure p-code. Expected results use independent sequential wider
arithmetic, checked against SameBoy v1.0.3's `daa` implementation. The reviewed
12.1.3 text golden exposes correction arithmetic. Boolean low/high corrections
and an eight-bit add/subtract factor preserve all 2,048 A/N/H/C combinations
without internal control-flow branches, avoiding artificial unreachable-block
diagnostics when preceding instructions establish the flags. Both known and
unconstrained input flags have native decompiler regressions. This is a semantic
improvement from the former ignored userop.

HALT/STOP/IME remain visible userops. The unused daaOperand declaration remains
to keep existing userop indices stable. STOP retains historical one-byte decode;
this static model does not claim hardware padding-fetch, speed-switch,
interrupt-delay or HALT-bug fidelity. Tests use flat 64 KiB RAM. Runtime mapper
switching and bus/cycle timing are outside this memory model.

POP retains its original single constructor and token bindings. A branchless
mask clears the unused flag bits for AF and preserves all flags for BC/DE/HL.
This replaces a conditional p-code branch on a constant opcode field. A balanced
PUSH/POP decompiler regression retains the input/output register value without
artificial unreachable-block diagnostics; stack execution initializes and checks
the preserved flags explicitly.

Language 1.0 requires preservation of persisted constructor identity as well as
register/context layout and instruction boundaries. The withdrawn decomp1
candidate added a dedicated POP AF constructor: fresh decoding passed, but saved
POP BC/DE/HL instructions reopened as POP AF. It must not be installed or used to
save annotated Programs. The decomp2 correction retains the exact original POP
constructor pattern and token bindings. Acceptance additionally requires an
old-provider save/new-provider reopen comparison against fresh decoding and
p-code; fresh-import tests alone cannot establish compatibility. Follow the
pinned Ghidra 12.1.3 GhidraDocs/languages/versioning.html rules and preserve
backed-up projects until that gate passes.

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
