# State-sensitive representation investigation

This investigation extends the retained finite-view comparison. It does not
qualify SA-01 or SA-02 by itself. Raw execution, address representation, native
decompilation, saved listing, and normal-window navigation are separate results.
The primary integration receipt owns final test and installed qualification.

## Identical adversarial inputs

`SoftwareCallStatePathsTest.kt` defines self-authored MBC3 inputs with no private
ROM dependency. An outer register-target RST helper calls bank 2 CPU 4100 with
SP=c100 and a real pushed CPU return word 0201. The architectural expectations
are independent of the representation candidate:

| Case | Physical bytes | Required result |
| --- | --- | --- |
| Revisit | bank2:4100 `043e03ea0020`; bank3:4106 `c30041`; bank3:4100 `0cc30042`; bank3:4200 `c9` | Both CPU4100 sources execute; B=1 and C=1 |
| Conditional | bank2:4100 `ca20413e03ea0020`; bank3:4108 `c30042`; bank2:4120 `3e02ea0020c30042`; bank2:4200 `3e22c9`; bank3:4200 `3e33c9` | Initial Z=0 selects bank3 A=33; Z=1 selects bank2 A=22 |
| Data | bank2:4100 `fa0050473e03ea0020`; bank3:4109 `fa00504fc9`; bank2:5000=22, bank3:5000=33 | B=22 and C=33; the identical CPU data address has two storage identities |
| Nested return | bank2:4100 `cd004247c9`; bank2:4200 `3e03ea0020`; bank3:4205 `cd00433e02ea0020`; bank3:4300 `0cc9`; bank2:420d `c9` | Inner CALL returns to bank3:4208, restoration selects bank2:420d, outer CALL returns to bank2:4103; B=2, C=1, SP=c100 |

The conditional test has two explicit flag premises. It does not establish a
single unknown-flag graph or all-input correctness. Its two paths must not be
merged solely because their eventual CPU PCs match.

The tests preserve current architectural proof and expose the native transport
veto separately. Their expected rejection is a recorded missing capability, not
support. The test's overlapping view request is one byte at CPU4100 from each
bank, so the failure cannot be attributed to a guessed suffix or a cut instruction.

## Compared mechanisms

### Existing overlays and the finite view

The current provider represents bank2:4100 and bank3:4100 as distinct canonical
overlay addresses. Its architectural effect engine already retains both fetch
identities in the revisit fixture. `SoftwareCallExecutionView` version 2 stores
one source per CPU interval and rejects these two ranges with
`A CPU address has multiple execution identities`. This is a structural conflict;
increasing the view's extent cannot solve it. The old continuation walker's
CPU-only visited set and injection emitter's CPU-keyed instruction map would
also conflate such graph nodes if the view rejection were removed.

Pinned Ghidra's `FunctionManagerDB.java:218–225` requires all ranges of a Function
body to occupy one address space. Existing canonical overlays therefore cannot
make a single native body containing the competing source ranges. Cross-overlay
CALLs between separate Functions remain a different, already qualified mechanism.

### Executed physical-segment candidate

A disposable language candidate was built under
`/private/tmp/ghidraboy-sa01-representation/module`, with language ID
`SM83WideExperiment:LE:32:default`. It uses a 32-bit physical space and explicit
`bank << 16 | CPU` source addresses. The same four instruction byte sets above
were decoded in real Ghidra Programs. The data case also stores its two distinct
bytes at physical 00025000 and 00035000. This is an actual compiled-language,
Program, native-decompiler and separate-process persistence experiment, not the
previous 16-bit overflow check.

The first compiler run, which only enlarged the space, failed on LOAD/STORE
pointer-size restrictions. The compiling candidate explicitly zero-extends
architectural address values only at memory access boundaries. PC, SP, BC, DE,
HL, the compiler's pointer size, pushed return words, and CPU arithmetic stay
16-bit. Each RET reads two individual bytes using separately wrapped 16-bit
addresses before extension. All physical code ranges can be retained in one
Function, including both 4100 identities. Original source files and installed
languages were never modified.

Actual results from final fresh and independent reopen runs:

| Case | Native result under this candidate |
| --- | --- |
| Revisit | Decompile completes but fetches unmapped 00024106 instead of 00034106; C is truncated with `halt_baddata` |
| Conditional | Fetches unmapped 00024108 and branch target 00004120; both required physical paths are misrepresented |
| Data | Both absolute reads decode as `(ram,0x5000,1)`; mapper write does not select 00035000, and execution truncates at 00024109 |
| Nested return | Native CALL is 00004200 instead of 00024200; native C can complete without a warning while calling the wrong physical target |

Each final process exits 0 and reports exactly four expected native
missing-memory warnings: one revisit, two conditional, one data. These are
semantic failures of the candidate, not successful qualification. The nested
case independently demonstrates why a completed, warning-free decompilation is
insufficient. Listing and native behavior persist across the separate-process
reopen. No normal CodeBrowser GUI was opened for this candidate; normal-window
navigation is unrun. The public DecompInterface used here is an experiment,
not an alternate workflow delivered to users.

This rejects **widening plus address adapters alone**. A complete segmented
design was not implemented or disproved. It would additionally need state-aware
fetch fallthrough, direct/indirect branch and call transport, independently
selected code/data identities, mapper-write lowering, alias storage semantics,
native segment operation behavior and reviewed migration of all saved addresses,
references, bodies, contexts and consumer schemas. The native results identify
those exact missing mechanisms rather than treating representability as proof.

Ghidra's built-in `SegmentedAddressSpace` uses x86 real-mode arithmetic
`(segment << 4) + offset`; `ProtectedAddressSpace` concatenates selector and
offset but retains x86 selector iteration rules. Neither provides Game Boy
mapper policy or code/data separation merely by enabling `<segmented_address>`.
A custom bank segment design needs its own implementation and evidence.

### Scoped state graph through supported injection

The selected integration direction retains physical overlay storage and 16-bit
CPU arithmetic. A justified state graph identifies each instruction by physical
source plus consumed mapper/register/memory/stack state. Local injected CFG
anchors distinguish graph nodes even when their CPU PCs coincide. Every data
access is translated using the node's state and access kind, independently of
the code view. Branches target graph nodes, not a CPU-keyed map.

State-qualified shared views retain canonical sources at original CPU offsets
for Listing navigation; no individual view claims competing physical sources
at one offset. Both canonical and derived entry Functions must use the complete
validated graph through the installed public injection mechanism. A reviewed
terminal listing representation prevents ordinary native fallthrough from
decoding unselected source bytes. Multiple views are an explicit topology in
the ownership/registry receipt, not independent proof premises or copied RAM.

Source inspection supports arbitrary site addresses for the existing local
injection emitter: its output operations all use the supplied call-site address.
The canonical-versus-alias decision is currently a registry-controlled condition
in `SoftwareCallInjection`, not an intrinsic native restriction on local CFGs.
The integrated native and normal-window tests must still establish this for
each changed path. Existing finite alias behavior should remain independently
covered; this investigation does not replace its canonical assertions.

Callee roots with competing states are an additional obligation. A caller's
complete continuation graph cannot by itself fix normal decompilation of an
independently opened callee. Pinned Ghidra supports prototype mechanism injection
through `<pcode inject="uponentry">` and `CALLMECHANISM_TYPE`; `PrototypeModel`
names it `prototype@@inject_uponentry` (lines 613–617, 665–675). However, actual
pinned native source rules it out for a whole CFG: `ActionConstbase::apply`
(`coreaction.cc:681–691`) injects into an existing basic block, and
`Funcdata::doLiveInject` (`funcdata.cc:848–877`) throws
`Illegal branching injection` for any call or branch. It can establish entry
register effects but cannot replace a callee graph. This source constraint
corrects the preliminary Java-only investigation; no runtime success is claimed.
Callee-root support requires a suitable pre-flow injection point or a separately
versioned native hook, with proof that original effects do not execute twice.

## Compatibility and proof obligations

The scoped graph direction can retain language 1.0 and physical mapping schema
v2 if it does not change architectural constructors or storage mapping. New graph,
registry and ownership records still need explicit versions, old-reader rejection,
paired canonical/all-view invalidation, retired-view lifecycle handling, and
reviewed migration preserving uncertain saved work. A changed graph must consume
configuration, physical bytes, data images, annotations, summaries and live-frame
dependencies. Old ownership stamps cannot silently authorize cleanup of new
state views. The independent tests here do not grant migration authority.

The physical-segment candidate uses a distinct disposable language ID, so it
does not silently reinterpret existing Programs. It has no saved-work migration
implementation. Successful fresh save/reopen only proves persistence of that
candidate's new addresses and incorrect native behavior; it says nothing about
migrating annotated production Programs.

## Exact experiment evidence and failures

Scratch evidence is retained at `/private/tmp/ghidraboy-sa01-representation/`.
`probe-identities.json` hashes source, compiled language and logs. Principal
identities at this experiment checkpoint:

| Artifact | SHA256 |
| --- | --- |
| `RepresentationProbe.java` | `2d589f95fabe9eb504f4b2de99752a695655c0720e7c5f5def1a2c1a7f4ee783` |
| Compiled experimental `sm83.sla` | `d728b7924de425f5307a930e900ef8f2fcfeda0f7ae42ef893cba5cf115d5935` |
| `wide-native-create-final.log` | `84f91794c28ef869871e4a3c5d4705140c9e43aed12d15fabd36bf8e34e203f9` |
| `wide-native-reopen-final.log` | `3f479fd281ea0a6e156b2a46e9f5748014c2989948ea64d06584ae3ea29b4723` |
| Pinned SoftwareModeling.jar | `220c419c4d94d65faddecf77ba899213b66382c092a3753be56f3bb08112c96f` |
| Native `mac_arm_64/decompile` | `5b736c3e9236667d35a732f226c99f0014736b9fe506147886a7f15ccb94939a` |
| JDK release file | `7b6f4e84249287203d8e1857254307a6b2dc0643b1efdeef5fa2aeaf791866f0` |

The native tuple is Ghidra 12.1.3 with
`12.1.3+ghidraboy.switch-recovery.2` on mac_arm_64, JDK 21 at
`/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`. Ghidra is read
from `/private/tmp/ghidraboy-sa00/ghidra_12.1.3_PUBLIC`; scratch settings and all
Programs are isolated from production/headless/GUI campaign projects.

Compilation invokes the pinned Java `ghidra.pcodeCPort.slgh_compile.SleighCompile`
against the scratch slaspec with the distribution JAR classpath. The probe is
compiled with JDK21 `javac -proc:none` using that same classpath, then run in two
JVMs: `RepresentationProbe` creates and saves the four Programs;
`RepresentationProbe reopen` opens and decompiles them. Both set
`java.awt.headless=true`, `user.home` to scratch `profile`, and
`application.settingsdir` to scratch `settings`. The final project is
`segmented-probe-2.gpr`.

Earlier failures remain in the scratch logs: the stock launcher attempted a
non-writable user preference path; the initial enlarged language failed width
checks; two address-adapter drafts failed grammar/size inference; the first
Java layout attempted to mutate an immutable module map; an earlier create
process saved all four Programs then failed consumer cleanup. The final create
fix explicitly registers project ownership and has no unexpected process error.
No failure log was overwritten. No active installation or private original was
changed, and no shared provider build was run by this worker.

Remaining acceptance work includes the integrated graph's native and normal
window behavior, unknown-condition multi-path handling, callee-root transport,
paired drift and migration, and installed separate-process qualification. These
remain requirements; this document is not a completion declaration.

## Subsequent root-entry mechanism prototypes

Two additional isolated prototypes answer how a complete graph could replace
normal callee-root decoding. They use a synthetic multi-block graph with a
conditional result and a real two-byte stack pop. The graph intentionally has
the same test body for each source shape; these runs establish the insertion
mechanism, **not** that the four mapper fixtures have graph-derived semantics.
Production must derive its per-root graph from validated architectural effects.

### Instruction-prefix CALLOTHER hook

`HookProbe.java` prepends a `gb_state_entry()` userop to each scratch SLEIGH
constructor and installs a static callotherfixup containing the complete graph.
The native decompiler displays the injected result and removes the original
effects as unreachable. However, it first decodes the original flow, retaining
the same four missing-memory warnings as the widened-space candidate. Calling
`Instruction.setFallThrough(null)` at a nonflow entry does not add a terminal
p-code operation to `getPcode(true)` and does not close this boundary.

`HookAnchorProbe.java` then explicitly gives the entry a self fallthrough and,
for the initial conditional jump, a RETURN override. The complete graph still
executes its original conditional logic; the listing overrides only bound
initial native decoding. Fresh and reopened native results contain the injected
CFG with no process WARN/ERROR and without doubled original entry effects.
This is a possible reviewed synthetic representation, not proof that the CPU
entry loops or returns immediately. It would require SLEIGH/version/override
migration and strict rejection of stale graph registrations. It is not selected
merely because these insertion probes pass.

### Narrow native pre-flow protocol

The later prototype preserves the original 16-bit SLEIGH constructors and
canonical bank overlays. All 238 native source files were checked against the
pinned pristine lock before copying. The existing switch-recovery.2 patch was
applied to the isolated source, then a narrow two-file prototype was added:

- `FlowInfo::generateOps` recognizes the reserved prototype name
  `__ghidraboy_state_entry_v1`, requests its existing uponentry injection payload
  **before** following raw instructions, and constructs initial native flow from
  that complete local CFG. Empty/missing payloads and fallthrough/external or
  unresolved indirect graph escapes are rejected.
- `ActionConstbase::apply` skips late uponentry insertion for only that reserved
  protocol, preventing double execution. Other calling conventions use the
  original late-injection behavior.

The Java probe installs an explicit reserved calling convention on each root.
It changes no source instruction's fallthrough, override, bytes or body.
Physical bank2/bank3 source blocks and listing addresses remain distinct, and
the actual CPU pointer, PC, SP and return word sizes remain two bytes. The
scratch language ID is distinct solely to isolate the experiment; its SLEIGH
source inputs are copied unchanged from the provider.

`NativeEntryProbe.java` freshly decompiles and saves all four source shapes;
a second JVM opens and decompiles them. Both processes exit 0 with no process
WARN/ERROR. Their C contains the synthetic graph's actual conditional output,
and no original-code bad-data or unreachable-block diagnostic. Negative
fallthrough, external direct branch, and unresolved indirect-branch payloads
each produce four expected failed decompilations, with the exact diagnostic
`Low-level Error: GhidraBoy state-entry graph escapes its local CFG`.

This establishes an insertion mechanism that can precede original bank-sensitive
recovery without an unconditional SLEIGH hook. It is a new native dependency,
not stock Ghidra support. The prototype deliberately uses a one-byte native
entry-site extent for injected operation indexing while preserving every saved
Function/listing range; production needs an explicit decision on native extent
metadata and its consumers. This must not become authority to truncate a saved
body or exclude an unresolved physical instruction.

The prototype build command was `make -j4 ghidra_opt` with
`CXX=clang++ -std=c++11`, `ARCH_TYPE=-arch arm64`, and
`ADDITIONAL_FLAGS=-mmacosx-version-min=11.0 -w`, matching the existing native
helper's platform flags. It ran only in the isolated native source directory.
No source lock, dependency pin, packaged artifact or active installation was
changed by this worker. These are mechanism probes; existing native switch,
full provider and GUI qualification is not inferred for this executable.

| New scratch artifact | SHA256 |
| --- | --- |
| `state-entry-preflow-prototype.patch` | `491f526e783b765bd26ff3e3fd9f5737106d88eaa79977a6106c9817158ca677` |
| `NativeEntryProbe.java` | `760b6c3637fb0c8d4b2f9019a0eaa82ede9cf4e69b1fac30671bc3b414832ce6` |
| `native-entry-create.log` | `d1c506c6ba7b7d8056f4684835513309db0b4e1545879a6c03f7bf26df32615a` |
| `native-entry-reopen.log` | `11d3090e86ddf12e1596a13ebecf1f097975820f50a0b2d718a5063610eae9ba` |
| New prototype native executable | `8370e184f2ec8782739c350b3a827a1fc8e8a14a81639f25610f3219521e2767` |

`native-entry-identities.json` also records all three negative logs and the build
log. The public Java transport is the existing CALLMECHANISM_TYPE injection API;
the new timing and protocol semantics require native companion versioning,
capability checks, saved prototype/registry ownership and independent review.
Full dynamic per-root semantic proof and normal-window qualification remain
integration work.

## Optional native delivery tool checkpoint

The narrow patch is now checked in as
`tools/patches/ghidra-12.1.3-state-entry-1.patch`; the initial tool checkpoint
used the prototype patch hash above. `tools/state_entry_native.py` implements build/package, copy-only
installation and byte/startup verification. It preserves the existing
switch-recovery dependency pins and updater. The additional capability marker is
`Ghidra/Features/Decompiler/state-entry-native.json`, with schema
`ghidraboy-state-entry-native-v1`, protocol `__ghidraboy_state_entry_v1`, and
native dependency version `12.1.3+ghidraboy.switch-recovery.2.state-entry.1`.
It records base/switch/state patch, source lock, patched-source inventory, platform
and executable identities. Marker verification checks the actual native bytes.

The tool's installation output is a new bundle containing `distribution/`,
`receipt.json` and exact backups under `original/`. It never overwrites the
source distribution or an existing output. A stale switch-only marker would
contradict the new executable, so the new copy replaces that marker with the
explicit composite marker and preserves the exact old marker in `original/`.
The original distribution remains untouched and is the immediate rollback path.

Ten focused Python tests pass using self-authored package/filesystem fixtures.
They cover reviewed pins/protocol, trusted package digests, changed executable
and patched-source receipts, path escape/symlink rejection, unchanged source and
backup inventories, failed-startup cleanup, changed pristine source rejection,
unrun qualification claims and unsupported-host refusal. Fake native fixtures
are never executed; their startup is mocked explicitly. `tools/check.py --suite
tools` discovers this test class automatically. The primary owns the full suite.

An actual build through the new tool succeeded using the same pinned source and
JDK, with work directory
`/private/tmp/ghidraboy-sa01-representation/tool-native-build`. Its executable is
byte-identical to the mechanism prototype. The resulting archive
`state-entry-native-mac_arm_64.zip` has SHA256
`091bb99c9d32618aaff6cb4d0aeeb261bdb0d803e8b175f6c914047bc702cc1a`.
The receipt status is deliberately `BUILT_UNQUALIFIED_STATE_ENTRY_PROTOCOL` with
`semanticQualification: UNRUN`; compilation/startup does not set qualification.

Actual copy-only install and `verify --probe` then passed against
`/private/tmp/ghidraboy-sa01-representation/tool-installed-native/distribution`.
The full source and copied distribution inventories were compared before and
after. Its source was the same pinned distribution listed above. This tool
checkpoint tests the native-delivery lifecycle, not a newly installed provider
campaign or GUI workflow. `tool-native-build-command.log`,
`tool-native-install-command.log`, `tool-native-verify-command.log`, the build
directory and installed bundle retain exact commands/results and inventories.

The primary subsequently reported all four `SoftwareCallStatePathsTest` tests
passing in focused-2 and focused-3. Those tests retain the explicit raw/native
distinction described above; the pass count does not close transport obligations.
Probe sources, language inputs, logs, patch and initial tool receipts are now
retained in [representation-probes](representation-probes/retained-probe-files.json),
with a SHA256 inventory. Compiled binaries and disposable Programs remain in
their recorded scratch directories rather than being added to the repository.

## Reviewed conditional-output notice

Independent integration review required native output to expose its selected
entry-state condition. Successful reserved pre-flow graph acceptance now adds
this native C header:

> GhidraBoy conditional execution model: valid only for the selected reviewed entry state. See the Function comment and GhidraBoy Tools execution contexts.

This uses `data.warningHeader`, not process WARN logging, and applies only to
`__ghidraboy_state_entry_v1`. Default/ordinary native functions retain their
existing behavior. The new patch SHA256 is
`91d8d2bfe6b2478cfb98f2c609d975036eb523a3c481c6f05d7516c87d503388`.
The optional tool's accepted patch identity changes with it; the earlier patch,
binary, archive and receipts above remain historical evidence. Ten focused
Python tool tests pass with the new patch identity. A new native build and
disposable installation receive separate receipts below.

The new tool build, copy-only install and `verify --probe` passed. The archive is
`/private/tmp/ghidraboy-sa01-representation/tool-native-build-context-header/state-entry-native-mac_arm_64.zip`,
SHA256 `d6041e4fe0115ba709a070fe23675fcf55a93d6c9da7fe4728d76534f2190ab9`.
Its executable SHA256 is
`d60be1dd82b660b4123adbe2a8c7c3353a7974e856d4298208f8dc68490db871`.
The separate disposable installation is
`/private/tmp/ghidraboy-sa01-representation/tool-installed-native-context-header/distribution`.
No earlier executable, installation, archive or receipt was overwritten.

`HeaderNativeEntryProbe` asserts the header in native C for all four source
shapes on fresh creation and a separate-process reopen: eight completed
decompilations with the expected visible header and no process WARN/ERROR.
`HeaderOrdinaryProbe` separately checks ordinary `__asm` code `3e42c9`; fresh and
reopened native C both return `0x42` and contain no conditional header. Those
two processes also have no WARN/ERROR. These remain insertion/display mechanism
probes; their static synthetic graph does not qualify production mapper effects.

The new sources, logs, build/package/install receipts and exact patch are retained
with hashes in [context-header-files.json](representation-probes/context-header-files.json).
This later inventory leaves the earlier probe inventory and identities intact.
The four reserved-root fresh log hash is
`833cbb6bfad379850d46b7917be6725ab6593816a04332d87524907dd351a954`;
the reopen log hash is
`c59716a48bf481eb1184650793c095506fe0e534656fa531892f598597c8a39e`.
