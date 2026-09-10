# Static contract v2

This is the static provider's Java/JSON contract, consumed by the optional
GhidraBoy debugger's retained GhiGBC adapter v1. The static provider supplies no
execution engine, telemetry or live bank selection. The debugger module owns
runtime translation, ambiguity policy, trace lifespans and versioned static
snapshot transport. This module boundary is distinct from repository ownership.

The [static accuracy specification](static-analysis-spec.md) describes planned
extensions and decision gates. This documentation update does not change mapping
schema v2, Java records, language identity or compiler IDs. Any representation or
schema migration must be qualified before changing this implemented contract.

`ProgramMapping.inspect(Program)` returns a deterministic, sorted snapshot.
`mapping-schema.json` describes the exported envelope. The schema is validated against actual exported snapshots using jsonschema 4.25.1.
Language/compiler IDs,
original FileBytes SHA256/length, raw header, calculated checksums, selected
hardware, mapper, warnings, source ranges, permissions and aliases are included.
Program options persist the parsed cartridge and override provenance; Ghidra
address property maps anchor RAM identities. Input bytes are never repaired on
import. The original SHA256 is distinct from `Sha256.of(exportBytes(..., true,
false, monitor))`, which describes current patches.

Physical identity is `(region, bank, offset)`: ROM banks are 16 KiB, WRAM banks
4 KiB, VRAM/SRAM banks 8 KiB; MBC2_RAM is 512 byte-addressed low-nibble entries.
Ranges may be portions of a bank. Names like `rom18` are decimal presentation
only. FileBytes sources establish ROM identity after rename, split or join.
Alias targets use the Program address factory, including real overlay spaces.
The API never uses a language-only factory for program overlays. RAM without
loader anchors remains unresolved in legacy programs. An explicit anchor can
be added with `ProgramMapping.identifyRam` with checked interval bounds after a human
identifies its region and bank; topology is never silently recreated.

`physicalToStatic`, `fileToStatic` return lists (empty = unmapped, multiple =
several views). `staticToPhysical` follows byte aliases and returns identities.
`MapperState.translate(cartridge, state, cpu, write)` reports mapped, unknown,
unmapped or device results. Null mapper state never assumes bank 1. Explicit
state JSON example:

```json
{"romLow":1,"romHigh":0,"mode":0,"ramSelect":0,"ramEnabled":false,"vbk":0,"svbk":1,"latch":0}
```

Writes in the ROM CPU range are cartridge control/ignored bus operations, not
ROM patches. I/O and RTC selections are device results. Encoded `LD (nn),A` and
`LD (nn),SP` now carry direct-write hooks. Program-aware injection lowers proven
non-RAW cartridge controls to visible bus operations and ordinary/RAW writes to
STOREs; a byte-mapped ROM view alone never redirects them. Analysis consumes the
same hooks and only adds justified supplemental references. Indirect p-code and
dynamic banking remain separate unresolved mechanisms. References do not rewrite
those operations. See [direct bus semantics](direct-bus-semantics.md) for scope,
legacy metadata activation, RAW policy and bounded validation helpers.

The present schema is a snapshot, not a live protocol. Space names can change;
regenerate snapshots after renaming or editing topology. Stable physical ROM
identity is reconstructed from actual sources, not exported display strings.
Multilevel/custom byte mapping and manually detached ROM blocks require review;
not every arbitrary third-party topology is reconstructible.


Schema v2 includes typed cartridge/header/geometry/support states, structured
request provenance (requested/selected mode, mapper override/selection, hardware
and its source), physical/source ranges with permissions and alias relationships,
and explicit known-unmapped original file intervals. Unknown, RAW-only and device
states are not converted to mapped certainty. Deterministic sorting is separate
from display names, which are not stable identities.

MapperTopology derives execution aliases from the mapper's reachable windows.
Every supported reachable ROM/window pair has a shared-byte view. Unsupported
wiring stays explicit; the loader does not duplicate storage to invent views.
Existing annotated legacy Programs are enhanced with metadata, never automatically
rebuilt to match new-import topology. Exact static endpoints use the Program's
actual overlay space, including end markers beyond its initialized extent.

Original export reads immutable FileBytes; current export starts with those bytes
and overlays established patches. Known-unmapped tails remain intact. Lost,
conflicting or detached sources produce explicit rejection rather than being
mistaken for a known-unmapped interval. Mapping schema versioning is independent
of SLEIGH language versioning. P-code-only changes do not by themselves require
a version change; the stock transport context schema now requires language 2.0.


Software-call model, preview, executable registry and ownership identities are
versioned independently from mapping and language compatibility. The earlier
preview-only receipt remains historical; the production identities follow.

The production software-call candidate adds registry, injection, effect and
execution-view version identities without changing the physical mapping schema,
SLEIGH constructors, CPU pointer widths or compiler IDs. Template/preview version
3 admits validated bus-ordered banked inline payloads; the bounded engine identity advances to
`20260907-sa01-canonical` so old previews require recomputation. Ownership
envelope 4 reads earlier envelopes conservatively and adds explicit payload,
helper/target, body, site and execution-view receipts. Old receipts do not acquire
new destructive ownership merely by being loaded.

Generated executable annotations are checked as vetoes and are not callee proof.
Raw source, mapper metadata, context, relevant native contracts and registry
configuration participate in invalidation. Unrelated discoveries must not make
an otherwise unchanged executable contract stale. Shared execution views retain
canonical byte backing and require reviewed application/removal; edits prevent
unsafe removal. The new source receipt tracks separate-process qualification.

Registry version 4 includes the complete discovered native-function dependency
set, and effect version 4 separates raw completion from native compatibility.
Clean execution-view removal retires real shared mappings as non-executable
rather than deleting their address spaces beneath queued analysis tasks. This
retention is explicit Program metadata, not duplicate initialized storage.


Current software-call qualification is incomplete. Canonical root decompilation now
uses installed callfixup continuation lowering; alias decompilation uses the shared
mapped listing. Registry v4 records canonical and execution identities together,
and either path requires both live receipts. Injection v3 lowers the validated
finite tail using local p-code edges and architectural RET stack operations.
Execution-view v2 validates every fetched byte's immutable physical source.
The current registry7 integration replaces that historical CALL_RETURN boundary
with an owned self-fallthrough and ordinary CALL flow. The complete injected graph
exits before this bounded decoding edge; the edge describes native transport, not
an architectural loop. A terminal one-instruction CALL otherwise triggers stock
thunk recognition and incorrectly inherits the helper contract. No signature or
parameter lock is invented. No cross-space canonical fallthrough is installed. Native p-code locations for
the lowered tail identify the canonical software-call site; the reviewed physical
segment inventory and execution alias retain original instruction locations.

Registry v3 and earlier executable records are rejected. Remove their owned
software-call annotations with the public removal action, preview again, and
reapply under the new provider; do not reinterpret an old saved digest as v4.
Ownership envelope 4 remains readable with conservative edit-preserving removal.
The public preview JSON is an object containing `sites`, `nestedRepairs`, and
`executionViews`; the saved review inventory contains sites and nested repairs.
Matched ordinary RET witnesses authorize only the exact nested CALL_RETURN and
noReturn repair, with original/applied metadata exposed before mutation.

The current source evidence is `docs/evidence/sa01-resume-20260907/`. General
same-CPU multiple-bank paths, later calls/mapper-changing continuations and full
original SA-01/SA-02 qualification remain open. Earlier failed receipts remain
historical evidence for their exact artifacts.

Normal parallel analysis may change the Program during a callback. Both installed
payloads now retry the entire proof at most sixteen times only after a modification
number change; stable stale inputs and exhausted retries still fail. Neutral
may-return implementation token advances to 2. No partial proof is reused.

View ownership stamp policy 3 treats an unedited decoder DEFAULT DATA reference
to its actual operand as equivalent to its automatic READ/WRITE refinement.
Arbitrary DEFAULT references and user/imported annotations remain protected.
Older view-stamp receipts do not gain new cleanup authority: unmatched old views
are retained conservatively during removal and can require a reviewed migration.

Canonical continuation instruction entries have stable scratch COPY anchors.
Local branches therefore survive nested native CALLOTHER replacement, which can
delete the original target sequence number. Injection v3 and explicit public
`canonicalTransport`/`appliedCanonicalFlow` fields identify this representation.
Architectural return classification, original raw pushes, and function bodies
remain separate from the canonical expansion's terminal listing override.

### Experimental stock execution entries

The stock transport uses default-off, nonflowing context and a bounded CALLOTHER
entry in an explicitly owned analysis view. Canonical source instructions remain
hardware instructions. Ordinary, predicate, configured-domain and exact software
adapters retain separate stock authority keys, with transport version 2 and no
native-identity substitution. A late straight-line integrity guard rejects the
demonstrated carrier-mode-removal failure without emitting CPU or memory effects.
Image carriers map the admitted snapshot in a separate view without establishing
a new generation. See the [decision and compatibility limits](decisions/stock-ghidra-transport.md).

Language 2.0, current-format headless persistence and specific native witnesses
are qualified only as recorded. Normal-window behavior, the full retained test
transition and switch obligations remain incomplete. Old annotated-Program
migration is not qualified; Ghidra can attempt an in-memory language update even
when it logs a missing old-language specification.

### Historical companion-based state-sensitive execution contexts

The state-qualified software-call path keeps language `SM83:LE:16:default` 1.0,
all decoder constructors and register widths, existing compiler IDs and mapping
schema unchanged. It adds the optional explicit `__ghidraboy_state_entry_v1`
prototype; default calling conventions retain their prior storage rules.
The built candidate uses registry/effects 5. Current source advances registry to
6 for caller-body/prototype dependency coverage; it is not yet fully qualified.
Ownership envelope 5 adds independently stamped
context convention/comment receipts. Prior ownership records retain conservative
removal policy. Executable older registries require public remove/review/reapply.

Multiple callee contexts retain separate shared-byte aliases. Proved calls use
the matching alias; canonical Decompiler selection is a visible, persisted
conditional analysis view, not a universal prototype or a mapper reset. The
optional pre-flow native companion is fingerprinted separately from the preceding
switch companion. Rooted discovery and terminal/nonlocal graph behavior remain
subject to the exact input assumptions and qualification scope in the current
source evidence receipt. Wider mapper, RAM-image, interrupt and all-input claims
are not implied by these interfaces.
