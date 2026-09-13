# Effectful call continuation

The initial revision left the requested effectful software-call capability unfinished.
That change resolves a physical-read lowering defect and strengthens native effect
checking; neither is qualification of symbolic software frames or a returned
state linked to a continuation.

## Observed boundaries

An actual read-only request on a preserved annotated Program reached the strict
software-call JSON boundary. Symbolic SP was rejected because the exact template
API requires an integer. No concrete register/SP stand-ins were supplied. The
symbolic public comparison encountered absent cartridge authority before graph
construction. That null-pointer failure now has an explicit diagnostic. Saved
bytes do not implicitly establish mapper or RAM identity.

The existing predicate engine owns symbolic register values, affine SP, frame
bytes and memory effects. Its current ordinary-call and native byte-A contracts
do not implement the requested helper. A conditional site mode must pair checked
input/mapping/frame changes with an effectful stock consumer. Source overrides
and canonical saved instructions must remain preserved in an owned view. A slice
boundary cannot supply a fabricated return.

## Physical operand correction

A self-authored two-bank witness selects a bank with a real mapper write, then
reads the same CPU offset directly or indirectly and executes a real RET. The
incumbent native direct form returned an unbound RAM expression for both banks;
its indirect form resolved their distinct bytes. The producer already recorded
the correct physical source for each operation and operand. Lowering now binds
the direct operand using that record and explicitly selects LOAD operand 1.

This repairs the existing byte-read contract; it introduces no new persisted
meaning, graph schema, language, compiler, mapper model or native protocol.
Existing records still undergo complete current-source rederivation and graph
comparison. Missing/ambiguous operand evidence refuses before emission. Old
incompatible records retain their existing quarantine; no migration is claimed.

## Native effect checker

Actual native STORE and address outputs are checked against permitted source
writes, including multiplicity. Non-frame final written storage must remain
observable even if a native write disappears. The finite-dispatch fixture's
explicit two-byte PUSH/POP footprint is the only final-storage exemption.
Raw/emitted ordering is still checked separately; native disjoint reordering and
frame forwarding are allowed. A UNIQUE value associated with a global is not
itself an architectural write. Terminal same-cell SSA COPY exemptions require
operation-time and terminal-position evidence. This bounded oracle does not
qualify arbitrary optimizer transformations or new effectful frames.

## Initial revision remaining obligations

The symbolic conditional mapper/shadow/SP domain, source-derived helper and
callee composition, real frame/data alias proof, live returned flags/registers,
linked continuation load, nonconstant sibling and cost measurements are still
required. Owned private application, preservation inventories, cancellation,
stale/refresh/current-record reopen, Linux effectful witness and normal-window
navigation remain unrun. These are in-scope implementation obligations, not
out-of-scope refusals or completed roadmap items.

## Revision 2: conditional call-site execution

The continuation implements bounded source-derived inlining in the existing
predicate engine. The exact integer software-call API is unchanged. The new
`ConditionalCallSites` adapter supplies a physical instruction site, Program/image
identity, explicit mapper/shadow coherence, symbolic registers with valid F bits,
an affine SP interval and physical footprint, unknown memory inputs, and explicit
boot/interference provenance. It requires no enclosing canonical Function. These
premises participate in derivation, ownership identity and currentness checks.

Architectural traversal uses override-free p-code, parsed instruction lengths,
16-bit CPU arithmetic and actual stack words. CALL/RST/PUSH/POP effects remain
ordered. RET dispatch, callee return, matched cleanup completion and analysis
exit are separate boundaries. Callee registers, flags, memory and residual frame
bytes flow into the actual continuation from the same outgoing state. Saved
flow/noReturn interpretations are preserved and reported, never used as hardware
successors. The generic sibling follows its flag-sensitive continuation through
an actual incoming-word RET. A one-instruction slice instead retains a linked
post-completion explanation; its native view ends at the real cleanup RET.
No source return is fabricated and the unanalysed tail remains explicit.

The existing CALLOTHER carrier lowers proved internal transfers into local graph
edges after their raw frame operations. This avoids the ordinary byte-A native
call contract without replacing it. This is reusable conditional derivation and
bounded faithful inlining, not a reusable interprocedural summary cache or a
universal state engine. Small origin-preserving byte/pair/mask simplifications
are local to this mode. Current limits are an acyclic 256-node graph, two real
CALL/RST transfers and zero or one requested continuation steps (zero means
continue to the proved incoming-word RET). Mapper writes must become exact per
path; current conditional support requires MBC5 with at most 256 ROM banks and
an explicit zero high latch. Unknown/overlapping accesses remain obligations.

The explicit WRAM0 stack interval/footprint allows upper-WRAM data only when
physical data and the entire possible frame union are disjoint. Existing memory
clients retain their old default domain. Checked RAM identification now supports
canonical HRAM through FFFE, excluding IE. Canonical identity does not establish
runtime values; uninitialized backing can carry declared symbolic inputs.
Metadata adoption and binding are separate, reviewed preparation operations.

### Storage oracle and observation contract

Storage checking now runs before reads, writes, SSA-cache hits, INDIRECT and
same-global/forwarding shortcuts. Same-width byte RAM metadata must corroborate
actual space/offset/width. Contradictions are integrity refusals. Unsupported
partial/wide symbol relationships are oracle-insufficient, and legitimate UNIQUE
associations remain temporaries. Retained captures and adversarial variants cover
these distinctions; no metadata can redirect a write.

The conditional checker shares the maintained arithmetic/raw machine and verifies
serialized boundary values against transfer snapshots. Raw/emitted comparison
includes registers, flags, mapper state, ordered accesses and residual stack/scratch
writes. Native checks retain required scratch/data effects and reject collateral
writes. Only the declared borrowed frame's final storage may be optimized away:
its full raw/emitted ledger is retained and its physical union is disjoint from
observed data and continuation inputs. This is not a general frame exemption.

### Compatibility and workflow

Conditional proof meaning is `conditional-call-site-3`, stock registration meaning
is `stock-conditional-call-sites-3`. Earlier experimental conditional versions are
quarantined; there is no automatic migration or relabeling. Ordinary graph and
stock record versions, mapper schema, language 2 and native transport are unchanged.
Full current-source rederivation and comparison bind every premise, boundary and
invocation. Domain-qualified owned names allow separate premises at one source.
Conservative dependencies can stale another view; explicit refresh is required.
Function comments contain stable premises only; current facts come from validated
explanation. Later user edits retain the existing ownership conflict behavior.

Public preview, apply, explain, navigation, refresh and remove use the maintained
script and stock ownership. Qualification covers independently authored carry,
relocated and indirect-alias fixtures, source mutation/native stale refusal,
explicit changed-result refresh, immutable second-JVM use, cancellation after
actual writes, and bounded normal-window navigation. Exact run receipts and the
separate private annex belong to the external continuation evidence, not this
source document. General W3/W4/W5, arbitrary device interference, recursive/looping
helpers, broad annotation repair, migration and release qualification remain open.
