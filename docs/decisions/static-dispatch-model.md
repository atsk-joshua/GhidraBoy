# Bounded finite dispatch on stock Ghidra

The W3 qualified graph now admits source-derived finite indirect jumps. It retains
`AbstractValues`, `ScalarAccess`, rooted instruction discovery, symbolic memory,
relative stack effects and the existing stock CALLOTHER carrier. This is neither
an upstream switch-recovery fix nor completion of W3/W4 or stock release qualification.

## Authority and lowering

A proof relates explicit entry inputs and an ordered path predicate to immutable
physical byte reads, a computed 16-bit destination, a mapper-qualified executable
successor and its live state. Reads retain operation/operand, CPU pointer origin,
mapper, width, ordered physical source bytes and predicates. Graph identity includes
saved stack bytes; original outer-return bytes must survive to an ordinary return.
A source body does not establish the set of possible indirect destinations.
Finite jumps are currently limited to acyclic root graphs; indirect callees and
cyclic dispatch remain frontiers. Incumbent ordinary-call/cyclic families retain
their separate domains.
Discovery follows actual proved edges, including discontiguous and banked ROM.

Structural relations evaluate guards before partial lookups. Missing feasible rows,
unknown mutable table dependencies and exhausted work budgets remain unresolved.
The zero singleton is distinct from an empty domain. Constants use the incumbent
fold; graph-only reconstruction of unchanged byte slices preserves their original
word provenance without changing other entry producers' representation.

Within each distinct physical/state node, lowering preserves computation and emits
ordinary local comparisons and BRANCH/CBRANCH edges. Temporary comparisons use
unique storage, not architectural flags. The last edge follows only from complete
coverage of that node's declared domain. Immutable reads retain physical LOAD
storage; a CPU offset does not select a bank. A JP never creates a hardware call
frame. Diagnostic emitted intervals connect requested operations to source nodes.

## Premises and compatibility

The memory declaration permits ordinary synchronous HRAM FF80..FFFE as well as the
existing disjoint fixed WRAM0 range. Storage must have a checked physical binding;
loader fill is not a known input value. An optional checked constant HL must point
to a declared mutable input cell. Its byte remains unknown. PUSH/POP support is
limited to HL through the existing affine, disjoint relative stack model. The HL
premise uses entry SP C802..CFFC; ordinary memory graphs retain their existing
C800..CFFC range. Neither arbitrary stack aliasing nor asynchronous writers are admitted.

An explicit custom source result may expose byte A or word HL with no custom
parameters. Its type, width and register storage are bound in the proof and checked
against both source and qualified Functions. It does not create a new compiler ID.

Graph authority is `predicated-ordinary-graph-5`; stock registration is
`stock-predicated-ordinary-calls-3`; legacy comparison registration is
`predicated-ordinary-calls-5`. Earlier records are rejected before interpretation,
without conversion. Stock transport, language 2.0, SLEIGH, physical mapping schema,
core and dependencies are unchanged. Historical acceptance remains attached to
its original artifacts; the targeted prior-record negative is not a migration campaign.

## Lifecycle and ownership

The shipped Tools script exposes explicit premise preview, reviewed apply, refresh
and removal. Native emission is read-only and rejects consumed dependency changes;
it does not reprove and replace a registration automatically. Explicit stock refresh
may update source segments after a changed finite relation while preserving the
one-byte carrier and invocation/domain identity. Legacy mapped-fragment refresh
retains its stricter topology condition.

Global dependency fingerprints are conservative: unrelated edits may require
explicit refresh. Registration contains the existing Function/view ownership receipts. Removal uses
the incumbent edit-preserving undo helper and retains canonical source listing.
Later user edits survive. Carrier storage retains its identity on retirement so
export cannot confuse it with cartridge bytes. Application and removal are
transactional and cancellable after real writes.

## Verification scope

The self-authored normalized fixture retains the actual unknown FF80 input,
phase/lookup computation and zero default. The nibble fixture retains 128 physical
table entries, the high-nibble/stride relation, second input read, real PUSH/POP HL,
output store and outer RET. Production envelope changes are explicit in the fixture
manifest; code occupying the logo area uses explicit cartridge loading.

Native terminal physical provenance checks use requested source intervals and retained stock operation
sequence provenance, together with complete input replay and actual native CFG
captures. The bounded witnesses have distinct handler RET instructions; this is not arbitrary native CFG equivalence. These checks are separate from target-set and observable-result checks. Exact
artifact results, failed attempts, limits, proof/work sizes, platforms and remaining
obligations are recorded in the STOCK-FINITE-DISPATCH report and evidence index.
Canonical automatic recovery and public JumpTable overrides remain separate,
unsafe diagnostics for the retained counterexamples.
