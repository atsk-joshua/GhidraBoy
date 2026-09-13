# Effectful call continuation: partial implementation

The requested effectful software-call capability remains unfinished. The current
change resolves a physical-read lowering defect and strengthens native effect
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

## Remaining obligations

The symbolic conditional mapper/shadow/SP domain, source-derived helper and
callee composition, real frame/data alias proof, live returned flags/registers,
linked continuation load, nonconstant sibling and cost measurements are still
required. Owned private application, preservation inventories, cancellation,
stale/refresh/current-record reopen, Linux effectful witness and normal-window
navigation remain unrun. These are in-scope implementation obligations, not
out-of-scope refusals or completed roadmap items.
