# Configured-domain dependency identity

The configured-domain save/reopen failure was reproduced using the unchanged
`far-call-review-v2` field algorithm with an opt-in sink inside its production
traversal. The stored registration, immediately-before-save capture and first
reopened `currentRecord` check retain the exact sorted JSON UTF-8 bytes, duplicate
fields, digest, component hashes and call stack. No preliminary reopened capture
or inventory precedes that check.

The complete original diff contains six dynamic-symbol numeric IDs. Every other
field matches, including stored symbols, references and bindings, Functions,
thunks, parameters, contexts, data definitions/settings/comments, ownership,
convention and block permissions. All eight ProgramFingerprint components also
match. Registration and pre-save bytes are identical. See the current external
batch through the [evidence index](../sa/evidence-index.json).

Pinned Ghidra 12.1.3 `SymbolManager` creates a standalone `AddressMapImpl(0x40, ...)`
for dynamic symbols. AddressMapImpl assigns address-space/base indices in first
observation order and incorporates them into IDs. Fresh domain aliases and
physical ROM spaces are observed in different orders after reopen. These
symbols have no stored database record; their process-local IDs are not durable
ownership. This explanation is independently tested by reversing allocation
order while retaining every semantic symbol descriptor and Program identity.

## Correction and preserved dependencies

`far-call-review-v3` replaces only dynamic-symbol numeric IDs with the literal
`dynamic`. It retains address-space-qualified address, qualified name, source
and pinned state. Stored-symbol IDs and all reference, Function, thunk and
parameter-associated IDs retain their existing meaning. Ghidra reference
associations accept stored labels, so reference binding IDs remain unchanged;
rebinding a reference between two labels at the same address still invalidates
installed domain authority. No context or data normalization is justified by
the evidence and none is applied.

Both capture variants retain their ownership/category behavior. All seven
production consumers remain guarded: FarCallConvention, SoftwareCallApplication,
SoftwareCallValidation, SoftwareCallInstructionDiscovery, SoftwareCallExecutionView,
SoftwareCallEffects and SoftwareCallDomains. Unchanged-state acceptance requires
complete production preimage equality as well as proof, view and native checks.
The opt-in diagnostic directory system property does not change hash inputs;
diagnostic metadata and process identities are outside the preimage.

## Compatibility

A changed digest meaning is an incompatible experimental authority even when
JSON keys are unchanged. Configured-domain records and proofs therefore advance
from `software-call-domains-1` to `software-call-domains-2`. The existing version
guard rejects v1 before dependency comparison, proof rederivation or emitted
semantic use. No old record is overwritten or reblessed. Fresh explicit reviewed
creation under v2 is required; general annotation migration and G4 remain open.

Other FarCallEvidence consumers use revalidated transient previews. The v3 hash
tag rejects old preview digests; their independent version constants remain
unchanged. SoftwareCallRegistry computes its own persisted semantic dependencies,
so its registry version is unchanged. Native, SLEIGH, mapping/public schema,
compiler and language identities are unchanged.

Replacing the whole dependency model with ProgramFingerprint, discarding stored
identity, normalizing reference bindings, prewarming reopened Programs or
refreshing saved registrations would lose required authority or conceal the
failure. None is part of this correction. This bounded repair does not establish
whole-ROM completeness or general migration compatibility.
