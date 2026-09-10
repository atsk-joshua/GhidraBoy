# Configured-domain discovery traversal

`SoftwareCallDomains.preview` traverses configurations in ascending existing
domain-ID order before accumulating rooted discovery. IDs still include Program
identity, physical site and configuration. Canonical order is local to a Program;
different Programs need not order the corresponding configurations alike.

The fresh REPO-CUTOVER-DOMAIN-FIX reproduction supplied the reverse of the order
returned by an initial read-only preview. On the uncorrected provider, domain
semantics matched but actual installation rejected the complete discovery Plan.
The original and rederived plans contained the same complete candidate records
in different orders. The first difference was candidate 4's address. Dependencies
and ordered reservations matched. Neither preview nor refusal changed the fresh,
undisassembled Program. Exact identities and structural differences live in the
external run linked from the [evidence index](../sa/evidence-index.json).

Previously discovery followed caller order, while returned domains were sorted
afterward. Initial installation rederived discovery from those returned domains,
so a Program whose domain IDs reversed the caller order could reject its own
proof. Moving canonical traversal before discovery makes both executions consume
the same roots in the same order, retaining first-discovery provenance as well as
bytes, physical identities, annotations and reservations.

Shared `SoftwareCallInstructionDiscovery.Plan` equality is unchanged. Removing
its guard, comparing only candidate sets, or pre-disassembling the fixture would
hide the failed authority check. Changing domain IDs would lose the existing
Program identity contract. These alternatives were rejected.

## Record compatibility

The private registration continues to store `version`, `programId`,
`configurations`, `semantics`, `views`, `dependencies` and `nativeIdentity`.
Discovery Plans are transient and are not serialized in the registration.
Current-record validation rederives the stored configurations and compares
canonical semantic authority; no persisted field changes meaning. Therefore
`software-call-domains-1` remains the version, with no migration or interpretation
of earlier incompatible formats. The local regression checks the field inventory
and rederivation from both stored configuration orders. Installed acceptance
checks the same saved registration in a separate read-only process.

The deterministic regression compares complete nonempty Plans before installation,
then exercises each caller order with rollback and a fresh proof from verified
pristine state. A changed candidate byte must reach the retained discovery guard
with all other proof authority unchanged. Existing request/display reversal,
wrong-domain, foreign-Program and stale-proof controls remain required.

This correction does not change native code, SLEIGH, public schemas, discovery
equality, or the broader W3/W4/G3/G4 qualification boundaries. It closes only the
demonstrated configured-domain revalidation defect. Historical failed evidence
remains immutable; source retirement and independent backup are separate from
installed validation.

## Execution limit discovered during repair

The unchanged v1 registration fields passed local tests, but actual installed
save/reopen refused both fixed Programs at the existing dependency guard before
rederivation. Identical serialized registration does not establish operational
compatibility. Public ProgramFingerprint components match in the instrumented
second Program; the additional FarCallEvidence discrepancy remains unlocalized.
No format change or shared fingerprint repair is justified by this evidence.
Current saved-domain acceptance remains blocked; see the linked status/evidence
index for the preserved failures.
