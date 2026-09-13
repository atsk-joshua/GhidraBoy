# Public operation lifecycle

The public Tools wrapper previously treated a mutator return as a navigation
boundary although GhidraScript still owned an open transaction. The real wrapper
probe confirms that runCommand(BackgroundCommand) invokes directly and returns
while an outer owner remains pending.

Use the supported script analysis mode and explicit caller participation, retaining
the actual outer TransactionInfo for asynchronous reconciliation. A BackgroundCommand
class alone, transaction description, checkout access flag, or local mutex cannot
prove an outer commit or universal exclusion. The submission gate covers cooperating
Tools requests only; AutoAnalysisManager coordinates its supported analysis population.

Publication uses the validated source revision plus a consumer-local generation and
actual activation/close events. Session identities stay in runtime handles, not
Program options or proof hashes. Pre-commit cancellation follows agreed whole-owner
rollback; post-commit cancellation never calls Undo. Removal keeps incumbent edited
artifact and retired-carrier policy. An early observer that read an absent option
with a null default registered a phantom option in Ghidra's cache; existence checks
before reads correct that observer bug without changing persisted meaning.

No language, constructor, register, compiler, mapping, image, ownership or proof
schema changes are made. Alternatives rejected are closing an unknown outer handle,
waiting inside the caller for its own commit, blanket scripted refusal, replacing
the decompiler, suppressing analysis events, and serializing job/request identities.
The supported contract and route inventory are in [public operations](../public-operations.md).

Headless public integration and installed native/reopen checks are distinct from
visible CodeBrowser qualification. The external PUBLIC-OPERATIONS-LIFECYCLE report
records exact candidates and dispositions. Pending desktop/service rows cannot be
promoted by this decision. Forward compatibility, broader callers, hardware/schema,
package and installation recovery gates remain open; no release approval follows.
