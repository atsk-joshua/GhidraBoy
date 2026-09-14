# Public operations in the normal tool

The attended lifecycle rehearsal exposed two differences from direct headless
script execution: ordinary analysis timing writes can advance the Program
revision before an explanation's owner finishes, and Script Manager's task
monitor can be cancelled when its progress dialog is disposed after completion.

## Decisions

An explanation whose revision changed before owner completion is revalidated
against the exact retained registration. Its source Program, entry, boundaries
and explanation text must be identical. The existing dependency validator must
still succeed. Only this equivalent result receives the checked revision for
publication; a subsequent revision change still suppresses publication.

The wrapper retains cancellation observed by its worker and submission monitors.
At cleanup it switches from the transient joint analysis monitor to the original
submission monitor before voting on its transaction. Cancellation is never
cleared or ignored because a monitor was disposed.

For a standalone suspended request with a wrapping task monitor in a real tool,
the submitting task waits boundedly for deferred presentation after releasing
its vote and gate and completing its state update. It runs outside the EDT and
the tool's background task thread. The analysis owner can finish independently.
Explicit owner participation remains inline and provisional; it never waits
for its own owner. Direct persistent caller monitors retain late cancellation.
Cancellation listeners are released before presentation completion and included
in the runtime resource inventory.

## Alternatives and limits

Ignoring analysis timing events globally would weaken source currentness.
Replacing the retained registration with a newly discovered registration would
allow a different operation's authority to certify this result. Neither is used.

Changing read scripts to disabled analysis would not avoid Ghidra's outer timing
persistence and would change event handling. Instead, unchanged-Program ordering
tests save a disposable Program before establishing their baseline and verify
that it is non-temporary and clean. They never save between the two requests.

Inferring monitor retirement from its implementation class would conflate normal
task disposal with real caller cancellation. The bounded submitting-task wait
keeps cancellation live. A wrapping monitor selects conservative waiting
behavior; its type is not proof of Script Manager provenance.

No language, compiler ID, mapping schema, persisted authority, native binary or
hardware premise changes. No migration is required. Save/reopen, actual chooser,
tool ownership, native-window and preservation qualification remain obligations
of each changed executable candidate. The external lifecycle report records the
executed scope; lifecycle acceptance is not release or installation approval.
