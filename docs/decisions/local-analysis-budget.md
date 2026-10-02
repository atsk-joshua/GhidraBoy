# Qualified local invocation resource budget

LOCAL-STATE-3 raises only the ordinary per-invocation instruction-state evaluation
limit from 128 to 179. This is an internal bounded analysis resource guard,
independent of Game Boy hardware and finite-loop semantics. Each local evaluation
also consumes the configured session budget; nested invocations retain separate
local counts and share the session count. No headroom is added.

The separately qualified LOCAL-STATE-2 diagnostic establishes 179 as the minimum
for its bounded source-derived witness: 178 refuses its final return, while 180
and 192 yield the same preview as 179. Self-authored straight-line fixtures
independently qualify completion through 179 evaluations and refusal before the
180th evaluation. Exact four/eight-iteration loops and the existing stable-cycle,
unknown-counter, recursion, global exhaustion, cancellation and widening controls
remain acceptance requirements.

## Compatibility decision

Engine `20261002-local-state-3` replaces `20261002-local-loop-1` because the larger
resource allowance can issue ordinary CALL proofs previously unavailable.
Schema remains 4: no persisted record or fingerprint shape changes. Prior results
and proofs require recomputation and cannot authorize apply or stock publication.
Known obsolete owned physical flow retains retirement/restoration authority only;
current recomputed authority may publish under the existing
[stock-flow lifecycle](ordinary-call-stock-flow.md). Packed save/reopen must retain
these currentness rules.

Retaining 128 would preserve a demonstrated resource-only refusal. Increasing
beyond 179 has no qualified capability benefit in this task. Loop predicates,
partial flags, JoinKey cycle admission, 32-key widening, active depth three,
recursion, cancellation and configured global budgets are unchanged, including
the 20,000-state replay budget. No device exception is added.

## Qualification limits

The external `LOCAL-STATE-3-20261002` batch records focused checks and the unseeded
public witness. A successful invocation remains insufficient for certificate
emission when later session exploration is incomplete. Timer effects and broader
workflow/aggregate qualification remain separate obligations; WUX-1B is not begun.
This intermediate candidate does not qualify arbitrary loops, whole-ROM
completeness, installations or releases. Detailed receipts remain outside source.
