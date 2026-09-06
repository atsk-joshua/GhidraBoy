# Candidate support and limits

The integration candidate uses Ghidra 12.1.3, Java 21 and existing Python 3.9+.
Packages identify exact source, dependency and binary hashes. The static SM83
provider remains usable without Python, SDL or an emulator. Generic trace history
and portable observation reports can be reopened without the original backend.

| Capability | SameBoy reference backend | mGBA experimental backend |
| --- | --- | --- |
| Hardware | DMG-B; CGB-E in native or DMG compatibility mode | Native CGB; no silicon revision claim |
| Boot | Matching redistributable DMG/CGB image, exact hash recorded | Engine post-boot initialization; no BIOS, explicitly recorded |
| Mappers | ROM-only, MBC1, MBC2, MBC3, MBC5 verified geometries | CGB MBC5 types 19–1B; no rumble |
| Execution | Step, pause/resume, bank-qualified breakpoints, ordinary over/out | Step/pause/resume and CPU/ROM execution breakpoints |
| Observation | Private stopped-state CPU inspection, copied physical banks | Copied physical banks; PPU/DMA CPU lockouts and IO/IE remain unknown |
| Research operations | CPU-origin watches, checkpoints, recoverable paused experiment edits | Physical capture, input/video; watches, checkpoints, edits and over/out rejected |
| Saved work | Legacy CGB schema-2 readers plus current engine-specific states | Backend-neutral recorded observations; no checkpoint resume capability |

SameBoy MBC2 exposes 512 low-nibble storage cells; mirrored CPU reads retain their
high nibble. RTC/device selections and unsupported geometries remain explicit.
Core-detected controller changes are rejected: a header that the engine
reinterprets as a different mapper is not reported as the header's mapper.
This includes ambiguous 32 KiB type-11 MBC3 images detected as MMM01 and oversized
ROM-only images. Multicart wiring is not qualified by ordinary mapper tests.
Watches distinguish attempted CPU accesses from final instruction-boundary bytes;
DMA/HDMA writer attribution and per-access commit timing are not claimed.

Timing is engine-reported. Cross-backend defined CPU/RAM fixtures agree, but
speed-switch intervals differ and must not be treated as interchangeable hardware
measurements. SameBoy counts retired opcodes; mGBA reports execution boundaries,
including interrupt dispatch, and leaves retired instruction count unavailable.
Report comparison retains differing model/boot/configuration and unknown values.

Both runtimes can be installed independently or together. macOS arm64 and Linux
x86-64 have separate qualification receipts. Linux container/Xvfb checks are
emulated/virtual-display evidence. The user deferred physical Steam Deck
verification until other work is solid; no Deck or Windows acceptance is claimed.
See the repository integration ledger for the actual qualified artifact tuple.

No audio-output workflow, reverse execution, portable emulator-state conversion,
battery-save import, complete reconstructed stack or inferred game-specific far
calls are included. Observation reports preserve evidence and hypotheses separately;
they do not make an access event proof of a caller or formula. Controlled repeat
uses a compatible engine checkpoint and an explicit experiment recipe.

Compatible old SameBoy CGB checkpoints remain readable. New checkpoints stopped
at the pending pre-fetch boundary require the new reader; do not downgrade them
to an older runtime. Keep original state files and distributions for rollback.
Publication and repository archival remain separate explicit actions.
