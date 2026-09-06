# Captured observations and controlled repeat

Open a matching Program and debugger trace, then open **Window → GBC History**.
Select a captured write to inspect its physical target, attempted value, final
byte and writer. **Go to writer** selects the original snapshot and static source
location in read-only Trace mode. **Bookmark observation** preserves an existing
note and adds the captured evidence; a writer is not automatically a caller.

The history filter accepts literal text and exact fields such as
`region:wram bank:3 offset:0x34 epoch:0 access:write`. A bank filter compares the
physical bank number, so bank 1 does not match bank 10. Clear the filter to see
all available events again.

Choose a physical region, bank, offset and length under **Capture range**.
**Pin capture** retains the selected observation. Move to another capture and use
**Compare capture** to see changed known bytes, unknown bytes, registers and
different source/settings. Selecting history does not rewind the emulator.

**Export capture** writes a bounded JSON report. **Reopen observation** validates
its format and content hash and pins it for comparison without starting an
emulator. The report retains exact capture/source references and optional ROM,
boot, model and timing identity. Missing legacy values stay unknown. The hash
detects changed content; it does not authenticate an author. Current Program
binding is not inferred from an old stored mapping.

CPU bytes are recorded at stops; immutable ROM-bank data written only at trace
initialization can have UNKNOWN state at a later snapshot. Use the captured CPU
window and its exact static mapping/bank metadata when inspecting an executed
instruction. Reports do not substitute older bytes for an unknown current byte.

For controlled repeat, use a backend that advertises checkpoints, record the
exact ROM/boot/model/clock, input sequence and operations, and retain the original
checkpoint with its manifest. Restore into the same compatible backend, repeat
the recorded operations, and compare results and interval deltas. Session counters
remain monotonic across restore; compare the appropriate before/after intervals.
An observation file alone contains no emulator state or replay recipe. mGBA's
current experimental tier deliberately rejects checkpoint/replay operations.

The combined package's `bash scripts/test_research_experiment.sh` reproduces the
self-authored fixture recipe: remove the setup breakpoint, checkpoint at ROM
bank 1 offset 0x29, execute the recorded instruction, restore/repeat, and verify
registers, source-mapped bytes and interval timing. It writes four observations
and an explicit recipe, then checks them in a separate Java process. This is a
regression/operational reference, not an assumption about an arbitrary game.

Long report operations run in the background. **Cancel** stops the pending work;
malformed files report an error while existing trace controls remain usable.
