# Native CGB device regression evidence

`debugger/tests/test_cgb_devices.py` builds complete self-authored CGB-only MBC5
fixtures using the existing redistributable cartridge header and boot input.
The tests explicitly confirm actual CGB-E hardware in CGB mode after boot.

Expectations follow [Pan Docs CGB registers at fe246067](https://github.com/gbdev/pandocs/blob/fe246067b695b5404a4a6a47efb4fd6d921ececb/src/CGB_Registers.md), retrieved 2026-09-06;
source SHA256 `df0c3b0885b5ee0b8068c88979dcfe65ff45d209023307d6014cebc74a005f9b`.
These are published expectations and emulator observations, not new physical
hardware measurements.

The KEY1/STOP case checks speed selection/arming, the first following physical
breakpoint, and normal/double-speed NOP intervals in the declared 8 MHz units.
It exposed the missed wake breakpoint; the [wake-boundary correction](sameboy-wake-notes.md)
passes the unchanged reproducer and separate timing/state preservation checks.

General and HBlank DMA cases copy an explicit 32-byte pattern into VRAM bank 1,
exercise source/destination low-bit masking and completed transfer status, and
verify that physical writes are not falsely attributed to a CPU watch. The
HBlank case begins in OAM mode and keeps executing while awaiting completion.
Both cases preserve zero reported event losses.

The final two-test run passes. Exact whole-core pristine comparison and source
hashes are recorded in the wake notes. This covers device effects and stated
observation boundaries, not exhaustive PPU/APU behavior or exact DMA/speed-switch
stall timing. Cross-backend timing differences remain separately classified.
