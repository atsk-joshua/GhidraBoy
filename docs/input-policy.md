# Cartridge and boot policy

Automatic detection retains the standard-logo SHA256 and known boot hashes.
It does not claim arbitrary binaries. `GhidraBoyImport.java` gives GUI/headless
manual CARTRIDGE, DMG_BOOT and CGB_BOOT modes, optional mapper override and
explicit hardware selection. The loader also exposes these options.

Header validation happens before database allocation. Current cartridge policy
requires 2..512 complete 16 KiB banks (32 KiB..8 MiB). Short headers, partial
banks, trailing bytes and unchecked size codes are rejected with diagnostics;
no bytes are silently discarded. Complete-bank declared/actual mismatches load
with warnings and actual geometry. Bad checksums and nonstandard logos remain
usable via deliberate manual import. Checksums are reported independently and
never repaired on load. Header global checksum data is big-endian per-instance
without changing its 0x14e offset, two-byte size, or shared integer type.

Codes 0x52/53/54 and RAM 0x01 are accepted as historical compatibility geometry,
not evidence of actual hardware. Non-power-of-two ROM addressing is unresolved.
Supported ordinary topology: ROM-only including RAM types, MBC1, MBC2, MBC3,
MBC5. Unknown/excess geometry is explicitly RAW, with physical ROM import only.
MBC1M is not detected; ordinary MBC1 is an explicit documented assumption.
MBC30 is not modeled. MBC2 allocates 512 mirrored entries, independent of the
header RAM-size field; static memory bytes do not enforce hardware low-nibble
write masks or high-nibble read values. MBC3 RTC selection/latch intent is
represented, without clock evolution. MBC5 bank zero, ninth ROM bit and rumble
RAM masking are handled. VBK/SVBK have explicit state; SVBK zero selects one.

CGB boot images are exactly 0x900 bytes including the unmapped 0x100..0x1ff hole;
DMG images exactly 0x100. FileBytes preserve the hole for export. Boot code is
readable/executable, with no fabricated cartridge-header data.

Load is transactional and cancellable, required hardware-block failures abort,
and existing programs cannot be overwritten by calling the mapping loader.
Legacy inspection is read-only; explicit enhancement only adds metadata and
reports unresolved RAM instead of recreating overlays.
