# Cartridge and boot policy

Automatic recognition remains strong: standard logo digest or known boot hashes.
It does not claim arbitrary binaries. The loader and `GhidraBoyImport.java` provide
explicit manual selection. CARTRIDGE uses strict validation; SALVAGE is a deliberate
byte-preserving policy for incomplete/trailing/nonstandard inputs.

Strict cartridge input requires 2..512 complete 16 KiB banks (32 KiB..8 MiB).
Partial banks, short headers, trailing bytes and unsupported size codes are
rejected. Complete declared/actual bank mismatches load with warnings and actual
geometry. Manual import can retain bad checksums and nonstandard logos; no import
path silently repairs checksums, truncates or pads bytes.

Salvage retains immutable original FileBytes in full, up to 16 MiB. The descriptor
separates actual, declared, addressable and trailing ranges. Only established
complete physical banks, up to the 8 MiB addressable limit, are mapped. Incomplete
headers and unknown/truncated geometry remain explicitly RAW; a mapper request
does not create certainty from an unsupported size code. Unmapped original bytes
survive both original and current export. Checksum repair requires an established
header and extent, and always writes a new destination.

Supported ordinary topology: ROM-only (including RAM types), MBC1, MBC2, MBC3,
MBC5. Capabilities and contradictory RAM/type geometry are checked. MBC2 has 512
mirrored nibble entries independent of the RAM header; static bytes do not enforce
hardware nibble masks. MBC5 has nine ROM bits, bank zero and rumble RAM limits.
Ordinary-MBC3 RTC selection/latch intent is represented without clock evolution.
VBK/SVBK are explicit; SVBK zero selects one. Mapper-reachable low/upper ROM views
share backing bytes, including upper bank zero for small MBC1/MBC2/MBC3 images.

MBC1M, MBC30 and exotic wiring are unsupported; ordinary MBC1 is an explicit
assumption, not automatic MBC1M detection. Excess/unknown capability is RAW.
Historical codes 0x52/53/54 and RAM 0x01 retain compatibility geometry but do not
establish non-power-of-two wiring. See static-contract.md for support statuses.

CGB boot is exactly 0x900 bytes with the unmapped 0x100..0x1ff hole; DMG boot is
0x100. Original bytes include the hole. Boot code is readable/executable, with no
fabricated cartridge header. Header global checksum uses a per-instance big-endian
two-byte type at 0x14e; the asymmetric checksum survives save/reopen.

Loads are transactional and cancellable; required hardware allocation failures
abort. Existing Programs cannot be overwritten by the mapping loader. Legacy
inspection is read-only; enhancement preserves known historical hardware and
reports unknown choices. Explicit RAM identification checks conflicts. Annotated
topology is never silently rebuilt.
