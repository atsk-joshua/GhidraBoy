# Limitations

- This is not whole-ROM completeness or a stable release.
- Unknown mapper, pointer, RAM, device, interrupt/DMA and exhausted-bound cases stay
  unknown or incomplete.
- Absent SRAM banks are not created. OAM, I/O and IE remain device/unresolved regions.
- Automatic universal RST/software-call and canonical JumpTable heuristics are not
  enabled.
- A source-compatible language-v1 provider is required for the pre-upgrade snapshot.
- An upgraded Program is not approved for downgrade into the old provider.
- Actual intended Linux/Steam Deck headed acceptance is candidate-specific and must
  be recorded separately.
