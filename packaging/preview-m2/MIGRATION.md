# Legacy migration

Stock Ghidra upgrades SM83 language-v1 Programs by redisassembling before any
supported extension callback can capture old reference-primary state. Migration is
therefore an outer, one-command operation.

Keep the source GZF immutable. Provide two disposable Ghidra 12.1.3 copies: one with
the source-compatible language-v1 provider and one with this M2 extension. Then run:

```sh
python3 migration/migrate_legacy_program.py \
  --source /absolute/original-copy.gzf \
  --output /absolute/new-migrated.gzf \
  --legacy-ghidra /absolute/ghidra-v1-copy \
  --ghidra /absolute/ghidra-m2-copy \
  --scripts /absolute/extracted-preview/migration/scripts \
  --work /absolute/new-migration-work
```

The launcher refuses existing output/work paths, makes a byte-identical input copy,
captures every USER_DEFINED reference and primary boolean, copies the project,
performs the supported upgrade, restores only primary state after exact preflight,
prepares recognized legacy topology, writes a new GZF, and verifies a separate
process reopen. Inspect `migration-result.json` and the retained logs.
