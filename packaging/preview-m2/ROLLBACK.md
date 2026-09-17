# Rollback

Never overwrite the original GZF or project. If migration/preparation/analysis fails,
discard the new output and retained work directory, reinstall the original extension
in its original Ghidra version, and reopen the untouched backup. Do not attempt to
open the migrated database with the older provider.
