# Retained debugger identities

The user-facing product name is **GhidraBoy debugger**. The integrated source
still uses these newer GhiGBC identities; renaming them provides little cleanup
benefit and would require separate installation and persistence migration work.

| Surface | Current dependency | Retention reason |
| --- | --- | --- |
| Extension and Gradle component | `debugger/ghidra-extension/extension.properties`: GhiGBC; integration manifest component GhiGBC | Installer ownership, compile-only study input and extension selection |
| Java API | `ghigbc.GbcPlugin`, mapping/action services in the `ghigbc` package | Saved tools, launch configuration and external extension imports |
| Python modules | `ghigbc.agent`, backends, profile and mapping contracts | Launch commands, installed profiles and external imports |
| Runtime and rollback | `GhiGBC-runtime`, `GhiGBC-rollback`, `.ghigbc-install.lock` in `debugger/scripts/install.py` | Recovery journals, managed installations and concurrent installer locking |
| Legacy rollback | `debugger/scripts/install_legacy_v2.py` | Reads existing version-2 journals; keep this reader |
| Launcher option | `OPT_GBC_HOME` and `-m ghigbc.agent` in backend launch scripts | Installer substitution and existing saved launch configuration |
| Native adapter | `libghigbc` and backend ABI in `debugger/backends/` | Existing bindings, source/native identities and checkpoint/runtime receipts |
| Trace and checkpoint data | Schema and legacy readers in `debugger/python/ghigbc/` | Existing captures remain readable; profiles are optional |
| Script entry point | `ExportGbcKnowledge.java` | Single maintained source under root ghidra_scripts; regular copy at scripts/ in debugger packages |

Inherited upstream `SM83:LE:16:default`, language version 1.0, default compiler,
register layout and 16-bit pointers remain unchanged by this cleanup. The root
provider layout remains familiar. Current runtime policy is Ghidra 12.1.3/JDK 21;
saved-Program compatibility does not imply support for older running Ghidra versions.
