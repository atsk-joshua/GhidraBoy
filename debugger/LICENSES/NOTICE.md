# Distributed dependency notices

GhidraBoy is the sole SM83 provider: Joonas Javanainen/Gekkio and contributors, Apache 2.0. Its separate archive includes its LICENSE and the extracted GhiGBC knowledge-exporter MIT notice. The maintained candidate is identified by suite.json, not the historical private compatibility patch.

SameBoy v1.0.3, LIJI32 and contributors, supplies the selected Core C code and assembled open-source BootROMs/cgb_boot.bin. The adapter links Core, not the Cocoa/SDL frontend. The top-level SameBoy license with directory exceptions is preserved in SameBoy.txt; selected Core and BootROMs use the applicable Expat terms. No Nintendo boot ROM is distributed.

GhiGBC and self-authored teaching assembly use the project MIT license. RGBDS and Zig are build tools; their notices are retained. Ghidra and its matched ghidratrace/protobuf wheels are external prerequisites and are installed offline from the selected Ghidra distribution; suite.json pins their digests. Ghidra itself and a Python/JDK runtime are not included.

The Linux candidate additionally carries Debian's dynamically linked SDL2 2.32.4+dfsg-1 library as a process-local fallback, with the complete exact package copyright in SDL2-copyright.txt. SDL2 uses the zlib license with the package's documented component exceptions. Graphics drivers, glibc and other system libraries are not bundled. The host must satisfy its listed dynamic dependencies. This fallback is tested separately with system SDL2 absent; no SteamOS compatibility is inferred from Debian execution.

Optional external study packages retain their own original MIT attribution. Generic runtime archives contain neither private game assets nor study code. No ROM/GZF/save/checkpoint from the private acceptance run is included.

Packages selecting mGBA additionally contain its pinned GB-only core under MPL 2.0. The complete pristine source archive, modified-file patch, adapter/build sources and reproduction instructions accompany the binary; see docs/MGBA_SOURCE.md. The exact MPL text is in mGBA-MPL-2.0.txt, and upstream component notices remain in the source archive. mGBA uses its own post-boot state and does not use SameBoy's boot ROMs. Backend selection is recorded by suite.json and runtime-backends.json.
