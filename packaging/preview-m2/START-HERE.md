# GhidraBoy Engineering Preview M2

This is an engineering preview for Ghidra 12.1.3 / JDK 21, not a stable release.
The exact Linux/Steam Deck headed workflow below is still **NOT_RUN** for this
candidate; `ENGINEERING-PREVIEW` remains **NOT_READY** until that acceptance passes.

1. Install `GhidraBoy-extension.zip` with File → Install Extensions, then restart.
2. For a language-v1 legacy Program, follow `MIGRATION.md` and create a new GZF.
3. Open the migrated/prepared Program in CodeBrowser.
4. Use Tools → GhidraBoy → Program Status....
5. Choose Analysis → Auto Analyze... and enable/run **GhidraBoy Bank and Mapper Analysis**.
6. Continue in the ordinary Listing and Decompiler, then save, close and reopen.

Basic analysis does not use Script Manager, MapperState JSON or proof JSON.
