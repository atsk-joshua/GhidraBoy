# mGBA corresponding source

The optional experimental adapter contains mGBA revision `685023e05d90d87050fb357f46f7bd2d907083f5`, from https://github.com/mgba-emu/mgba. mGBA's MPL 2.0 license is included at `LICENSES/mGBA-MPL-2.0.txt`. Its original copyright and license notices, including third-party component notices, are retained in the complete pristine `sources/mgba-source.tar`. The archive SHA-256 is `a59017f0dee15f8f9067c5f0638707f81487de595274f6b9e5a3e88f2bb517e9`.

The modification to mGBA disables SM83 idle fast-forward so debugger stops remain instruction-boundary observations. The exact patch is `backends/mgba/native/patches/0001-sm83-no-idle.patch`; the modified mGBA file remains under MPL 2.0. The new adapter, CMake configuration, and build script accompany the source. Keep these source files, notices, and the patch available with binary redistribution. This source distribution is included directly in the package, with no separate download required.

To rebuild using an installed C/C++ compiler, CMake 3.21+, Git, tar, and Python 3.9+, run from the extracted package:

```sh
python3 scripts/build_mgba.py --source sources/mgba-source.tar --work /tmp/mgba-fresh-build --output /tmp/mgba-rebuilt
```

The work directory must not exist. The builder validates the pristine archive, applies the exact patch, and builds the GB-only adapter. The build receipt records compiler commands, source hashes, binary hash, and effective ABI flags. Reproducing a byte-identical binary also requires the same compiler, SDK, platform, and tool versions; the receipt's absolute diagnostic paths do not enter the runtime compatibility identity. mGBA-only packages do not include or require SameBoy's native library or boot ROMs.

The supported experimental scope is native CGB/MBC5 without rumble, with engine post-boot state. Checkpoint restore, experiment edits, hardware revision selection, and physical watchpoints are unavailable. Linux mGBA builds require separate platform qualification; successful macOS execution does not establish SteamOS support.
