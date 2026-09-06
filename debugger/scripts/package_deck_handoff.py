#!/usr/bin/env python3
"""Build the student-facing ZIP from the already built Linux candidate."""
from pathlib import Path
import hashlib
import json
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'dist/GhiGBC-SteamDeck-Handoff-0.1.0.zip'
DOCS = {'QUICKSTART.md', 'UI_ACTION_VALIDATION.md', 'STEAM_DECK.md', 'NATIVE_CONTRACT.md', 'ACTUAL_BATTLE.md', 'HANDOFF_REPORT.md'}
files = {}
with tarfile.open(ROOT/'dist/GhiGBC-0.1.0-linux-x86_64.tar.gz') as archive:
    for member in archive.getmembers():
        if not member.isfile():
            continue
        relative = Path(member.name).relative_to('GhiGBC-linux-x86_64')
        if '..' in relative.parts:
            raise RuntimeError('Unsafe handoff member')
        if relative.parts[0] == 'docs' and (len(relative.parts) != 2 or relative.name not in DOCS):
            continue
        files[str(relative)] = (archive.extractfile(member).read(), member.mode)
guide = (ROOT/'docs/STEAM_DECK_HANDOFF.md').read_bytes()
files['START-HERE.md'] = (guide, 0o644)
files['README.md'] = (guide, 0o644)
files['NOTES.txt'] = (b'''GhiGBC Steam Deck results - fill this in after testing

SteamOS version:
Ghidra version:
Setup result:
Automated validation result:
Interactive button validation result:
Did the game window open?
Did input stay responsive while paused?
Did held directions release after switching focus?
Did closing the game disconnect the agent?
Other errors or observations:

Run bash Collect-results.sh to include these notes with the test logs.
''', 0o644)
files['docs/evidence/.gitkeep'] = (b'', 0o644)
files['docs/IMPLEMENTATION_STATUS.md'] = (b'''# Handoff status

Ghidra12.1.2 and SameBoy integration are verified on the development Mac. The Linux candidate and its exported ABI were built and inspected, but Steam Deck execution is pending. Follow START-HERE.md and return the collected results.

Known limits: CPU-origin watches only; no DMA/HDMA watches, GBW3 far-call over/out, inferred callers/full stack, battery import, or audio output. See NATIVE_CONTRACT.md and DEVELOPMENT_VALIDATION.md.
''', 0o644)
files['docs/DEVELOPMENT_VALIDATION.md'] = (b'''# Development validation

Verified on macOS 26.5.2 arm64, Ghidra 12.1.2, Java21, Python3.14.7, pinned SameBoy1.0.3.

- 25 native/control tests pass; original 11 legacy tests and 256 initiative /150 damage /8 modifier /3 order cases rerun.
- Real Trace RMI registers, bank-specific breakpoints, physical/static mappings, checkpoints/edits and independently reopened history pass.
- Actual UI breakpoint/Resume/historical writer/bookmark sequence and game-profile HP-button/cleanup pass.
- Actual CLASS2 battle: APC HP10 to3, exact writer rom18::40b5, restore/repeat and independent reopen verified.
- Integrated250-stop probe: agent RSS +16KiB, Ghidra RSS +178320KiB, saved trace +1196032 bytes, dropped0. Step p95 37.625ms and pause269.863ms including settling. This is a bounded measurement, not a leak-proof claim.

The Linux x86-64 library was cross-built for glibc2.28 and its ABI inspected. Steam Deck native execution and desktop behavior remain unverified until you run the included checks. No Mac test logs are preloaded into the Deck result folder.
''', 0o644)
for name, action in [('Setup.sh', 'setup'), ('Validate.sh', 'validate'), ('Collect-results.sh', 'collect')]:
    script = '#!/usr/bin/env bash\nset -euo pipefail\ncd -- "$(dirname -- "$0")"\nexec python3 scripts/deck_handoff.py ' + action + ' "$@"\n'
    files[name] = (script.encode(), 0o755)
manifest = {'package': 'GhiGBC Steam Deck handoff', 'version': '0.1.0', 'ghidra': '12.1.2',
            'target': 'Linux x86-64 / Steam Deck desktop mode', 'target_execution_verified': False,
            'files': {name: hashlib.sha256(data).hexdigest() for name, (data, mode) in sorted(files.items())}}
files['PACKAGE-MANIFEST.json'] = (json.dumps(manifest, indent=2).encode()+b'\n', 0o644)
with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as archive:
    for name, (data, mode) in sorted(files.items()):
        info = zipfile.ZipInfo('GhiGBC-SteamDeck/' + name)
        info.create_system = 3
        info.external_attr = (0o100000 | mode) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, data)
OUT.with_suffix('.zip.sha256').write_text(hashlib.sha256(OUT.read_bytes()).hexdigest()+'  '+OUT.name+'\n')
(ROOT/'dist/SHA256SUMS').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n'
                                       for path in sorted((ROOT/'dist').iterdir()) if path.is_file() and path.name != 'SHA256SUMS'))
print(OUT)
