#!/usr/bin/env python3
"""Build an allowlisted source handoff and macOS development artifact, no private assets."""
from pathlib import Path
import hashlib,tarfile,json
root=Path(__file__).resolve().parents[1];out=root/'dist';out.mkdir(exist_ok=True)
paths=[]
for base in ('native','python','scripts','tests','docs','legacy','LICENSES','ghidra-extension'):
 for p in (root/base).rglob('*'):
  rel=p.relative_to(root)
  if not p.is_file() or any(x in ('__pycache__','build','dist','.gradle') for x in rel.parts):continue
  if p.suffix.lower() in ('.gb','.gbc','.gzf','.sav','.sbs','.gbwstate'):raise RuntimeError(f'Private/ROM file in source tree: {rel}')
  paths.append(p)
paths += [root/p for p in ('README.md','LICENSE','dependencies.lock.json','.gitignore')]
archive=out/'GhiGBC-0.1.0-source.tar.gz'
with tarfile.open(archive,'w:gz') as t:
 for p in sorted(paths):t.add(p,arcname='GhiGBC/'+str(p.relative_to(root)))
# Redistributable teaching artifact built exclusively from our checked-in assembly.
for p in (root/'build/teaching.gbc',root/'build/teaching.sym'):
 (out/p.name).write_bytes(p.read_bytes())
for folder in (root/'ghidra-extension/dist',root/'.deps/GhidraBoy/build/distributions'):
 p=max(folder.glob('*.zip'),key=lambda p:p.stat().st_mtime);(out/p.name).write_bytes(p.read_bytes())
# Platform bundle: no C compiler needed for first native loading/tests on the Deck.
if (root/'build/libghigbc.so').exists():
    binary=out/'GhiGBC-0.1.0-linux-x86_64.tar.gz'
    extra=[root/'build/libghigbc.so',root/'build/teaching.gbc',root/'build/teaching.sym',root/'.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin']
    for folder in (root/'ghidra-extension/dist',root/'.deps/GhidraBoy/build/distributions'):
        extra.append(max(folder.glob('*.zip'),key=lambda p:p.stat().st_mtime))
    with tarfile.open(binary,'w:gz') as t:
        for p in sorted(paths+extra):t.add(p,arcname='GhiGBC-linux-x86_64/'+str(p.relative_to(root)))
(out/'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(out.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))
print(archive)
