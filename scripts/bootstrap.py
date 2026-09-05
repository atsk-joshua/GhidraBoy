#!/usr/bin/env python3
"""Acquire pinned sources in this checkout. Never installs global packages."""
import hashlib,inspect,json,os,platform,subprocess,sys,urllib.request,zipfile,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];os.chdir(ROOT)

def archive(name,destination):
    locked=json.loads((ROOT/'dependencies.lock.json').read_text())['downloads'][name]
    file=ROOT/'.deps'/name
    if not file.exists():
        temporary=file.with_suffix(file.suffix+'.partial')
        urllib.request.urlretrieve(locked['url'],temporary);temporary.rename(file)
    if hashlib.sha256(file.read_bytes()).hexdigest()!=locked['sha256']:raise RuntimeError(f'Checksum mismatch: {name}')
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    if file.suffix=='.zip':
        with zipfile.ZipFile(file) as z:
            for member in z.infolist():
                if Path(member.filename).is_absolute() or '..' in Path(member.filename).parts:raise RuntimeError('Invalid archive member')
                z.extract(member,destination)
                target=destination/member.filename
                if target.is_file() and member.external_attr>>16:target.chmod((member.external_attr>>16)&0o777)
    else:
        with tarfile.open(file) as t:
            for member in t.getmembers():
                if Path(member.name).is_absolute() or '..' in Path(member.name).parts or not (member.isfile() or member.isdir()):raise RuntimeError('Invalid archive member')
            t.extractall(destination,**({'filter':'data'} if 'filter' in inspect.signature(t.extractall).parameters else {}))

def run(*args):subprocess.run(args,check=True)
def git(name,url,commit,patch=None):
    dest=ROOT/'.deps'/name
    if not (dest/'.git').exists():
        dest.mkdir(parents=True,exist_ok=True)
        run('git','init',str(dest));run('git','-C',str(dest),'remote','add','origin',url)
        run('git','-C',str(dest),'fetch','--depth','1','origin',commit)
        run('git','-C',str(dest),'checkout','--detach',commit)
    current=subprocess.check_output(['git','-C',str(dest),'rev-parse','HEAD'],text=True).strip()
    if current!=commit:
        if subprocess.check_output(['git','-C',str(dest),'status','--porcelain'],text=True).strip():raise RuntimeError(f'{name}: preserve local changes before changing pin')
        run('git','-C',str(dest),'checkout','--detach',commit)
    if patch:
        reverse=subprocess.run(['git','-C',str(dest),'apply','--reverse','--check',str(ROOT/patch)],capture_output=True)
        if reverse.returncode:run('git','-C',str(dest),'apply',str(ROOT/patch))

if __name__=='__main__':
    (ROOT/'.deps').mkdir(exist_ok=True)
    git('SameBoy','https://github.com/LIJI32/SameBoy.git','208ba4afabffab9edde416f2dbb8ae459e34adb8','native/patches/0001-cpu-bus-provenance.patch')
    git('GhidraBoy','https://github.com/Gekkio/GhidraBoy.git','42032f9d97e9e502dc10a14743bdb3d1b9388588','ghidra-extension/patches/ghidraboy-12.1.2.patch')
    git('rgbds','https://github.com/gbdev/rgbds.git','92bfe5d930c07dd4672b148f811305aa294d6e6f')
    system=platform.system();arch=platform.machine()
    if (system,arch) not in (('Darwin','arm64'),('Linux','x86_64')):raise RuntimeError('Supported lanes: macOS arm64 and Linux x86-64')
    archive('rgbds-macos.zip' if system=='Darwin' else 'rgbds-linux-x86_64.tar.xz',ROOT/'.deps/rgbds-bin')
    archive('gradle.zip',ROOT/'.deps')
    ghidra=Path(os.environ['GHIDRA_INSTALL_DIR'])
    props=dict(line.split('=',1) for line in (ghidra/'Ghidra/application.properties').read_text().splitlines() if '=' in line and not line.startswith('#'))
    if props['application.version']!='12.1.2':raise RuntimeError('This release requires Ghidra 12.1.2')
    run(sys.executable,'-m','venv','.venv12')
    run(str(ROOT/'.venv12/bin/python'),'-m','pip','install','--no-index','--find-links',str(ghidra/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist'),'ghidratrace==12.1','protobuf==6.31.0')
    print('Pinned sources and Trace RMI environment ready. Build RGBDS if needed, then run scripts/build_native.sh and scripts/build_extension.sh.')
