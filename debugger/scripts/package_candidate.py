#!/usr/bin/env python3
"""Build reproducible prebuilt generic payloads from explicit allowlists; no private assets."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile

from build_inputs import artifact_inputs, runtime_dependencies, sha

ROOT=Path(__file__).resolve().parents[1]
REPOSITORY=ROOT.parent
EPOCH=1788566400


def archive(source,output):
    with output.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=EPOCH) as gz,tarfile.open(fileobj=gz,mode='w',format=tarfile.PAX_FORMAT) as tar:
        for file in sorted(source.rglob('*')):
            if not file.is_file():continue
            info=tarfile.TarInfo(str(Path(source.name)/file.relative_to(source)));data=file.read_bytes()
            info.size=len(data);info.mtime=EPOCH;info.mode=0o755 if os.access(file,os.X_OK) else 0o644;info.uid=info.gid=0;info.uname=info.gname=''
            tar.addfile(info,io.BytesIO(data))


def main(default_platform=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts',type=Path,default=REPOSITORY/'build/integration/artifacts.json')
    p.add_argument('--provider',type=Path,help='Compatibility override; must match the verified provider artifact')
    p.add_argument('--ghidra',required=True,type=Path)
    p.add_argument('--jdk',required=True,type=Path)
    p.add_argument('--platform',required=default_platform is None,default=default_platform,choices=['macos-arm64','linux-x86_64'])
    a=p.parse_args()
    products,inputs=artifact_inputs(REPOSITORY,a.artifacts)
    lock=runtime_dependencies(ROOT)
    if products['ghidra']!=lock['ghidra']['version']:raise ValueError('Build/dependency Ghidra mismatch')
    release=products['release']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*',release):raise ValueError('Invalid build release identity')
    provider=inputs['GhidraBoy']['archive']
    if a.provider and sha(a.provider)!=sha(provider):raise ValueError('Provider override does not match build outputs')
    tracked=set(subprocess.check_output(['git','ls-files','-z'],cwd=REPOSITORY).decode().split('\0'))
    package_name='GhidraBoy-Debugger-'+release+'-'+a.platform
    stage=ROOT/'build/candidate'/package_name
    if stage.exists():shutil.rmtree(stage)
    stage.mkdir(parents=True)
    def copy(src,relative):
        if src.is_symlink():raise ValueError('Refusing symlink payload: '+str(src))
        dest=stage/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
    def tree(relative):
        for src in sorted((ROOT/relative).rglob('*')):
            if src.is_file() and src.relative_to(REPOSITORY).as_posix() in tracked:copy(src,src.relative_to(ROOT))
    for relative in ('python/ghigbc','LICENSES','docs/contracts'):tree(relative)
    runtime_files=[str(f.relative_to(stage)) for f in stage.rglob('*') if f.is_file() and (f.relative_to(stage).parts[0] in ('python','LICENSES'))]
    native=ROOT/'build'/('libghigbc.dylib' if a.platform=='macos-arm64' else 'libghigbc.so')
    for src,relative in [(native,'build/'+native.name),(ROOT/'.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin','.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin')]:
        copy(src,relative);runtime_files.append(relative)
    if a.platform=='linux-x86_64':
        for src,relative in [(ROOT/'build/sdl-linux/libSDL2-2.0.so.0','build/runtime-libs/libSDL2-2.0.so.0'),(ROOT/'build/sdl-linux/SDL2-copyright.txt','LICENSES/SDL2-copyright.txt')]:
            copy(src,relative);runtime_files.append(relative)
    for relative in ('native/patches/0001-cpu-bus-provenance.patch','build/teaching.gbc','build/teaching-dmg.gb','build/teaching.sym','LICENSE','scripts/install.py','scripts/runtime_python.py','scripts/install_legacy_v2.py','scripts/doctor.py','scripts/test_display_runtime.py','scripts/build_inputs.py'):
        copy(ROOT/relative,relative);runtime_files.append(relative)
    (stage/'dependencies.lock.json').write_text(json.dumps(lock,indent=2,sort_keys=True)+'\n')
    runtime_files.append('dependencies.lock.json')
    for relative in ('scripts/test_ui_actions.sh','scripts/test_display_runtime.py','scripts/test_installer.py','scripts/test_native.sh','scripts/test_ghidra.sh','scripts/prepare_runtime.py','scripts/deck_handoff.py','scripts/collect_results.py'):
        copy(ROOT/relative,relative)
    copy(REPOSITORY/'tools/native_dependency_update.py','scripts/native_dependency_update.py')
    for source in (ROOT/'tests').glob('test_*.py'):
        if source.relative_to(REPOSITORY).as_posix() in tracked:copy(source,source.relative_to(ROOT))
    # Precompile the real RMI acceptance harness on the build host. Runtime checks need only java.
    debugger=inputs['GhiGBC']['archive']
    classes=ROOT/'build/candidate-test-classes'
    if classes.exists():shutil.rmtree(classes)
    classes.mkdir()
    cp=[str(f) for f in a.ghidra.rglob('*.jar') if 'yajsw' not in str(f)]
    cp += [str(inputs[name]['jar']) for name in ('GhiGBC','GhidraBoy')]
    subprocess.run([str(a.jdk/'bin/javac'),'-proc:none','-cp',os.pathsep.join(cp),'-d',str(classes),str(ROOT/'tests/ghidra/RealTraceTest.java'),str(ROOT/'tests/ghidra/MappingContractTest.java'),str(ROOT/'tests/ghidra/UiActionTest.java')],check=True)
    jar=stage/'build/GhiGBC-acceptance.jar'
    with zipfile.ZipFile(jar,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for f in sorted(classes.rglob('*.class')):
            info=zipfile.ZipInfo(str(f.relative_to(classes)),(2026,9,5,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,f.read_bytes())
    for src in (provider,debugger):copy(src,'extensions/'+src.name)
    with zipfile.ZipFile(debugger) as z:
        jars=[n for n in z.namelist() if n.endswith('.jar') and '/lib/' in n]
        assert jars==['GhiGBC/lib/GhiGBC.jar'],jars
        assert not any(n.endswith('.ldefs') for n in z.namelist())
    # Simple runtime entry points. Setup installs; validation invokes installed components.
    setup='#!/usr/bin/env bash\nset -euo pipefail\ncd "$(dirname "$0")"\nmkdir -p .local/results\n"${GBC_PYTHON:-python3}" scripts/install.py "$@" 2>&1 | tee .local/results/setup.log\n'
    (stage/'Setup.sh').write_text(setup);(stage/'Setup.sh').chmod(0o755)
    validate='#!/usr/bin/env bash\nset -euo pipefail\ncd "$(dirname "$0")"\nmkdir -p .local/results docs/evidence\n{\n  "${GBC_PYTHON:-python3}" scripts/prepare_runtime.py\n  export GBC_PYTHON="$PWD/.venv12/bin/python"\n  if [[ "${1:-}" == "--ui" ]]; then\n    bash scripts/test_ui_actions.sh\n  else\n    bash scripts/test_native.sh\n    bash scripts/test_ghidra.sh --growth\n  fi\n} 2>&1 | tee .local/results/validate.log\n'
    (stage/'Validate.sh').write_text(validate);(stage/'Validate.sh').chmod(0o755)
    (stage/'Collect-results.sh').write_text('#!/usr/bin/env bash\nset -euo pipefail\ncd "$(dirname "$0")"\nexec "${GBC_PYTHON:-python3}" scripts/collect_results.py\n');(stage/'Collect-results.sh').chmod(0o755)
    copy(ROOT/'docs/PACKAGE.md','README.md')
    for name in ('INSTALL.md','SUPPORT.md','NATIVE_CONTRACT.md','UI_ACTION_VALIDATION.md'):
        if (ROOT/'docs'/name).exists():copy(ROOT/'docs'/name,'docs/'+name)
    copies={str(f.relative_to(stage)):sha(f) for f in sorted(stage.rglob('*')) if f.is_file()}
    wheels={f.name:sha(f) for f in (a.ghidra/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist').glob('*.whl') if f.name.startswith(('ghidratrace-','protobuf-'))}
    source={}
    for repo in (REPOSITORY,):
        source[repo.name]={'scope':'Tracked build/runtime sources; migration ledger and release evidence excluded','head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'files':{}}
        tracked=subprocess.check_output(['git','ls-files','--cached'],cwd=repo,text=True).splitlines()
        for name in sorted(set(tracked)):
            file=repo/name
            if file.is_file() and not name.startswith(('docs/evidence/','docs/integration/')) and name!='docs/debugger-integration-plan.md':
                source[repo.name]['files'][name]=sha(file)
    manifest=dict(schema=1,kind='generic',version=release+'-candidate',ghidra=products['ghidra'],platform=a.platform,python_requirement='>=3.9',python_selection='Existing system python3, or explicit GBC_PYTHON/--python; verified by capability and installed-runtime checks',native_abi=1,checkpoint_schema=2,profile_api=1,mapping_schema=2,python_wheels=wheels,runtime_files=sorted(set(runtime_files)),extensions=[dict(name='GhidraBoy',path='extensions/'+provider.name),dict(name='GhiGBC',path='extensions/'+debugger.name)],sources=source,files=copies)
    manifest['native_decompiler']=lock['native_decompiler']
    (stage/'suite.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    out=REPOSITORY/'dist'/(package_name+'.tar.gz');out.parent.mkdir(exist_ok=True);archive(stage,out)
    out.with_suffix(out.suffix+'.sha256').write_text(sha(out)+'  '+out.name+'\n')
    print(json.dumps({'stage':str(stage),'archive':str(out),'sha256':sha(out),'manifest_sha256':sha(stage/'suite.json')}))

if __name__=='__main__':main()
