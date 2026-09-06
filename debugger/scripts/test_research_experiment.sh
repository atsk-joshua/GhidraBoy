#!/usr/bin/env bash
# Controlled real RMI experiment and independent observation-file reopen.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test_java_common.sh
ghigbc_test_init research-java
research_output="${GBC_EVIDENCE_DIR:-$ghigbc_test_work/evidence}"
mkdir -p "$research_output"
ghigbc_test_compile ghidra-extension/src/main/java/ghigbc/*.java tests/ghidra/RealTraceTest.java tests/ghidra/MappingContractTest.java tests/ghidra/ResearchExperimentTest.java
ghigbc_test_java ResearchExperimentTest "$PWD" "$research_output"
ghigbc_test_java ResearchExperimentTest reopen "$research_output"
# Test the direct API as well as the real RMI capability-negotiation rejection above.
PYTHONPATH="$PWD/python" "$GBC_PYTHON" - "$research_output" <<'PY'
import json,sys
from pathlib import Path
from ghigbc.backend import create_backend,UnsupportedFeature
output=Path(sys.argv[1]);destination=output/'unsupported-mgba-checkpoint'
with create_backend('mgba',Path('build/teaching.gbc')) as machine:
    before=machine.capture()
    try:
        machine.checkpoint(destination)
    except UnsupportedFeature as error:
        assert 'checkpoint' in str(error),str(error)
        assert not destination.exists(),'Unsupported checkpoint created a payload'
        after=machine.capture()
        assert before.state['pc']==after.state['pc'],'Unsupported checkpoint changed the selected PC'
        (output/'mgba-checkpoint-rejection.json').write_text(json.dumps(dict(status='PASS',backend=machine.descriptor.id,capabilities=sorted(machine.descriptor.features),diagnostic=str(error),pc=after.state['pc'],scope='Direct API rejects unsupported checkpoint before mutation; no portable state produced'),indent=2)+'\n')
        print('PASS research direct mGBA checkpoint rejection:',error)
    else:
        raise AssertionError('mGBA unexpectedly accepted unsupported checkpoint')
PY
