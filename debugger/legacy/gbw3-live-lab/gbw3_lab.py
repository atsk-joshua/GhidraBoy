"""Migration delegate; optional legacy study code is owned by GhiBW3."""
from pathlib import Path
import os,runpy,sys
root=Path(os.environ.get('GHIBW3_ROOT',str(Path(__file__).resolve().parents[3]/'GhiBW3')))
legacy=root/'legacy/gbw3-live-lab'
if not (legacy/Path(__file__).name).is_file():raise SystemExit('Install GhiBW3 legacy tools and set GHIBW3_ROOT')
sys.path.insert(0,str(legacy))
globals().update(runpy.run_path(str(legacy/Path(__file__).name),run_name=__name__))
