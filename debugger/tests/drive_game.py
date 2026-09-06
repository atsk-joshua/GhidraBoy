"""Compatibility command; the optional game acceptance driver lives in GhiBW3."""
from pathlib import Path
import os,runpy,sys
study=Path(os.environ.get('GHIBW3_ROOT',str(Path(__file__).resolve().parents[2]/'GhiBW3')))
if not (study/'scripts/drive_game.py').exists():raise SystemExit('Install optional GhiBW3 and set GHIBW3_ROOT; generic debugger remains independent.')
sys.path.insert(0,str(study/'python'))
runpy.run_path(str(study/'scripts/drive_game.py'),run_name='__main__')
