#!/usr/bin/env bash
#@title GBC / mGBA (experimental)
#@desc <html><body width="320px">Debug a CGB MBC5 ROM with the experimental mGBA adapter. Native CGB post-boot state; execution breakpoints only.</body></html>
#@menu-group local
#@icon icon.debugger
#@arg :file "ROM" "The matching GB/GBC ROM or included regression fixture"
#@env OPT_GBC_HOME:dir="" "GhiGBC directory" "Installed GhiGBC package directory"
#@env OPT_GBC_DISPLAY:bool=true "Game window" "Show the playable SDL game window"
set -euo pipefail
if [[ -z ${OPT_GBC_HOME:-} ]]; then
  echo 'Set GhiGBC directory to the installed package directory.' >&2
  exit 2
fi
export PYTHONPATH="$OPT_GBC_HOME/python"
args=(--rom "$1" --connect "$GHIDRA_TRACE_RMI_ADDR" --backend mgba --model CGB)
if [[ ${OPT_GBC_DISPLAY:-true} == true ]]; then args+=(--display); fi
exec "$OPT_GBC_HOME/.venv12/bin/python" -m ghigbc.agent "${args[@]}"
