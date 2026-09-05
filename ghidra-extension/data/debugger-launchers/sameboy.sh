#!/usr/bin/env bash
#@title GBC / SameBoy
#@desc <html><body width="320px">Play and debug a GBC ROM with SameBoy. Uses the selected Ghidra version's Trace RMI client. Select the exported matching ROM for an annotated program.</body></html>
#@menu-group local
#@icon icon.debugger
#@arg :file "ROM" "The matching GBC ROM or included teaching ROM"
#@env OPT_GBC_HOME:dir="" "GhiGBC directory" "Installed GhiGBC package directory"
#@env OPT_GBC_DISPLAY:bool=true "Game window" "Show the playable SDL game window"
#@env OPT_GBC_EXPERIMENT:bool=false "Experiment edits" "Allow paused emulator edits with required recovery checkpoint"
set -euo pipefail
if [[ -z ${OPT_GBC_HOME:-} ]]; then
  echo 'Set GhiGBC directory to the installed package directory.' >&2
  exit 2
fi
export PYTHONPATH="$OPT_GBC_HOME/python"
args=(--rom "$1" --connect "$GHIDRA_TRACE_RMI_ADDR")
if [[ ${OPT_GBC_DISPLAY:-true} == true ]]; then args+=(--display); fi
if [[ ${OPT_GBC_EXPERIMENT:-false} == true ]]; then args+=(--experiment); fi
exec "$OPT_GBC_HOME/.venv12/bin/python" -m ghigbc.agent "${args[@]}"
