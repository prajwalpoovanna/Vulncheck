#!/usr/bin/env bash
# Simple helper to run the dashboard in the vulncheck conda environment
set -e
if [ -z "$MINIFORGE_HOME" ]; then
  MINIFORGE_HOME="$HOME/miniforge3"
fi
$MINIFORGE_HOME/bin/conda run -n vulncheck --no-capture-output python dashboard_app.py
