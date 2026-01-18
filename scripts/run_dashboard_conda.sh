#!/usr/bin/env bash
set -euo pipefail

# Activate conda env (works if Miniforge/conda was installed via the setup script)
INSTALL_DIR="$HOME/miniforge3"
if [ -f "$INSTALL_DIR/etc/profile.d/conda.sh" ]; then
  source "$INSTALL_DIR/etc/profile.d/conda.sh"
fi

conda activate vulncheck

echo "Starting dashboard..."
python dashboard_app.py
