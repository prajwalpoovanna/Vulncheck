#!/usr/bin/env bash
set -euo pipefail

# Installer for Miniforge + create env from environment.yml
# Usage: bash scripts/setup_conda_env.sh

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="$HOME/miniforge3"

echo "==> Installing Miniforge (batch mode) to $INSTALL_DIR"
OS_ARCH="MacOSX-arm64"
INSTALLER="Miniforge3-${OS_ARCH}.sh"
URL="https://github.com/conda-forge/miniforge/releases/latest/download/${INSTALLER}"

TMP="/tmp/$INSTALLER"
curl -sSfL -o "$TMP" "$URL"
chmod +x "$TMP"

if [ -d "$INSTALL_DIR" ]; then
  echo "Miniforge seems to already exist at $INSTALL_DIR"
else
  bash "$TMP" -b -p "$INSTALL_DIR"
fi

echo "==> Initializing conda shell support"
# shell hook for current session
source "$INSTALL_DIR/etc/profile.d/conda.sh"

echo "==> Creating conda environment 'vulncheck' from environment.yml"
conda env remove -n vulncheck -y >/dev/null 2>&1 || true
conda env create -f "$ROOT_DIR/environment.yml"

echo "==> Done. Activate with: conda activate vulncheck"
echo "If your shell doesn't recognize 'conda', restart your terminal or run: source $INSTALL_DIR/etc/profile.d/conda.sh"
