#!/usr/bin/env bash
#
# run.sh — Convenience launcher.
#
# Activates the venv created by install.sh, then invokes eyestat_runner.py with
# any arguments you pass. Falls back to a sensible small smoke-test run if
# no arguments are given.
#
# USAGE
#   ./run.sh                       # small smoke-test (1000 seeds, ctak_right + park_miller)
#   ./run.sh --modes all --seed-end 1000000 --workers 32 --languages fi
#

set -euo pipefail

VENV_PATH="${EYESTAT_VENV:-${BF_VENV:-$HOME/.venvs/eyestat}}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$VENV_PATH" ]]; then
    echo "ERROR: venv not found at $VENV_PATH"
    echo "  Run ./install.sh first, or set EYESTAT_VENV to point at your venv."
    exit 1
fi

# shellcheck disable=SC1091
source "$VENV_PATH/bin/activate"
cd "$PROJECT_DIR"

if [[ $# -eq 0 ]]; then
    echo "[run.sh] No args given — running a small smoke-test."
    echo "[run.sh] Pass arguments to override (e.g. --modes all --seed-end 1000000)."
    echo
    exec python3 eyestat_runner.py \
        --data noita_eye_data.json \
        --modes ctak_right \
        --prngs park_miller \
        --seed-start 0 --seed-end 1000 \
        --workers 4 \
        --threshold 13 \
        --output-dir eyestat_results_smoke
else
    exec python3 eyestat_runner.py "$@"
fi
