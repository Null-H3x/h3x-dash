#!/usr/bin/env bash
# Rebuild h3x-dash.tar.gz from the local ./h3x-dash/ tree.
# The git repo tracks the tarball, not the extracted directory.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/h3x-dash"
OUT="$ROOT/h3x-dash.tar.gz"

if [[ ! -d "$SRC" ]]; then
  echo "error: $SRC not found — extract first: tar -xzf h3x-dash.tar.gz" >&2
  exit 1
fi

tar -czf "$OUT" \
  --exclude='__pycache__' \
  --exclude='*.py[cod]' \
  --exclude='.DS_Store' \
  --exclude='scans' \
  --exclude='reports' \
  --exclude='loot' \
  --exclude='logs' \
  --exclude='.env' \
  --exclude='venv' \
  --exclude='.venv' \
  -C "$ROOT" h3x-dash

echo "Wrote $OUT ($(du -h "$OUT" | cut -f1))"
