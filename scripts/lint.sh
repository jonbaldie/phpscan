#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sh -n install.sh
for f in scripts/*.sh tests/*.sh; do bash -n "$f"; done
python3 -m py_compile tests/test_cli.py tests/test_install.py scripts/check-docs.py
python3 scripts/check-docs.py
git diff --check
scripts/bend.sh src/main.bend --check-only
