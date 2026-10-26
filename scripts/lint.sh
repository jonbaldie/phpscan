#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sh -n install.sh
for f in scripts/*.sh tests/*.sh; do bash -n "$f"; done
python3 -m py_compile tests/test_cli.py tests/test_advisories.py tests/test_symfony.py tests/test_laravel.py tests/test_install.py tests/test_docs.py scripts/check-docs.py scripts/catalog.py
python3 scripts/catalog.py --check
python3 scripts/check-docs.py
git diff --check
scripts/bend.sh src/main.bend --check-only
scripts/bend.sh tests/version-order.bend | grep -qx 0
scripts/bend.sh tests/symfony-profile.bend | grep -qx 0
scripts/bend.sh tests/laravel-profile.bend | grep -qx 0
scripts/bend.sh tests/catalog-check.bend | grep -qx 0
