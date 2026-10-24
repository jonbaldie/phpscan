#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
archive=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$archive" -C "$tmp"
test -f "$tmp/LICENSE"
test -f "$tmp/licenses/Bend-Apache-2.0.txt"
"$tmp/phpscan" --version
bash tests/check.sh "$tmp/phpscan" tests/cases/*.php tests/versions/*.php
python3 tests/test_cli.py "$tmp/phpscan"
python3 tests/test_install.py "$tmp/phpscan"
