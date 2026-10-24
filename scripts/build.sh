#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
scripts/bend.sh PROOF.bend | tee dist/proof.txt
grep -q '^ALL PROOFS CHECK$' dist/proof.txt
scripts/bend.sh tests/status.bend | tee dist/status.txt
grep -qx '2' dist/status.txt
scripts/bend.sh src/main.bend -o dist/phpscan.c
if [[ $(uname -s) = Darwin ]]; then
  export MACOSX_DEPLOYMENT_TARGET=13.0
fi
"${CC:-clang}" -std=c11 -O3 dist/phpscan.c -lpthread -lm -o dist/phpscan
{
  printf 'phpscan %s\n' "$(scripts/version.sh)"
  printf 'revision %s\n' "$(git rev-parse HEAD 2>/dev/null || printf uncommitted)"
  printf 'platform %s %s\n' "$(uname -s)" "$(uname -m)"
  scripts/bend.sh version
  bun --version
  "${CC:-clang}" --version
} > dist/build-info.txt
dist/phpscan --version
