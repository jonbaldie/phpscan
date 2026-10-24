#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
stage=${1:-all}
[[ $# -le 1 ]] || { echo 'Usage: scripts/build.sh [generate|compile]' >&2; exit 2; }
case "$stage" in all|generate|compile) ;; *) echo 'Usage: scripts/build.sh [generate|compile]' >&2; exit 2;; esac
mkdir -p dist
if [[ $stage != compile ]]; then
  scripts/bend.sh PROOF.bend | tee dist/proof.txt
  grep -q '^ALL PROOFS CHECK$' dist/proof.txt
  scripts/bend.sh tests/status.bend | tee dist/status.txt
  grep -qx '2' dist/status.txt
  echo 'Generating portable C with Bend.'
  scripts/bend.sh src/main.bend -o dist/phpscan.c
fi
if [[ $stage = generate ]]; then exit 0; fi
[[ -s dist/phpscan.c ]] || { echo 'Run make generate before make compile.' >&2; exit 2; }
printf 'Compiling native C for %s %s.\n' "$(uname -s)" "$(uname -m)"
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
