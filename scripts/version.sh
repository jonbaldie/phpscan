#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
awk -F '"' '/^  "/ { print $2 }' src/version.bend
