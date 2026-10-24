#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
compiler="$root/.tools/bend-2.0.38/bend2/main.ts"
[[ -f $compiler ]] || { echo 'Run make setup first.' >&2; exit 1; }
export BEND_NO_TELEMETRY=1
exec bun "$compiler" "$@"
