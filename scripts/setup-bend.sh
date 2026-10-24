#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=2.0.38
sum=f3e82804e2672a331ab6713632836be4a6b554fec052a28cfc8ba57032b722a0
command -v bun >/dev/null || { echo 'Install Bun 1.3.14 before running make setup.' >&2; exit 1; }
if [[ -f ".tools/bend-$version/bend2/main.ts" ]]; then
  exit 0
fi
mkdir -p .tools
tmp=$(mktemp -d .tools/download.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
  "https://codeload.github.com/bendlang/bend/tar.gz/refs/tags/v$version" -o "$tmp/bend.tar.gz"
if command -v sha256sum >/dev/null; then
  got=$(sha256sum "$tmp/bend.tar.gz")
else
  got=$(shasum -a 256 "$tmp/bend.tar.gz")
fi
[[ ${got%% *} = "$sum" ]] || { echo 'Bend archive checksum mismatch.' >&2; exit 1; }
tar -xzf "$tmp/bend.tar.gz" -C "$tmp"
mv "$tmp/bend-$version" .tools/
printf 'Bend %s installed in .tools/.\n' "$version"
