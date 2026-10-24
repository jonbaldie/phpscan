#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
case $(uname -s) in Linux) os=linux;; Darwin) os=darwin;; *) exit 1;; esac
case $(uname -m) in x86_64|amd64) arch=x86_64;; aarch64|arm64) arch=arm64;; *) exit 1;; esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp dist/phpscan dist/build-info.txt LICENSE README.md THIRD_PARTY_NOTICES.md "$tmp/"
mkdir "$tmp/licenses"
cp licenses/Bend-Apache-2.0.txt "$tmp/licenses/"
COPYFILE_DISABLE=1 tar -czf "dist/phpscan-$os-$arch.tar.gz" -C "$tmp" \
  phpscan build-info.txt LICENSE README.md THIRD_PARTY_NOTICES.md licenses
printf 'Packaged dist/phpscan-%s-%s.tar.gz\n' "$os" "$arch"
