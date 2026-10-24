#!/bin/sh
set -eu
usage() {
  printf '%s\n' 'Usage: sh install.sh [vX.Y.Z]' \
    'Installs the latest release unless a version is given.' \
    'Set PHPSCAN_INSTALL_DIR to change the destination (default: ~/.local/bin).'
}
fail() { printf 'phpscan install: %s\n' "$*" >&2; exit 1; }
if [ "${1:-}" = --help ]; then usage; exit 0; fi
[ "$#" -le 1 ] || { usage >&2; exit 1; }
version=${1:-latest}
if [ "$version" != latest ]; then
  printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$' || fail 'Expected a version such as v0.1.0.'
fi
case $(uname -s) in Linux) os=linux;; Darwin) os=darwin;; *) fail 'Supported operating systems are Linux and macOS.';; esac
case $(uname -m) in x86_64|amd64) arch=x86_64;; aarch64|arm64) arch=arm64;; *) fail 'Supported architectures are x86_64 and arm64.';; esac
for tool in curl tar awk mktemp install; do
  command -v "$tool" >/dev/null 2>&1 || fail "Missing required command: $tool"
done
if command -v sha256sum >/dev/null 2>&1; then
  sha=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  sha=shasum
else
  fail 'Install sha256sum or shasum to verify the download.'
fi
dest=${PHPSCAN_INSTALL_DIR:-"$HOME/.local/bin"}
asset="phpscan-$os-$arch.tar.gz"
base=https://github.com/jonbaldie/phpscan/releases
if [ "$version" = latest ]; then base="$base/latest/download"; else base="$base/download/$version"; fi
tmp=$(mktemp -d)
stage=
cleanup() {
  rm -rf "$tmp"
  if [ -n "$stage" ]; then rm -f "$stage"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$base/$asset" -o "$tmp/$asset"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
expected=$(awk -v name="$asset" 'NF == 2 && $2 == name { print $1 }' "$tmp/SHA256SUMS")
[ "${#expected}" -eq 64 ] || fail "Missing or duplicate checksum for $asset."
case "$expected" in *[!0-9a-fA-F]*) fail 'Invalid checksum.';; esac
if [ "$sha" = sha256sum ]; then actual=$(sha256sum "$tmp/$asset"); else actual=$(shasum -a 256 "$tmp/$asset"); fi
[ "${actual%% *}" = "$expected" ] || fail 'Checksum mismatch. The installed binary was not changed.'
mkdir "$tmp/unpack"
tar -xzf "$tmp/$asset" -C "$tmp/unpack" phpscan
[ -f "$tmp/unpack/phpscan" ] && [ ! -L "$tmp/unpack/phpscan" ] || fail 'Archive does not contain a regular phpscan binary.'
chmod 755 "$tmp/unpack/phpscan"
installed_version=$("$tmp/unpack/phpscan" --version) || fail 'The downloaded binary cannot run on this machine. Check the platform requirements.'
if [ "$version" != latest ]; then
  [ "$installed_version" = "phpscan ${version#v}" ] || fail 'The binary version does not match the requested release.'
fi
mkdir -p "$dest"
stage=$(mktemp "$dest/.phpscan.XXXXXX")
install -m 755 "$tmp/unpack/phpscan" "$stage"
mv -f "$stage" "$dest/phpscan"
stage=
printf 'Installed %s to %s/phpscan\n' "$installed_version" "$dest"
case :$PATH: in *:"$dest":*) ;; *) printf 'Add this directory to PATH: %s\n' "$dest";; esac
