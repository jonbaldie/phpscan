#!/usr/bin/env bash
# Fetch each pinned upstream file in tests/cve/manifest.tsv into its own new
# empty directory, check its sha256, scan it and check the expectation.
# Downloads are data: nothing in them is executed.
# Usage: tests/cve.sh <phpscan-binary>   (exit 0 when every row holds)
set -u
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
manifest="$(cd "$(dirname "$0")" && pwd)/cve/manifest.tsv"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
fail=0
while IFS=$'\t' read -r cve ver role expect sum url; do
  case "$cve" in '#'*|'') continue;; esac
  dir=$(mktemp -d)
  file="$dir/$(basename "$url")"
  if ! curl -fsSL --retry 3 -o "$file" "$url"; then
    echo "FAIL $cve $ver: download failed: $url"; fail=1; rm -rf "$dir"; continue
  fi
  got=$(sha "$file")
  if [ "$got" != "$sum" ]; then
    echo "FAIL $cve $ver: sha256 $got, want $sum"; fail=1; rm -rf "$dir"; continue
  fi
  out=$("$bin" "$file" 2>/dev/null)
  code=$?
  case "$code" in
    0|1) ;;
    *) echo "FAIL $cve $ver: scanner exited $code"; fail=1; rm -rf "$dir"; continue;;
  esac
  rule=${expect#!}; rule=${rule%@*}; line=${expect#*@}
  if [ "$line" = '*' ]; then pat=":[0-9]+: \[$rule\]"; else pat=":$line: \[$rule\]"; fi
  if printf '%s\n' "$out" | grep -Eq "$pat"; then hit=yes; else hit=no; fi
  case "$expect" in '!'*) want=no;; *) want=yes;; esac
  if [ "$hit" = "$want" ]; then res=PASS; else res=FAIL; fail=1; fi
  echo "$res $cve $ver ($role) expect $expect sha256 ok"
  printf '%s\n' "$out" | sed "s|$dir/||; s|^|    |" | grep -v '^    $'
  rm -rf "$dir"
done < "$manifest"
exit $fail
