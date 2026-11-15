#!/usr/bin/env bash
# Fetch each pinned upstream file in tests/cve/manifest.tsv into its own new
# empty directory, check its sha256, scan it and check the expectation.
# Downloads are data: nothing in them is executed.
# Usage: tests/cve.sh <phpscan-binary>   (exit 0 when every row holds)
set -u
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
manifest="$(cd "$(dirname "$0")" && pwd)/cve/manifest.tsv"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
verdict=passing
while IFS=$'\t' read -r cve ver role expect sum url; do
  case "$cve" in '#'*|'') continue;; esac
  dir=$(mktemp -d)
  file="$dir/$(basename "$url")"
  phase=download
  while :; do
    case "$phase" in
      download)
        if curl -fsSL --retry 3 -o "$file" "$url"; then
          phase=verify
        else
          echo "FAIL $cve $ver: download failed: $url"
          verdict=failed
          phase=cleanup
        fi
        ;;
      verify)
        got=$(sha "$file")
        if [ "$got" = "$sum" ]; then
          phase=scan
        else
          echo "FAIL $cve $ver: sha256 $got, want $sum"
          verdict=failed
          phase=cleanup
        fi
        ;;
      scan)
        out=$("$bin" "$file" 2>/dev/null)
        code=$?
        case "$code" in
          0|1) phase=expectation;;
          *) echo "FAIL $cve $ver: scanner exited $code"; verdict=failed; phase=cleanup;;
        esac
        ;;
      expectation)
        rule=${expect#!}; rule=${rule%@*}; line=${expect#*@}
        if [ "$line" = '*' ]; then pat=":[0-9]+: \[$rule\]"; else pat=":$line: \[$rule\]"; fi
        if printf '%s\n' "$out" | grep -Eq "$pat"; then hit=yes; else hit=no; fi
        case "$expect" in '!'*) want=no;; *) want=yes;; esac
        if [ "$hit" = "$want" ]; then res=PASS; else res=FAIL; verdict=failed; fi
        echo "$res $cve $ver ($role) expect $expect sha256 ok"
        printf '%s\n' "$out" | sed "s|$dir/||; s|^|    |" | grep -v '^    $'
        phase=cleanup
        ;;
      cleanup)
        rm -rf "$dir"
        break
        ;;
      *) echo "FAIL $cve $ver: invalid fixture phase $phase"; verdict=failed; phase=cleanup;;
    esac
  done
done < "$manifest"
case "$verdict" in passing) exit 0;; failed) exit 1;; esac
