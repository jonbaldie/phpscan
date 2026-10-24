#!/usr/bin/env bash
# Compare phpscan findings with the `// expect: RULE...` comments in fixtures.
# Usage: tests/check.sh <phpscan-binary> <fixture.php>...
# Exit 0 when every fixture matches exactly, 1 otherwise.
set -u
bin=$1; shift
fail=0
for f in "$@"; do
  want=$(grep -n 'expect: ' "$f" | sed -E 's/^([0-9]+):.*expect: (.*)$/\1 \2/' |
    awk '{for (i = 2; i <= NF; i++) print $1, $i}' | sort)
  raw=$("$bin" "$f" 2>&1)
  code=$?
  got=$(printf '%s\n' "$raw" | sed -nE 's/^.*:([0-9]+): \[([A-Z-]+)\].*$/\1 \2/p' | sort)
  if [ -n "$want" ]; then expected_code=1; else expected_code=0; fi
  if [ "$want" = "$got" ] && [ "$code" -eq "$expected_code" ]; then
    echo "PASS $f ($(printf '%s\n' "$want" | grep -c .) findings)"
  else
    echo "FAIL $f (exit $code, want $expected_code)"
    printf '%s\n' "$raw"
    diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | sed 's/^</  missing:/; s/^>/  unexpected:/' | grep -E 'missing|unexpected'
    fail=1
  fi
done
exit $fail
