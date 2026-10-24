#!/usr/bin/env bash
# `php -l` every version fixture under every supported PHP release, in the
# official php:<v>-cli images. A fixture for 8.x must pass on 8.x and later
# and fail on every earlier release: that shows it really uses 8.x syntax.
# Usage: tests/lint-matrix.sh   (needs docker; exit 0 when the matrix holds)
set -u
here=$(cd "$(dirname "$0")/versions" && pwd)
versions="8.2 8.3 8.4 8.5"
fail=0
for v in $versions; do
  echo "php:$v-cli $(docker run --rm --network none "php:$v-cli" php -r 'echo PHP_VERSION;')"
done
for f in "$here"/php8*.php; do
  name=$(basename "$f" .php)
  need="8.${name#php8}"
  for v in $versions; do
    out=$(docker run --rm --network none -v "$here:/src:ro" "php:$v-cli" php -l "/src/$name.php" 2>&1 | grep -v '^$' | head -1)
    if printf '%s' "$out" | grep -q '^No syntax errors'; then ok=pass; else ok=fail; fi
    if [ "$(printf '%s\n%s\n' "$need" "$v" | sort -V | head -1)" = "$need" ]; then want=pass; else want=fail; fi
    if [ "$ok" = "$want" ]; then mark=OK; else mark=WRONG; fail=1; fi
    echo "$mark $name on $v: lint $ok (want $want): $out"
  done
done
exit $fail
