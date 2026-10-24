# Release native binaries

## Prepare the version

1. Start from the current `origin/main` with a clean checkout.
2. Update `src/version.bend` and the version-specific CLI assertions and examples.
3. Update [release notes](release-notes.md).
4. Run `make setup build test lint cves package`.
5. Run `bash scripts/verify-archive.sh dist/phpscan-*.tar.gz`.
6. Merge the change after the entire native and PHP-version CI matrix passes.

## Publish the tag

1. Confirm that `main` contains the intended release commit and its CI run passed.
2. Set `version=$(bash scripts/version.sh)`.
3. Run `git tag -a "v$version" -m "Release phpscan $version"`.
4. Run `git push origin "v$version"`.
5. Wait for the tag's complete `CI and release` workflow to pass.

The workflow generates portable C once on Linux, then compiles every tuple
from `scripts/platforms.json` natively. This keeps the high-memory Bend emission
step off low-memory native workers. It tests each native binary and archive,
checks the PHP syntax matrix and CVE regressions, and publishes the archives
with `SHA256SUMS` and `install.sh`.
Linux builds use a pinned Ubuntu 22.04 image and clang 14 for a glibc 2.35
baseline. macOS builds target macOS 13. Archives contain the binary,
build metadata, and both project and runtime licenses.

Only the publication job has release-write permission. Tags must match
`src/version.bend`. A failed platform or regression job blocks publication.
The final jobs download through the public release URLs, verify checksums
with the actual installer, and execute the installed binaries on every tuple.
If post-publication verification fails, the workflow is red even though the
release already exists. Investigate and ship a new version. Keep published
version tags fixed.

## Verify the published result

1. Query `gh release view "v$version" --repo jonbaldie/phpscan` and check the assets.
2. Install with `PHPSCAN_INSTALL_DIR="$(mktemp -d)" sh install.sh "v$version"`.
3. Run `--version`, a vulnerable scan, a sanitized scan, and SARIF output with the installed binary.
4. Append the release URL, tag revision, CI run URL, downloaded checksums, and actual results to the GitHub release notes. Link that release record from `docs/evidence/`.

Keep post-publication outcomes in the release record so recording them does not
create another unreleased source commit.

Done means the release is public, all expected assets exist, the tag workflow
including public-install verification is green, and the installed CLI behaves
as documented. A tag or a successful upload alone is not completion.

SHA-256 detects download corruption. The checksums and archives come from the
same GitHub release. They are not an independent signature. macOS binaries
are not Apple-notarized.
