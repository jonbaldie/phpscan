# Run phpscan in CI

## Fail a job on findings

Use the pinned installer on any supported Linux or macOS runner:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/jonbaldie/phpscan/v0.1.0/install.sh -o install-phpscan.sh
PHPSCAN_INSTALL_DIR="$PWD/.phpscan-bin" sh install-phpscan.sh v0.1.0
./.phpscan-bin/phpscan src/
```

The scan exits 0 when clean, 1 for findings, and 2 for an error or reported
incomplete analysis. Let your CI service keep that status. Use a version tag,
not `latest`, for repeatable jobs.

## Upload SARIF in GitHub Actions

This example preserves scan failure and uploads the report when one exists.
GitHub code scanning must be available and enabled for your repository.
Public repositories can use code scanning. Private repositories can require
GitHub Code Security.

```yaml
name: PHP security scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - name: Install phpscan
        run: |
          curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/jonbaldie/phpscan/v0.1.0/install.sh -o "$RUNNER_TEMP/install-phpscan.sh"
          PHPSCAN_INSTALL_DIR="$RUNNER_TEMP/phpscan-bin" sh "$RUNNER_TEMP/install-phpscan.sh" v0.1.0
          echo "$RUNNER_TEMP/phpscan-bin" >> "$GITHUB_PATH"
      - name: Scan PHP
        id: scan
        run: phpscan --format=sarif src/ > phpscan.sarif
      - name: Upload SARIF
        if: always() && hashFiles('phpscan.sarif') != ''
        uses: github/codeql-action/upload-sarif@4bfa242aa49c5f7c6770b98670d354a7dfac05f8 # v3
        with:
          sarif_file: phpscan.sarif
```

For inline annotations without code scanning, replace the scan and upload
steps with `phpscan --format=github src/`.

If installation fails, the job fails before the scan. A scan error can leave
an empty report, which the upload action can also reject. The scan step's
failure remains visible. Review [the analysis limits](reference.md#analysis-limits)
before making the scanner your only security gate.

The repository's [CI workflow](../.github/workflows/ci.yml) exercises native
archives, an installed binary, SARIF generation, CVE regressions, and PHP
8.2 through 8.5 fixtures. A tagged release also installs the public assets
on all supported platform tuples.
