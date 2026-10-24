# phpscan

phpscan's goal is to identify security vulnerabilities and CVEs in the source
code of public, internet-facing PHP applications.

The current scanner finds unsafe uses of request data and reports the file,
line, and rule without running PHP. It does not yet match dependency versions
to CVE advisories or check whether your application can call the affected code.
See [CVE coverage](docs/reference.md#cve-coverage) for what the existing tests show.

## Install the CLI

Download a native binary for Linux or macOS. You do not need PHP, Bend, Bun,
or a compiler.

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/jonbaldie/phpscan/releases/latest/download/install.sh -o install-phpscan.sh
sh install-phpscan.sh
export PATH="$HOME/.local/bin:$PATH"
phpscan --version
```

The command prints `phpscan` followed by the installed version. The installer
selects the latest release, verifies its SHA-256 checksum, and installs to
`~/.local/bin`. To choose another directory, set `PHPSCAN_INSTALL_DIR` when
you run the installer.

The [release page](https://github.com/jonbaldie/phpscan/releases) also has
archives and `SHA256SUMS` for manual installation.

Supported hosts are Linux with glibc and macOS, on x86_64 or arm64. Check the
[minimum system requirements](docs/reference.md#supported-platforms) before
installing. The CLI uses the system's `find` and `cat` commands.

## Run your first scan

```sh
printf '%s\n' '<?php echo $_GET["name"];' > example.php
phpscan example.php
```

The command prints a finding and exits with code 1:

```text
example.php:1: [PHP-XSS] cross-site scripting: request data reaches echo (CWE-79)
```

The summary goes to stderr. Scan a project directory with:

```sh
phpscan src/
```

Directories include `.php`, `.phtml`, and `.inc` files. A clean scan exits 0.
Usage errors, unreadable paths, and incomplete analysis exit 2.
A clean result does not prove that the code is secure. Review findings and
read the [analysis limits](docs/reference.md#analysis-limits).

## Use phpscan in CI

Use `--format=github` for GitHub annotations or `--format=sarif` for SARIF.
See the [CI integration guide](docs/ci.md) for a version-pinned workflow that
uploads reports without hiding scan failures. Any CI service can install the
CLI with the same installer and run `phpscan src/`.

## Find the next guide

- [Rules, sanitizers, suppression, and limits](docs/reference.md).
- [Build, test, and contribute](docs/development.md).
- [Release a version](docs/releasing.md).
- [Verification and source provenance](docs/evidence/README.md).

phpscan is [MIT-licensed](LICENSE). Binary archives include the
[Bend runtime's Apache-2.0 license](THIRD_PARTY_NOTICES.md).
