# phpscan

Find likely injection vulnerabilities in PHP source before you ship.
phpscan tracks request data into dangerous operations and reports the file,
line, and rule. It scans source without running PHP.

## Install the CLI

Download a native binary for Linux or macOS. You do not need PHP, Bend, Bun,
or a compiler.

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/jonbaldie/phpscan/v0.1.0/install.sh -o install-phpscan.sh
sh install-phpscan.sh v0.1.0
export PATH="$HOME/.local/bin:$PATH"
phpscan --version
```

Expected output is `phpscan 0.1.0`. The installer verifies the release's
SHA-256 checksum and installs to `~/.local/bin`. To choose another directory,
set `PHPSCAN_INSTALL_DIR` when you run the installer. Run the installer without
a version to select the latest release.

The [release page](https://github.com/jonbaldie/phpscan/releases) also has
archives and `SHA256SUMS` for manual installation.

Supported hosts are Linux with glibc 2.35 or later, and macOS 13 or later,
on x86_64 or arm64. The CLI uses the system's `find` and `cat` commands.
Alpine/musl and Windows are not supported. macOS binaries are not notarized.

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

Use `--format=github` for GitHub annotations or `--format=sarif` for SARIF 2.1.0.
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
