# phpscan v0.1.0

First standalone release of the PHP taint scanner extracted from the Bend tool.

- Native CLI archives for Linux and macOS on x86_64 and arm64.
- A version-pinned installer that verifies SHA-256 before replacing a binary.
- Text, GitHub annotation, and SARIF 2.1.0 output.
- Ten vulnerability rule classes and explicit incomplete-analysis status.
- PHP 8.2 through 8.5 fixtures and pinned vulnerable/fixed CVE regression inputs.

The binary needs no PHP, Bend, Bun, or compiler installation. Linux requires
glibc 2.35 or later. macOS requires version 13 or later. Both use system `find`
and `cat`. Windows and Alpine/musl are not supported. macOS binaries are not
notarized.

Install and scan with the commands in the README. Review the analysis limits
before using the results as a security gate. A clean scan does not establish
that the code is secure.
