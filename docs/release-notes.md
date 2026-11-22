# phpscan v0.2.0

This release adds offline matching of installed Composer dependencies against a
small embedded advisory catalog, alongside improvements to source analysis and
file discovery.

- Report affected dependency versions separately from evidence of affected code.
  The catalog covers selected Livewire, Symfony and Laravel advisories; it is
  not a complete advisory database.
- Track request data through `parse_str` results and restore taint after modeled
  HTML entity decoders.
- Scan explicitly named files and symlinked files, deduplicate overlapping
  inputs, and honor suppressions on the finding line.
- Escape line breaks in text findings and report incomplete analysis as exit 2.

Native archives support Linux with glibc 2.35 or later and macOS 13 or later,
on x86_64 and arm64. Windows and Alpine/musl are not supported. macOS binaries
are not notarized. The installer verifies SHA-256 checksums supplied with the
release; these are not independent signatures.

See the README for installation and the reference for advisory coverage and
analysis limits. A clean scan does not establish that code is secure.
