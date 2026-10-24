# Coding standards

## Bend

- Use two-space indentation and the existing affine types and module conventions.
- Keep tokenization in `src/lex.bend`, bracket grouping in `src/tree.bend`, taint analysis in `src/scan.bend`, and CLI I/O in `src/main.bend`.
- Keep analysis pure. Discover and read files only at the CLI boundary.
- Bound recursive analysis with fuel. Emit `PHP-INCOMPLETE` and exit 2 when analysis is incomplete, even if findings exist.
- Preserve deterministic path, line, and rule ordering. Escape external values for their output format.
- Model a sanitizer only for the vulnerability classes it actually removes. Add unsafe and sanitized examples together.
- Preserve the meaning of `LAWS.bend`. A passing suppression proof is not a claim of complete security coverage.

## Distribution scripts

- Use POSIX `sh` for the user installer. Contributor scripts may use Bash 3.2-compatible syntax.
- Quote paths and arguments. Pass scanned paths as literal process arguments, not shell programs.
- Use temporary directories with cleanup. Verify checksums and executable behavior before replacing an installed binary.
- Keep the application version in `src/version.bend`. Derive package metadata from it.
- Pin downloaded language toolchains and GitHub Actions revisions. Record the native compiler in build metadata. Keep publication permissions in the release job.
- Build portable CPU code. Use no host-specific instruction flags or GPU runtime requirement.

## Tests and verification

- Run the real scanner or installer and assert literal output, exit status, or filesystem changes.
- Keep fixture `expect:` comments independent of scanner output. Check missing and unexpected findings and the scanner's exit status.
- Pair clean inputs with vulnerable inputs. Treat download errors and incomplete scans as failures, never clean results.
- Control only external transport in installer tests. Execute the actual installed binary afterward.
- Keep network-dependent CVE tests separate from offline tests. Verify each upstream file's pinned checksum.
- Run `make setup build test lint` before shipping. Run `make cves` for scanner changes and releases.

## Documentation

Write commands a new user can copy. Show the expected result and exit status.
Keep README.md focused on installation and the first scan. Put CI, reference,
and contributor procedures in their linked task-specific documents.
Use short instructions with explicit completion checks in agent documents.
Keep comments for reasons the code cannot show.
