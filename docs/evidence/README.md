# Verification evidence

## Source provenance

The scanner was extracted from Jonathan Baldie's local `bend/phpscan` at
commit `0a75438189e8309fc67241c004ac85f2eb721979`.
`src/lex.bend`, `src/tree.bend`, and `src/scan.bend` preserve the original source.
The standalone CLI adds help, a version, GitHub property escaping, and the
correct precedence of incomplete-analysis status over findings.

[The extraction baseline](original/extraction-fixtures.txt) records the original
native binary's fixture run. Other files under `original/` are historical
upstream run outputs copied from the source tool. They are not evidence of
this release's hosted build.

## Documentation and engineering method

[The skill application record](skill-application.md) identifies the requested
skills, their actual source hashes, the choices they changed, and the checks
used on README.md and AGENTS.md.
[The release design](../release-design.md) records the source trace, alternatives,
and serial execution limits of this session.

## Repeat the checks

Run `make setup build test lint cves package`, then
`bash scripts/verify-archive.sh dist/phpscan-*.tar.gz`.
The [workflow](../../.github/workflows/ci.yml) runs native checks on all four
platform tuples. Tagged runs also install and execute the public release.
Subprocess tests check actual findings, reports, exit codes, installed bytes,
and refusal to overwrite an existing binary after a corrupt download.

Public-release and fleet-registration evidence is added after those operations
complete. Local compilation and desired fleet configuration do not prove either.
