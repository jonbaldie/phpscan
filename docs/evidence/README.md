# Verification evidence

## Source provenance

The scanner extraction source revision is
`0a75438189e8309fc67241c004ac85f2eb721979`.
`src/lex.bend`, `src/tree.bend`, and `src/scan.bend` preserve the original source.
The standalone CLI adds help, a version, GitHub property escaping, and the
correct precedence of incomplete-analysis status over findings.

[The extraction baseline](original/extraction-fixtures.txt) records the original
native binary's fixture run. Other files under `original/` are historical
upstream run outputs copied from the source tool. They are not evidence of
this release's hosted build. The extraction report now uses this repository's
relative fixture paths. Finding counts are unchanged.

## Documentation and engineering method

[The skill application record](skill-application.md) identifies the requested
skills, their actual source hashes, the choices they changed, and the checks
used on README.md and AGENTS.md.
[The release design](../release-design.md) records the source trace, alternatives,
and serial execution limits of this session.
[The build recovery record](build-memory.md) shows the observed native-runner
stall, profiling, portability check, and successful replacement CI.
[The documentation review](documentation-review.md) records the version and
path audit, concrete `/unslop` edits, and documentation-policy checks.

## Repeat the checks

Run `make setup build test lint cves package`, then
`bash scripts/verify-archive.sh dist/phpscan-*.tar.gz`.
The [workflow](../../.github/workflows/ci.yml) runs native checks on all four
platform tuples. Tagged runs also install and execute the public release.
Subprocess tests check findings, reports, exit codes, and installed bytes.
They also check that a corrupt download leaves an existing binary unchanged.

[Fleet enrollment verification](fleet-enrollment.md) records the shipped
registry changes, actual loaded roles, and staged/manual control mode.
The [v0.1.0 release record](https://github.com/jonbaldie/phpscan/releases/tag/v0.1.0)
is the destination for published asset checksums, the tag-workflow result, and
actual public-install results. Those outcomes are recorded in the release notes
after publication, without creating a new unreleased source commit. Local
compilation and pre-publication CI do not prove that a public release exists.
