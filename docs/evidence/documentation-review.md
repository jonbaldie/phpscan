# Documentation review

Reviewed on 2026-10-24. This records the cleanup, not live verification status.
The scanner implementation, published release assets, and Fleet settings did
not change.

## Purpose and current coverage

[README.md](../../README.md) and [AGENTS.md](../../AGENTS.md) now state the goal
of identifying security vulnerabilities and CVEs in source for public,
internet-facing PHP applications. Both distinguish that goal from the current
unsafe-code checks. [CVE coverage](../reference.md#cve-coverage) explains why
the existing vulnerable/fixed fixtures do not establish project-level CVE
detection. Advisory matching and checks for calls to affected dependency code
remain unimplemented.

## Version and path audit

- Replaced the release tag repeated in the README's download URL, installer argument, and expected output. The README now downloads the latest release's installer, runs it without a version argument, and describes the version output without a fixed number.
- Moved minimum host versions to the platform reference. The output reference already specifies the SARIF schema version. AGENTS.md had no version literals to remove.
- Kept `--tlsv1.2` as the download's minimum TLS setting and `Apache-2.0` as the runtime license identifier. Neither is a cached application version. CI examples keep deliberate release pins for repeatability.
- Reviewed every root Markdown file and every file under `docs/`, including JSON and historical reports. Removed private checkout and audit locations, private log filenames, and the operator-specific service identifier. Skill evidence retains names, hashes, and read results without private paths or session identifiers.
- Changed extraction fixture paths to match this repository's layout. Finding counts and other historical outputs are unchanged.

## `/unslop` and `/writing-for-agents`

Read both skills and reviewed every changed Markdown sentence against them.
This was a serial writing review, not an automated command or independent
review. The [read audit](skill-reads.json) records the source hashes and
successful read timestamps under `documentation_review`.

| Passage before review | Edit | Applied rule |
| --- | --- | --- |
| "Find likely injection vulnerabilities in PHP source before you ship." | State the intended CVE purpose, then explain the current request-data checks and missing CVE checks. | `/unslop` 27, concrete facts instead of a general promise. |
| "It was appended without changing existing repository order or discovery offsets." | "The registration appended phpscan without changing existing repository order or discovery offsets." | `/unslop` 29, name the actor. |
| "Subprocess tests check actual findings, reports, exit codes, installed bytes, and refusal to overwrite an existing binary after a corrupt download." | Split the test description. State separately that a corrupt download leaves the existing binary unchanged. | `/unslop` 28 and 30, split the dense sentence and remove the redundant modifier. |
| A fixed version appears in the download URL, installer invocation, and expected output. | Use the latest release for first-time installation. Keep deliberate CI pins in the CI guide. | `/writing-for-agents`, remove cached facts and keep task-specific detail behind pointers. |

The review also checked sentence-case headings, plain words, straight quotes,
and punctuation. Changed prose contains no em dashes. Commands, rule names,
and historical scanner results keep their technical meaning.

## Documentation-policy regression

[The checker](../../scripts/check-docs.py) now scans documentation and evidence
for machine-specific paths and rejects cached versions in README.md and
AGENTS.md. It still validates local Markdown links. It allows portable paths,
license identifiers, and versions in reference guides and historical records.

[The regression tests](../../tests/test_docs.py) execute the real checker in a
temporary documentation tree. They assert its exit status and diagnostics,
not values supplied by a mock. All eight tests are production-grounded. No
test-local, test-layer-only, or unclear tests were found in this test file.

Before the fix, the link-only checker accepted all 34 prohibited examples.
The regression run failed with 34 assertion failures. After the fix, all eight
tests pass, including valid links, a missing link, private paths in prose and
JSON/SARIF/text evidence, and release/toolchain versions in both entry guides.
`make test` runs these checks on native CI workers, and `make lint` checks the
repository's documentation.

## Executed checks

- `make setup build test lint cves package` passed. The run covered PHP fixtures, the CLI and real installer, the documentation checker, and the pinned vulnerable/fixed CVE cases.
- Archive verification, ShellCheck, actionlint, and `git diff --check` passed. The documentation check covered 26 files and 51 local links, with no prohibited paths or cached entry-guide versions.
- The README's exact installation and first-scan blocks passed in a temporary home directory using real public HTTPS downloads. The installer matched its published asset digest, the version output matched the public release, and the example finding and exit 1 matched the README.
- A sanitized counterpart exited 0 and an invalid option exited 2. Guards for PHP, Bend, Bun, and compiler commands recorded no calls.
- Every file under `src/` matched its pre-change SHA-256. These documentation checks do not establish new scanner coverage or a new binary release.
