# Work on phpscan

phpscan is a native PHP taint scanner written in Bend. Preserve its scanner
implementation when changing distribution code.

## Complete a change

1. Read [CODING_STANDARDS.md](CODING_STANDARDS.md) before editing code or tests.
2. Read [development](docs/development.md) for toolchain setup and source ownership.
3. Reproduce a behavior change through the CLI, then add a regression test that fails before the fix.
4. Run `make setup build test lint`. For analysis changes, also run `make cves`.
5. Read the diff. Commit only when those checks pass. Report the commands and actual outcomes.

Done means the requested behavior works through the built binary, all required
checks pass, and the diff contains no unrelated files. A local build is not
release evidence.

## Read when the task applies

- **Scanner rules or parsing.** Read [rule behavior and limits](docs/reference.md). Keep findings deterministic and incomplete analyses at exit 2.
- **Installer or release.** Read [release procedure](docs/releasing.md). Test the installed archive and checksum rejection before publishing.
- **CI examples.** Read [CI integration](docs/ci.md). Preserve exit 1 for findings and exit 2 for failures when uploading reports.
- **Issues or triage.** Read [issue tracker](docs/agents/issue-tracker.md) and [triage labels](docs/agents/triage-labels.md).
- **Shipping.** Read [agent workflow](docs/agents/workflow.md).
- **Domain terms or decisions.** Read [domain documentation](docs/agents/domain.md).
- **Project provenance or prior verification.** Read [release evidence](docs/evidence/README.md). Historical logs describe their recorded runs, not current verification.

`LAWS.bend` states the extracted scanner invariant. Preserve the law's meaning
and update `PROOF.bend` with relevant implementation changes.
Run `scripts/bend.sh PROOF.bend` to check it. The proof concerns suppression, not scanner completeness.
