When using Bend:

- run `bend guide` to learn it
- use `LAWS.bend` to keep important rules
- run `bend PROOF.bend` before committing
- parallelize the code whenever possible

# Work on phpscan

Build phpscan to identify security vulnerabilities and CVEs in source code for
public, internet-facing PHP applications. The current Bend scanner detects
unsafe uses of request data. Offline advisory matching covers a pinned Composer
snapshot. A bounded Symfony profile adds possible path-prefix authorization
check evidence. Other affected-code flows remain unknown.
Preserve the scanner implementation when changing distribution code.

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
- **CVE detection.** Read [CVE coverage](docs/reference.md#cve-coverage). Verify advisory and version matches separately from possible calls to affected code. Report missing evidence as unknown.
- **Installer or release.** Read [release procedure](docs/releasing.md). Test the installed archive and checksum rejection before publishing.
- **CI examples.** Read [CI integration](docs/ci.md). Preserve exit 1 for findings and exit 2 for failures when uploading reports.
- **Shipping.** Read [agent workflow](docs/agents/workflow.md).
- **Project provenance or prior verification.** Read [release evidence](docs/evidence/README.md). Historical logs describe their recorded runs, not current verification.

`LAWS.bend` states the extracted scanner invariant. Preserve the law's meaning
and update `PROOF.bend` with relevant implementation changes.
Run `scripts/bend.sh PROOF.bend` to check it. The proof concerns suppression, not scanner completeness.

## Agent skills

### Issue tracker

Issues live in `jonbaldie/phpscan` on GitHub. Read [issue tracker](docs/agents/issue-tracker.md) when working with issues or specifications.

### Triage labels

Use the five default triage roles. Read [triage labels](docs/agents/triage-labels.md) when classifying issues.

### Domain docs

Single-context: root `GLOSSARY.md` and `docs/adr/`. Read [domain documentation](docs/agents/domain.md) when naming concepts or recording decisions.
