# Applied skills

This record describes actions in the extraction/release session, not an
independent review. Only one coding agent was available. Parallel sub-agents
and cross-model review were not run. Role reviews used fresh serial passes.

## `/writing-for-agents`

Read `/Users/jonathanbaldie/.agents/skills/writing-for-agents/SKILL.md`.
SHA-256: `551adca942227b44192edba88acd4e8db911f0121ce58ad16944ccf6a896a74a`.

The skill changed the documentation structure:

- README.md starts with a copyable installation and first-scan task. Its output and exit status are explicit.
- AGENTS.md starts with ordered work steps and a binary completion check: build, tests, lint, and the requested behavior must pass.
- Rule behavior, CI upload handling, contributor setup, and publication steps live behind task-specific links rather than filling the always-loaded guide.
- Context pointers lead with the triggering task: scanner rules, installer/release, CI, issues/triage, shipping, domain terms, or provenance.
- Each guide keeps its definitions and caveats together. The scanner reference contains the analysis limits; the release procedure contains its publication gate and trust limits.

Reviewed README.md and AGENTS.md sentence by sentence against the skill's
hierarchy, pointer, completion, and pruning rules. Removed an unnecessary
repeated tracker summary from AGENTS.md when adding the authoritative tracker
pointer. `make lint` validates local Markdown link targets as well as source.
The first-scan command is verified with the actual native binary.

## `/poteto-mode`

Read `/Users/jonathanbaldie/Code/pstack/.agents/skills/poteto-mode/SKILL.md`.
SHA-256: `923d54375f398f1850c7cf4465fa805bc2938c6fc2e43a561f7dbfbf9bf7b937`.

The session read the router, autonomous-run playbook, and the leaf skills below
before applying their principles. A plan and decision log live in the local
workspace audit at `.audit/phpscan-release/`.

| Read leaf | Decision it changed |
| --- | --- |
| `principle-build-the-lever` | Added repeatable native builds, archive verification, and public-install CI instead of one-off binaries. |
| `principle-laziness-protocol` | Retained Bend's scanner and generated native C rather than rewriting the analysis. |
| `principle-prove-it-works` | Required execution of binaries downloaded from the actual published release. |
| `principle-sequence-verifiable-units` | Verified the original baseline, extraction, archives, publication, and fleet enrollment separately. |
| `principle-model-the-domain` | Put the version in one module and the supported platform tuples in one matrix file. |
| `principle-test-behavior-not-implementation` | Asserted real CLI output, exit codes, reports, and installer filesystem effects. |
| `principle-fix-root-causes` | Reproduced Fleet's missing-role installation bug through its public CLI, fixed rollback reconciliation, and repeated the real installation instead of manually loading plists. |

The design pass traced source ownership and the compiler/runtime boundary,
compared native archives with a runtime launcher, and chose native archives.
[The design record](../release-design.md) contains the alternatives and reasons.

The arena/reviewer fallback was serial: implementation, tests, documentation,
then a fresh verification pass. The `no-comments` pass covered newly authored
packaging code and changed CLI blocks, with no application-code edits or
comment deletions required. Preserved scanner files were excluded from comment
cleanup to keep the extraction byte-identical. No lint suppressions were added.

The test-evidence audit found all 19 Python test methods production-grounded:
10 execute the native CLI; 9 execute the real installer. Their assertions trace
to stdout/stderr, exit status, report JSON, installed bytes, or preservation of
an existing binary. Only download transport is controlled locally. Public
release verification uses real HTTPS downloads instead.

## Fleet setup

Read Fleet's enrollment skill, artifact checklist, installation guide, tracker
adapter contracts, and shipping rules. Used the documented GitHub tracker and
default triage roles for this new GitHub repository. The user requested an
autonomous run, so the interactive setup template's defaults were selected
without an interview. Tracker, triage, domain, and shipping policies are
recorded under `docs/agents/`.

[The enrollment verification](fleet-enrollment.md) distinguishes shipped
membership, actual loaded roles, and staged manual operation. The first live
installation failed its loaded-role check despite returning success. The
root-cause fix and red/green regression shipped separately in Fleet before the
installation was repeated. Existing jobs, active PIDs, definitions, and source
configuration were verified unchanged. A registry edit alone was not accepted
as proof of a loaded service.
