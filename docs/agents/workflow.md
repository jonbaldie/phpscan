# Issues and shipping

## Use the tracker

Use GitHub issues at `jonbaldie/phpscan`. Query with
`gh issue list --repo jonbaldie/phpscan`. Keep bug reports reproducible with
source input, the exact CLI command, expected output, and observed output.

Use `bug` or `enhancement` for the issue kind. Triage with `needs-triage`,
`needs-info`, `ready-for-agent`, `ready-for-human`, or `wontfix`.
Only mark an issue `ready-for-agent` when its expected behavior and verification
are clear enough to implement without another product decision.

## Ship a change

1. Start a topic branch from the current `origin/main`.
2. Make the scoped change and run the checks in [AGENTS.md](../../AGENTS.md).
3. Open a pull request to `main` with the problem, change, and verification commands.
4. Wait for all CI jobs to pass on the pull request's current revision.
5. Merge the passing pull request and synchronize local `main`.

Done means the requested change is on `origin/main` and checks pass there.
Release binaries only through [the release procedure](../releasing.md).
Never describe an unpublished local archive as a released artifact.
