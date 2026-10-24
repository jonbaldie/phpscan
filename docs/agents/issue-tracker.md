# Issue tracker: GitHub

Issues and specifications live in `jonbaldie/phpscan` on GitHub.
Use the authenticated `gh` CLI from this checkout; it resolves `origin`.
Use `--repo jonbaldie/phpscan` when running elsewhere.

- Create: `gh issue create --title "..." --body-file report.md`.
- Read: `gh issue view NUMBER --comments`.
- Comment: `gh issue comment NUMBER --body "..."`.
- Label: `gh issue edit NUMBER --add-label "..."`.
- Close: `gh issue close NUMBER --comment "..."`.

## Ready queues

Bugs are open issues with both `bug` and `ready-for-agent`.
Enhancements are open issues with both `enhancement` and `ready-for-agent`.
Order ready issues by creation time, then issue number. Read every page.
A failed tracker query is unavailable, not an empty queue.

An issue is ready when it states the input or task, expected result,
verification command, and scope clearly enough for unattended implementation.
Close it after the change lands on `origin/main` with passing checks.
Comment with the landed revision and verification results before closure.

The role-to-label mapping is in [triage labels](triage-labels.md).
The shipping procedure is in [workflow](workflow.md).

## Pull requests as a triage surface

**PRs as a request surface: no.** Pull requests carry changes; GitHub issues
carry triage and ready-queue requests.
