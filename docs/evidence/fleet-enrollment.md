# Fleet enrollment verification

Verified on 2026-10-24. This is an installation snapshot, not the Fleet registry.

## Shipped registration

Fleet's private Gogs `jon/fleet` repository landed registration commit
`53dfe4b67fde2f85cdb9404fe7b1e86fb08c1d4d` through `fleet-land`.
The canonical checkout is `~/Code/github.com/jonbaldie/phpscan`.
It was appended without changing existing repository order or discovery offsets.
The repository is staged: automatic work is disabled; manual requests are available.

The first real install exposed a Fleet bug: legacy rollback reconciliation
selected only already-loaded roles and skipped newly registered ones.
A regression through the public installation CLI failed on the missing role.
Fleet commit `c7dad062bc7ae5613cc57fc69f91f3bf5c3bb257` fixed that selection,
recorded legacy ownership for idempotent retries, and retained removal behavior.
The regression, all installation CLI tests, and the merged-result full checks
passed before `fleet-land` shipped the fix. Gogs issue `#596` was closed only
after the real installation succeeded.

## Actual installed state

After `fleet-manager install --repo phpscan`:

- Every role derived from Fleet's registered pipeline definitions was present in `launchctl print gui/501/<label>`.
- The loaded arguments referenced the canonical checkout. Loaded definitions matched installed plists, and neither had calendars for this staged repository.
- Previously loaded services remained loaded. Active PIDs, existing plist bytes, and source configuration hashes were unchanged.
- The live installation still reported `legacy (rolled back)`. This enrollment did not change the fleet-wide control mode or claim event-active operation.
- GitHub ready-bug and ready-enhancement adapters returned verified empty queues; Fleet's readiness validators both exited `1`, meaning empty, not unavailable.
- The local adapters paginate every result page, exclude pull requests, and sort by creation time and issue number. Controlled transport probes covered multiple pages, ordering ties, query failures, and malformed responses.
- The GitHub release policy names the documented workflow and exact archive/checksum/installer asset set.

The local verification trail is under the workspace's
`.audit/phpscan-release/`: `fleet-loaded-roles.json`,
`fleet-operational-before.json`, `fleet-after-status.txt`, `fleet-after-events.json`,
`fleet-rollback-red.txt`, `fleet-rollback-green.txt`, and `fleet-rollback-land.txt`.
These files are local operational evidence, not publicly hosted Fleet logs.

## Automatic-work boundary

No phpscan remote source or production recovery checkpoint was configured.
No public receiver endpoint was available in the existing installation, and the
live fleet intentionally remained rolled back. The verified result is staged,
loaded manual operation, not automatic event admission. Source coverage and
promotion remain separate Fleet operations; this record does not assert them.
