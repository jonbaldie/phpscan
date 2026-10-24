# Native build recovery

These are pre-publication build results, not proof that a public release exists.
See the [release record](https://github.com/jonbaldie/phpscan/releases/tag/v0.1.0)
for published assets and post-publication installation results.

## Observed failure

The [initial run](https://github.com/jonbaldie/phpscan/actions/runs/40094276127)
completed three native jobs, but the macOS arm64 job remained in Bend C emission
for over 20 minutes. It was cancelled to obtain logs. The log did not report
an explicit out-of-memory error.

Local profiling with Bend 2.0.38 and Bun 1.3.14 measured:

| C emission | Elapsed time | Peak memory footprint |
| --- | --- | --- |
| Default Bun | 127.74 s | 17,050,728,368 bytes |
| `bun --smol` | 69.43 s | 14,325,624,616 bytes |

The generated C files were byte-identical. Both footprints were high, so a
Bun flag was not selected as the remedy. These measurements support memory
pressure as a diagnosis; they do not establish a hosted OOM event.

## Change and portability check

[PR #2](https://github.com/jonbaldie/phpscan/pull/2) separated C emission and
source checks from native compilation. Linux now generates one C artifact;
each supported target compiles, tests, packages, and installs it natively.
`make build` still performs both stages for contributors.

Portability was checked, not assumed. Bend's host-sensitive `process.platform`
and `process.arch` branches inspected in `comp.ts` belong to the JavaScript
`io_sys` runtime. The emitted C uses `__APPLE__` and `__linux__` preprocessor
guards, evaluated by each native compiler. Execution on every target then
checked the actual result rather than relying on that inspection alone.

## Results

- [PR CI](https://github.com/jonbaldie/phpscan/actions/runs/40097150253): C generation passed in 1m58s; macOS arm64 passed in 1m12s. All four native targets, PHP 8.2–8.5 jobs, and CVE checks passed.
- [Merged-main CI](https://github.com/jonbaldie/phpscan/actions/runs/40097618798) passed at `9c92ec9071771b387c6ffacf43e8466960462dfc`.
- Local `make setup build test lint cves package` and archive verification passed. A separate `make compile test` reused C without emitting it again.
- Missing C and invalid build-stage arguments returned 2. No analysis-module changes were made: lexer, tree, and scanner still matched the extraction source byte for byte.

The native jobs exercise fixture findings, 10 CLI tests, 9 real-installer tests,
and archive installation/execution. Controlled local download transport is
not evidence of publication. Only tagged workflows install public assets.
