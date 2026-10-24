# Release design

## Ground

The original `main.bend` owns arguments, file discovery, process-based reads, formatting, and exit status. `lex.bend` turns PHP text into tokens, `tree.bend` groups brackets, and `scan.bend` evaluates taint and function summaries. `Src` becomes `Rep`, then stdout findings and a stderr summary. No PHP interpreter runs the scanned files. The native binary uses the system's `find` and `cat` commands. The original fixture suite passed against a native arm64 binary at source commit `0a75438189e8309fc67241c004ac85f2eb721979`.

Bend 2.0.38 emits C and compiles it with clang, `-std=c11 -O3 -lpthread -lm`, without host-specific instruction flags. Its generated runtime is Apache-2.0. The compiler archive is pinned by SHA-256. Linux Process.run requires glibc 2.34 or later. Building both Linux architectures inside Ubuntu 22.04 gives a documented glibc 2.35 baseline. macOS builds target macOS 13. Native binaries require neither Bend nor Bun nor PHP.

Fleet owns membership in `bin/fleet_manager.py`. Appending preserves discovery offsets. New enrollment starts staged, with executable GitHub readiness adapters and a policy derived from the repository's release workflow. Registry changes land through a separate linked worktree and `fleet-land`. Installed definitions and loaded launchd roles are different checks.

## Architect phases

1. Ground. Complete after tracing source, native compiler flags, original fixture checks, and fleet enrollment instructions.
2. Sketch. Compare the two packages below.
3. Agree. No human checkpoint requested. Choose against the stated rubric.
4. Implement. Keep the scanner, add the smallest release interface.
5. Scrap. Reconsider only if native runtime or installation evidence disproves the shape.

## Arena phases

1. Frame. Produce a native CLI distribution with a verified installer and CI use.
2. Fan out. Skip parallel execution because this Pi session has no subagent tool. Evaluate both whole-shape candidates serially under the documented Harness fallback.
3. Cross-judge. Skip independent judging because no separate model tool is exposed. Record self-review as self-review.
4. Pick. Candidate A wins the rubric below.
5. Graft. Keep Candidate B's explicit toolchain setup only for source contributors.
6. Verify. Run native CLI tests, fixtures, archive installation, checksum rejection, and public-release installation.

## Caller usage

`sh install.sh v0.1.0` installs `phpscan` in `~/.local/bin`.
`phpscan src/` reports findings and returns 1 when it finds a problem.
`phpscan --format=sarif src/ > phpscan.sarif` produces CI output while retaining the scanner's exit status.

## Candidate A. Native release archives

A release artifact is `(version, operating system, architecture, archive, SHA-256)`. A native matrix builds four archives. The installer maps `uname` to one artifact and verifies its checksum before replacing a binary. The scanner retains its existing typed `Src`, `Rep`, and `Opts` structures. A version module is the one source of application version. There is no launcher process or language runtime on the user's machine.

Public interface is the scanner plus one installer with a version argument and destination environment variable. Build, package, and verification scripts hide compiler and archive details from users.

## Candidate B. Bend launcher package

A shell executable checks a locally installed Bun/Bend runtime, downloads missing compiler files, and launches the scanner source. A package includes source and compiler metadata instead of native executables. Users get one command but inherit a compiler download, source compilation, writable cache, and network/runtime dependencies. Offline CI needs a warmed cache or extra setup. This conflicts with the requested released binary.

## Rubric

| Criterion | Candidate A | Candidate B |
| --- | --- | --- |
| Released native binary, without language-runtime setup | Pass | Fail |
| Linux and macOS, both requested architectures | Native matrix | Runtime availability-dependent |
| Version-pinned CI installation | One archive and checksum | Runtime and cache setup |
| Existing Bend scanner retained | Pass | Pass |
| Small user interface | One binary | Launcher plus runtime lifecycle |
| Reproducible behavior checks on installed artifact | Direct execution | Launcher may compile different artifacts |

## Synthesis decision

Choose Candidate A. Adapt Candidate B's toolchain setup into a contributor-only script. Reject a port to Go or Rust because it would replace tested analysis logic without helping distribution. No candidate was independently generated or cross-model reviewed.

## Accepted tradeoffs and boundaries

Use system `find` and `cat`, as the original scanner does. Document POSIX host dependencies, symlink discovery, path limitations, and analysis gaps instead of claiming full PHP parsing or complete security coverage. Linux archives target glibc-based distributions, not Alpine/musl. macOS binaries have no Apple notarization. SHA-256 detects corruption but is not an independent signing identity.

Build the Lever changes the implementation by requiring committed build, archive, installer, and artifact checks. Laziness Protocol keeps the Bend scanner instead of a rewrite. Prove It Works requires downloading the published assets and running them. Sequence Work into Verifiable Units requires checking extraction before release and release before fleet registration. Model the Domain keeps artifact identity as a platform tuple and application version in one module. Test Behavior, Not Implementation requires literal expectations from actual scanner and installer subprocesses.

## Next check

Add the packaging scripts and execute the native build and installed-artifact checks before creating a release tag.
