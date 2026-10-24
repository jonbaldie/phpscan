# Build and test phpscan

Install Git, Bash, curl, Python 3, clang 14 or later, make, and Bun 1.3.14.
On macOS, install the Xcode command line tools for clang.
You do not need a PHP runtime for scanner tests.

1. Clone this repository and enter its directory.
2. Run `make setup`. The script downloads Bend 2.0.38 and checks its pinned SHA-256.
3. Run `make build`. The script checks the suppression proof and incomplete-status regression, emits C, and builds `dist/phpscan`.
4. Run `make test lint`. All fixture, CLI, and installer checks must pass.
5. Run `make cves` to check pinned vulnerable and fixed upstream files. This step needs network access.
6. Run `make package` to produce the archive for your host in `dist/`.

To repeat PHP syntax validation locally, run `bash tests/lint-matrix.sh` with
Docker and the official PHP 8.2, 8.3, 8.4, and 8.5 images available.
CI checks the same fixtures under each PHP version.

## Find the code

`src/main.bend` owns arguments, source discovery, output formats, and exit codes.
`src/lex.bend` produces tokens. `src/tree.bend` groups bracketed tokens.
`src/scan.bend` tracks taint and builds function summaries.
`src/version.bend` owns the application version.

Native builds embed Bend's runtime. They do not launch Bend or Bun when users
run the scanner. The scanner invokes `find` and `cat` with literal arguments.
The toolchain stays in ignored `.tools/`. Build output stays in ignored `dist/`.

## Build stages and memory

`make generate` checks the suppression proof and incomplete-status regression,
then emits portable `dist/phpscan.c`. `make compile` requires that generated C
and builds the host's native binary and build metadata. `make build` runs both
stages, preserving the normal contributor command.

C emission can exceed 16 GB of peak memory footprint on macOS; low-memory
machines can swap heavily. CI generates C once on Linux, then compiles and
executes it on every supported native target. Source checks run in the
C-generation job; native workers run fixture, CLI, installer, and archive checks.
Use generated C from the same checkout's trusted generation step. `make compile`
alone is not source verification.

## Add a regression

For a rule change, add a PHP fixture in `tests/cases/`. Put `// expect: RULE`
on each expected finding's line. Use more than one rule name when the same
line has multiple findings. Add the corresponding sanitized case too.
`tests/check.sh` compares the literal expectations with actual scanner output
and checks exit status.

For arguments, output formatting, or discovery, add a subprocess assertion in
`tests/test_cli.py`. For installation, add a filesystem or installed-binary
assertion in `tests/test_install.py`.

Before sending a change, follow [the agent workflow](agents/workflow.md) and
[CODING_STANDARDS.md](../CODING_STANDARDS.md).
