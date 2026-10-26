# CLI and analysis reference

## Invocation

```text
phpscan [--format=text|github|sarif] <file-or-dir>...
phpscan --help
phpscan --version
```

The default format is `text`. Findings go to stdout and the summary goes to
stderr. GitHub output uses workflow annotations. SARIF output is one SARIF
2.1.0 document, including an empty results array for a clean scan.

| Exit code | Meaning |
| --- | --- |
| 0 | No findings and no reported incomplete analysis. |
| 1 | At least one finding and no reported incomplete analysis. |
| 2 | Invalid arguments, a discovery/read error, or reported incomplete analysis. This takes precedence over findings. |

File discovery includes `.php`, `.phtml`, and `.inc` names, sorts the paths,
and scans files independently. Each explicitly scanned directory also checks
its immediate `composer.lock`. An explicit `composer.lock` file is supported.
Nested lockfiles are not discovered unless their directory is an input.
The summary's file count includes lockfiles.
Symlinked directories are not followed.
Overlapping input directories can scan a file more than once.
An empty directory returns 0. Paths with newline characters are unsupported.
Use `./` before a path whose name starts with `-`.

## Supported platforms

Native archives support Linux with glibc 2.35 or later and macOS 13 or later,
on x86_64 or arm64. The CLI uses the system's `find` and `cat` commands.
Windows and Alpine/musl are not supported. macOS binaries are not notarized.

## CVE coverage

A CVE identifies a known vulnerability. A CWE describes a type of weakness.
The source scanner reports weakness rules such as `PHP-CODEI` and their CWEs.
The separate offline dependency scanner matches exact installed versions from
`composer.lock` against a pinned, embedded [advisory catalog](../advisories/composer.json).
The catalog covers `livewire/livewire` CVE-2025-54068,
GHSA-29cq-5w36-x7w3, in `>=3.0.0-beta.1,<3.6.4`. Version 3.6.3 is affected.
Version 3.6.4 is the first fix. The catalog records the discrepancy between the
maintainer's structured range and prose and the reviewed Composer boundary.
It also covers CVE-2025-64500 / GHSA-3rg7-wf37-54rm for
`symfony/http-foundation` in `<5.4.50`, `>=6.0.0,<6.4.29`, and
`>=7.0.0,<7.3.7`. The distinct `symfony/symfony` record starts its first
interval at `2.0.0`; the later intervals are the same. The catalog records the
maintainer's conflicting unbounded first monolithic interval and prefers the
reviewed Composer range.
The catalog also covers Laravel TokenGuard authentication bypass,
CVE-2026-114509 / GHSA-f9x3-7vq9-cph6, for exactly `laravel/framework` in
`<12.68.0` and `>=13.0.0,<13.29.0`. Fixes are `12.68.0` and `13.29.0`.
The first interval has no lower bound. The reviewed 13.x lower bound takes
precedence over the maintainer's unbounded `<13.29.0` shorthand so patched
12.x does not match the 13.x interval. The patch adds string-token checks
before credential retrieval. This is not a SQL-injection rule or blanket
Sanctum or Passport advisory. It is not a complete Composer advisory database.

Dependency findings report the installed version, interval, fix boundary,
lockfile location, and dependency group. Both `packages` and `packages-dev`
are checked. Development dependencies are labeled separately, with deployment
unknown. Missing `packages-dev` means an empty development inventory.
A missing lockfile leaves source-only scanning available. It does not establish
that dependencies are safe. `packages` must be an array of entries with string
`name` and `version` fields. Malformed JSON or inventory produces
`PHP-ADVISORY-INCOMPLETE` and exit 2, even alongside findings.

Supported versions are exact SemVer `MAJOR.MINOR.PATCH`, optionally prefixed
with lowercase `v`, with optional prerelease and build identifiers. Core
components are integers from 0 to 4294967295, without leading zeros.
Prerelease identifiers use SemVer numeric and lexical ordering. Build metadata
does not affect ordering. Composer constraints, branch aliases, four-component
versions, and unresolved development versions are unsupported. An unsupported
version for a catalogued package produces an unknown analysis and exit 2.
Packages absent from the catalog have no advisory coverage, regardless of version.
The scanner does not resolve dependencies or query a live advisory service.

A version match exits 1 unless analysis is incomplete. A completed no-match
exits 0. This means no match in this limited snapshot, not a dependency safety
certification. Text and GitHub messages identify dependency-version evidence.
SARIF properties also separate the dependency group, version, interval, source
URLs, catalog date, and range provenance. Symfony dependency matches can also
carry possible path-prefix access check sites from sources within the same CLI
path argument. A nested directory with `composer.json` or `composer.lock` does
not supply evidence to its parent project. Its PHP files still receive the
normal taint scan. Scanning a lockfile alone gives version-only evidence. Each site
records source path, method/check lines, authorization marker line, receiver type,
and prefix. SARIF keeps `sourceEvidence` and `relatedLocations` separate from
dependency-version evidence. One dependency match remains one finding.

The bounded Laravel profile reads only the project root's conventional
`config/auth.php` and `config/database.php`, plus immediate `routes/*.php` files.
It accepts a single `return [...]` statement in each config file. Array keys
must be literal strings. The root array, guards, providers, and their entries
must have unique keys. Unpacking, merged arrays, computed guard or provider
entries, and malformed brackets do not produce positive evidence.
Other config values remain uninterpreted, including model class expressions.
The Laravel and Symfony source profiles treat double-quoted strings containing
any backslash as unsupported, leaving literal-sensitive evidence unknown.
Unescaped double-quoted strings and the existing single-quoted string behavior
remain supported.
A candidate requires a literal `guards[name]` with `driver => 'token'`,
`hash => false`, and a literal provider name whose `providers[name]` entry
has `driver => 'eloquent'`. A custom provider is unresolved.

Routes must be standalone, top-level statements of the exact form
`Route::middleware('auth:<guard>')->get(<literal URI>, <action>);`.
The action is not interpreted. The facade must have a simple explicit
`use Illuminate\Support\Facades\Route;` import, a simple `as` alias, or the
fully qualified `\Illuminate\Support\Facades\Route` name.
Namespaces, grouped or conflicting imports, route groups, other HTTP methods,
additional chain calls, middleware arrays, dynamic middleware, and nested
route statements are outside this grammar. Strings, comments, and unrelated
facades do not establish a link. Guard names match case-sensitively.

Only a resolved guard-route link produces `token-guard` and `guard-route`
observations with status `possible`. Database observations require a valid link
between a TokenGuard guard, its provider, and a route. They are not a standalone
inventory.
A literal database default of `mysql` or `mariadb` adds a separate
`database-selection` observation with status `possible`.
A dynamic default, such as `env('DB_CONNECTION')`, or another literal database
adds a database observation with status `unknown` at the default field's line.
The guard and route remain possible. Missing fields or malformed optional
source do not invent locations or remove the dependency match.
Each observation records `kind`, `sourcePath`, `line`, `status`, and `detail`
in SARIF `sourceEvidence`, with a related location and a GitHub notice.
Text reports the same observations. Order follows guard declaration order,
then sorted route source paths and statement order, followed by the database.
A suppressed guard field or route prevents the link. A suppressed database
field removes only that observation. A model's connection override, runtime
configuration, guard extensions, middleware registration, and exploitability
remain unknown. The profile never executes PHP or sends application HTTP or
database requests.

The bounded Symfony profile resolves simple explicit imports and aliases for
Illuminate or Symfony Request parameter types, and fully qualified types. It
recognizes a direct `getPathInfo()` receiver in an exact
`str_starts_with(..., '/prefix')` condition as the function's first statement.
The braced branch must start with `abort_unless(auth()->check(), 403)`.
This restriction excludes earlier receiver reassignment without guessing about
intervening calls. Logging alone is not an access check. Union types, nullable
types, unresolved types, complex imports, multiple or braced namespaces,
malformed bracket sequences, and unsupported flows leave affected-code evidence
unknown. Traversal fuel derives from the token count. Exhaustion exits 2.
A source-line `phpscan-ignore` removes that site's evidence, not its dependency
match. GitHub output adds notices at possible source locations.
Possible evidence does not prove authorization bypass. Runtime exposure,
exploitability, deployment, middleware registration, server configuration, and
independent authorization remain unknown. The pinned Livewire
record has no affected-function metadata. The scanner does not infer
reachability from that absence and does not execute application code.

JSON accepts escaped strings and Unicode surrogate pairs and rejects duplicate
object keys. Parsing has a 100000-step recursive budget. An exhausted budget
produces an incomplete advisory analysis, not a clean scan.
See [catalog updates](development.md#update-the-offline-advisory-catalog).

The [CVE regression manifest](../tests/cve/manifest.tsv) names exact vulnerable
and fixed upstream PHP files. `make cves` downloads and verifies those files,
then checks for an expected rule finding or its absence. For these source-only
cases, the test harness supplies the CVE identifier. The source scanner does not
infer it. Passing these cases does not establish general detection of those
CVEs in a PHP project.

For CVE detection work, verify the advisory identifier, affected versions,
and any available affected-function metadata. Keep a version match separate
from evidence that the application can call the affected code. State when
that evidence is unavailable. A possible call is not proof of exploitation.

## Rules

The table gives examples, not every modeled function. BuddyPress
`bp_locate_template()` is modeled as an inclusion sink because the framework's
template loader consumes its result.

| Rule | CWE | Example sinks |
| --- | --- | --- |
| PHP-SQLI | 89 | `mysqli_query`, `pg_query`, `->query`, `->get_results`, `->exec` |
| PHP-CMDI | 78 | `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, backticks |
| PHP-CODEI | 95 | `eval`, `assert`, `create_function`, dynamic callbacks |
| PHP-XSS | 79 | `echo`, `print`, `printf`, `die`, `exit`, `wp_die` |
| PHP-PATH | 22 | `file_get_contents`, `fopen`, `readfile`, `unlink`, `file_put_contents` |
| PHP-LFI | 98 | `include`, `require`, `include_once`, `require_once`, BuddyPress `bp_locate_template` |
| PHP-SSRF | 918 | `curl_init`, `CURLOPT_URL`, `fsockopen`, `wp_remote_get` |
| PHP-DESER | 502 | `unserialize`, `maybe_unserialize` |
| PHP-HEADER | 113 | `header`, `wp_redirect` |
| PHP-VAROVR | 621 | `extract`, `parse_str` without a result array |
| PHP-INCOMPLETE | None | The analysis exhausted its fuel. |

## Sources and sanitizers

The scanner tracks request data from `$_GET`, `$_POST`, `$_REQUEST`,
`$_COOKIE`, selected `$_SERVER` and `$_FILES` fields, `php://input`, and
modeled request functions. `$_ENV`, `GLOBALS`, and uninitialized session data
are not request sources in this version.

Taint propagates through variables, arrays, interpolation, branches, loops,
closures, and function summaries within a file. `parse_str($query, $result)`
propagates query taint into the result array; without a result array it is a
variable-overwrite sink. Unknown functions pass argument taint through. A
finding inside a user function can appear at the caller that passes tainted
data into that function.

Sanitizer models clear selected classes. `htmlspecialchars` clears XSS and
header taint but does not clear SQL taint. `escapeshellarg` clears command
taint. `basename` clears path and inclusion taint. Numeric conversions clear
all classes. `html_entity_decode`, `htmlspecialchars_decode`, and
`wp_kses_decode_entities` restore every class to request data that earlier
sanitizers cleared. Placeholder queries with separately bound parameters are not
flagged, but a tainted query string passed to `prepare` can be flagged.
These models are heuristics, not proofs that the actual PHP operation is safe.

## Suppression

A trailing `// phpscan-ignore` suppresses findings on the same line.
A standalone comment suppresses the next line.

```php
<?php
echo $_GET['reviewed']; // phpscan-ignore
```

Suppression applies to all rules on that line. Record your triage reason beside
the suppression in project code.

## Analysis limits

- The scanner uses a tokenizer and bracket tree, not a complete PHP parser. Invalid PHP can produce a clean result. Unusual syntax can be misread.
- Function summaries stay within a file. Cross-file calls, object state passed between methods, `global`, and values stored across requests can be missed.
- A decoder restores sanitized taint only within one function. A value sanitized by a caller and decoded inside a called function is missed.
- Method names from different classes can share a summary. This can cause false positives.
- Sanitizers and framework models lack full context. Encoding, SQL dialects, shell syntax, and application authorization can change the real risk.
- Summary propagation uses three rounds. Some recursive or deep call chains can be missed without a `PHP-INCOMPLETE` report.
- The scanner does not run Composer, resolve project autoloading, or validate PHP syntax. Run `php -l` and your other security checks separately.
- The CLI reads each file through a child process with a 64 MiB output limit and reads all selected source into memory. Large projects can exceed available memory.
- Discovery uses newline-delimited `find` output. Filenames containing newlines are unsupported. The scanner uses ordinary host filesystem permissions, not a sandbox.

Review each finding. Exit 0 means no finding from this analysis, not absence
of vulnerabilities. The suppression proof does not change these limits.
