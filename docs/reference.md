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
and scans files independently. Symlinked directories are not followed.
Overlapping input directories can scan a file more than once.
An empty directory returns 0. Paths with newline characters are unsupported.
Use `./` before a path whose name starts with `-`.

## Supported platforms

Native archives support Linux with glibc 2.35 or later and macOS 13 or later,
on x86_64 or arm64. The CLI uses the system's `find` and `cat` commands.
Windows and Alpine/musl are not supported. macOS binaries are not notarized.

## CVE coverage

A CVE identifies a known vulnerability. A CWE describes a type of weakness.
The scanner reports weakness rules such as `PHP-CODEI` and their CWEs. It does
not report CVE identifiers, read advisory records, or identify installed
vulnerable dependency versions. It also does not check whether an application
can call code named in a CVE advisory. These are gaps in phpscan's intended
CVE checking, not capabilities supplied by its current rules.

The [CVE regression manifest](../tests/cve/manifest.tsv) names exact vulnerable
and fixed upstream PHP files. `make cves` downloads and verifies those files,
then checks for an expected rule finding or its absence. The test harness
supplies the CVE identifier. The scanner does not infer it. Passing these
cases does not establish general detection of those CVEs in a PHP project.

For CVE detection work, verify the advisory identifier, affected versions,
and any available affected-function metadata. Keep a version match separate
from evidence that the application can call the affected code. State when
that evidence is unavailable. A possible call is not proof of exploitation.

## Rules

The table gives examples, not every modeled function.

| Rule | CWE | Example sinks |
| --- | --- | --- |
| PHP-SQLI | 89 | `mysqli_query`, `pg_query`, `->query`, `->get_results`, `->exec` |
| PHP-CMDI | 78 | `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, backticks |
| PHP-CODEI | 95 | `eval`, `assert`, `create_function`, dynamic callbacks |
| PHP-XSS | 79 | `echo`, `print`, `printf`, `die`, `exit`, `wp_die` |
| PHP-PATH | 22 | `file_get_contents`, `fopen`, `readfile`, `unlink`, `file_put_contents` |
| PHP-LFI | 98 | `include`, `require`, `include_once`, `require_once` |
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
closures, and function summaries within a file. Unknown functions pass argument
taint through. A finding inside a user function can appear at the caller
that passes tainted data into that function.

Sanitizer models clear selected classes. `htmlspecialchars` clears XSS and
header taint but does not clear SQL taint. `escapeshellarg` clears command
taint. `basename` clears path and inclusion taint. Numeric conversions clear
all classes. Placeholder queries with separately bound parameters are not
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
- Method names from different classes can share a summary. This can cause false positives.
- Sanitizers and framework models lack full context. Encoding, SQL dialects, shell syntax, and application authorization can change the real risk.
- Summary propagation uses three rounds. Some recursive or deep call chains can be missed without a `PHP-INCOMPLETE` report.
- The scanner does not run Composer, resolve project autoloading, or validate PHP syntax. Run `php -l` and your other security checks separately.
- The CLI reads each file through a child process with a 64 MiB output limit and reads all selected source into memory. Large projects can exceed available memory.
- Discovery uses newline-delimited `find` output. Filenames containing newlines are unsupported. The scanner uses ordinary host filesystem permissions, not a sandbox.

Review each finding. Exit 0 means no finding from this analysis, not absence
of vulnerabilities. The suppression proof does not change these limits.
