# Third-party notices

phpscan's source is MIT-licensed. Native binaries contain generated runtime and
Base library code from [Bend 2.0.38](https://github.com/bendlang/bend/tree/v2.0.38).
Bend is Copyright 2026 BendAI and licensed under Apache-2.0.
The complete license is in [licenses/Bend-Apache-2.0.txt](licenses/Bend-Apache-2.0.txt)
and every binary archive includes it.

The scanner extraction source revision is
`0a75438189e8309fc67241c004ac85f2eb721979`. The extracted scanner law and proof
cover suppression only. They do not prove vulnerability detection is complete.

The CVE test manifest links to upstream PHP files and pins their SHA-256 values.
Tests download those files as data. Release archives do not contain them.
