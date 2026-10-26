import Base

type Advisory is Data:
  Advisory{ghsa: String, cve: String, package: String, lower: String, upper: String, fixed: String, provenance: String, sources: List<&2, String>, functions: List<&2, String>}

def snapshot_date() -> String:
  "2026-10-26"

def records() -> List<&2, Advisory>:
  [
    Advisory{"GHSA-29cq-5w36-x7w3", "CVE-2025-54068", "livewire/livewire", "3.0.0-beta.1", "3.6.4", "3.6.4", "Reviewed Composer range >=3.0.0-beta.1,<3.6.4. The maintainer structured range says <3.6.3, but its prose includes 3.6.3 and identifies 3.6.4 as the fix. The reviewed record and patch boundary take precedence.", ["https://github.com/advisories/GHSA-29cq-5w36-x7w3", "https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3", "https://github.com/livewire/livewire/commit/ef04be759da41b14d2d129e670533180a44987dc"], []}
  ]
