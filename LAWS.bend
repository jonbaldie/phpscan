import Base
import ./src/scan.bend as S

# Extracted unchanged from the scanner's original law.
law suppress_none:
  for fs: List<&2, S.Finding>
  {S.suppress(fs, []) == fs : List<&2, S.Finding>}
