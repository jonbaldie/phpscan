import Base
import ./src/scan.bend as S
import ./LAWS.bend as Laws

def Laws.suppress_none(fs):
  match fs:
    case Nil{}:
      {==}
    case Con{S.Finding{+l, +c, +s}, +rest}:
      %Laws.suppress_none(rest) : {S.suppress(Con{S.Finding{l, c, s}, rest}, []) == Con{S.Finding{l, c, s}, _} : List<&2, S.Finding>}
      {==}
