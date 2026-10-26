import Base
import ../src/catalog.bend as C
import ../src/versions.bend as V
import ../src/lex.bend as L

def ordered(lo: Maybe<&2, V.Version>, hi: Maybe<&2, V.Version>) -> Bool:
  match lo hi:
    case Some{lo} Some{hi}:
      V.less(V.cmp(lo, hi))
    case _ _:
      False{}

def lower_valid(lo: Maybe<&2, String>, +hi: Maybe<&2, V.Version>) -> Bool:
  match lo hi:
    case None{} Some{v}:
      True{}
    case Some{lo} +hi:
      ordered(V.read(lo), hi)
    case _ _:
      False{}

def gap(hi: Maybe<&2, V.Version>, lo: Maybe<&2, V.Version>) -> Bool:
  match hi lo:
    case Some{hi} Some{lo}:
      Bool.not(V.less(V.cmp(lo, hi)))
    case _ _:
      False{}

def separated(hi: String, lo: Maybe<&2, String>) -> Bool:
  match lo:
    case None{}:
      False{}
    case Some{lo}:
      gap(V.read(hi), V.read(lo))

def pair(a: C.AffectedRange, b: C.AffectedRange) -> Bool:
  match a b:
    case C.AffectedRange{p, lo, hi, f, why} C.AffectedRange{q, lower, upper, fixed, provenance}:
      Bool.not(String.eq(p, q)) || separated(hi, lower) || separated(upper, lo)

def against(+a: C.AffectedRange, rs: List<&2, C.AffectedRange>) -> Bool:
  match rs:
    case Nil{}:
      True{}
    case Con{r, rest}:
      pair(a, r) && against(a, rest)

def ranges(rs: List<&2, C.AffectedRange>) -> Bool:
  match rs:
    case Nil{}:
      True{}
    case Con{+r, +rest}:
      C.AffectedRange{p, lo, +hi, fixed, why} = r
      String.eq(hi, fixed) && lower_valid(lo, V.read(hi)) && against(r, rest) && ranges(rest)

def records(rs: List<&2, C.Advisory>) -> Bool:
  match rs:
    case Nil{}:
      True{}
    case Con{C.Advisory{id, cve, profile, rs, sources, functions}, rest}:
      ranges(rs) && records(rest)

def main() -> U32:
  L.sel(U32, records(C.records()), u => 0, u => 1)
