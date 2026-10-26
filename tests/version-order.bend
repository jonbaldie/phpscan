import Base
import ../src/versions.bend as V
import ../src/lex.bend as L

def less(a: Maybe<&2, V.Version>, b: Maybe<&2, V.Version>) -> Bool:
  match a b:
    case Some{a} Some{b}:
      Cmp.is_lt(V.cmp(a, b))
    case _ _:
      False{}

def equal(a: Maybe<&2, V.Version>, b: Maybe<&2, V.Version>) -> Bool:
  match a b:
    case Some{a} Some{b}:
      Cmp.is_eq(V.cmp(a, b))
    case _ _:
      False{}

def main() -> U32:
  L.sel(U32,
    less(V.read("3.0.0-beta.2"), V.read("3.0.0-beta.10")) &&
    less(V.read("3.0.0-beta.10"), V.read("3.0.0-beta.a")) &&
    less(V.read("3.0.0-beta.1"), V.read("3.0.0-beta.1.0")) &&
    less(V.read("3.0.0-beta.1"), V.read("3.0.0-rc.1")) &&
    less(V.read("3.0.0-rc.1"), V.read("3.0.0")) &&
    less(V.read("3.9.0"), V.read("3.10.0")) &&
    equal(V.read("v3.6.3+one"), V.read("3.6.3+two")),
    u => 0, u => 2)
