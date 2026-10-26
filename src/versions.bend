import Base
import ./lex.bend as L

type Version is Data:
  Version{major: U32, minor: U32, patch: U32, pre: List<&2, String>}

def digits(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{c, rest}:
      Char.is_digit(c) && digits(rest)

def leading(s: String) -> Bool:
  match s:
    case SCon{'0', SCon{c, rest}}:
      False{}
    case _:
      True{}

def numeric(+s: String) -> Maybe<&2, U32>:
  L.sel(Maybe<&2, U32>, Bool.not(String.is_empty(s)) && digits(s) && leading(s), u => U32.read(s), u => None{})

def id.chars(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{+c, rest}:
      (Char.is_digit(c) || Char.is_alpha(c) || Char.is_eq(c, '-')) && id.chars(rest)

def ids.valid(xs: List<&2, String>, +pre: Bool) -> Bool:
  match xs:
    case Nil{}:
      True{}
    case Con{+x, rest}:
      Bool.not(String.is_empty(x)) && id.chars(x) &&
      (Bool.not(pre && digits(x)) || leading(x)) && ids.valid(rest, pre)

def core(xs: List<&2, String>, pre: List<&2, String>) -> Maybe<&2, Version>:
  match xs:
    case Con{a, Con{b, Con{c, Nil{}}}}:
      do Maybe<&2, Version>:
        major : U32 <- numeric(a)
        minor : U32 <- numeric(b)
        patch : U32 <- numeric(c)
        return Version{major, minor, patch, pre}
    case _:
      None{}

def base(xs: List<&2, String>) -> Maybe<&2, Version>:
  match xs:
    case Con{c, Nil{}}:
      core(String.split(c, '.'), [])
    case Con{c, Con{p, rest}}:
      +pre = String.split(String.join(Con{p, rest}, "-"), '.')
      L.sel(Maybe<&2, Version>, ids.valid(pre, True{}), u => core(String.split(c, '.'), pre), u => None{})
    case _:
      None{}

def with_build(xs: List<&2, String>) -> Maybe<&2, Version>:
  match xs:
    case Con{v, Nil{}}:
      base(String.split(v, '-'))
    case Con{v, Con{b, Nil{}}}:
      L.sel(Maybe<&2, Version>, ids.valid(String.split(b, '.'), False{}), u => base(String.split(v, '-')), u => None{})
    case _:
      None{}

def read(+s: String) -> Maybe<&2, Version>:
  with_build(String.split(L.sel(String, String.starts_with(s, "v"), u => String.drop(s, 1n), u => s), '+'))

def then(c: Cmp, rest: Unit -> Cmp) -> Cmp:
  match c:
    case EQ{}:
      rest(Unit{})
    case c:
      c

def id.cmp(+a: String, +b: String) -> Cmp:
  +an = digits(a)
  +bn = digits(b)
  L.sel(Cmp, an && bn,
    u => then(Nat.cmp(String.length(a), String.length(b)), v => String.order(a, b)),
    u => L.sel(Cmp, an, v => LT{}, v => L.sel(Cmp, bn, w => GT{}, w => String.order(a, b))))

def ids.cmp(a: List<&2, String>, b: List<&2, String>) -> Cmp:
  match a b:
    case Nil{} Nil{}:
      EQ{}
    case Nil{} Con{y, ys}:
      LT{}
    case Con{x, xs} Nil{}:
      GT{}
    case Con{x, xs} Con{y, ys}:
      then(id.cmp(x, y), u => ids.cmp(xs, ys))

def pre.cmp(a: List<&2, String>, b: List<&2, String>) -> Cmp:
  match a b:
    case Nil{} Nil{}:
      EQ{}
    case Nil{} Con{y, ys}:
      GT{}
    case Con{x, xs} Nil{}:
      LT{}
    case Con{x, xs} Con{y, ys}:
      ids.cmp(Con{x, xs}, Con{y, ys})

def cmp(a: Version, b: Version) -> Cmp:
  match a b:
    case Version{a, b, c, p} Version{x, y, z, q}:
      then(U32.cmp(a, x), u => then(U32.cmp(b, y), v => then(U32.cmp(c, z), w => pre.cmp(p, q))))

def less(c: Cmp) -> Bool:
  match c:
    case LT{}:
      True{}
    case _:
      False{}

def in_range(+v: Version, lower: Version, upper: Version) -> Bool:
  Bool.not(less(cmp(v, lower))) && less(cmp(v, upper))
