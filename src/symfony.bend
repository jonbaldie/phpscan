import Base
import ./lex.bend as L
import ./tree.bend as T

import ./evidence.bend as E

type Import is Data:
  Import{alias: String, target: String}

def known(s: String) -> String:
  match s:
    case "illuminate\\http\\request":
      "Illuminate\\Http\\Request"
    case "symfony\\component\\httpfoundation\\request":
      "Symfony\\Component\\HttpFoundation\\Request"
    case _:
      ""

def has_alias(xs: List<&2, Import>, +name: String) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{Import{alias, target}, rest}:
      String.eq(alias, name) || has_alias(rest, name)

def lookup(xs: List<&2, Import>, +name: String) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{Import{+alias, target}, +rest}:
      L.sel(String, String.eq(alias, name),
        u => L.sel(String, Bool.not(has_alias(rest, name)), v => known(target), v => ""),
        u => lookup(rest, name))

def resolve(+name: String, imports: List<&2, Import>) -> String:
  L.sel(String, String.starts_with(name, "\\"),
    u => known(String.to_lower(String.drop(name, 1n))),
    u => lookup(imports, String.to_lower(name)))

def imports(ns: List<&2, T.Node>) -> List<&2, Import>:
  match ns:
    case Nil{}:
      []
    case Con{T.Leaf{L.Tok{1, "use", l}}, Con{T.Leaf{L.Tok{1, +name, n}}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}}:
      Con{Import{String.to_lower(L.strip_ns(name)), String.to_lower(name)}, imports(rest)}
    case Con{T.Leaf{L.Tok{1, "use", l}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Leaf{L.Tok{1, "as", a}}, Con{T.Leaf{L.Tok{1, alias, b}}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}}}}:
      Con{Import{String.to_lower(alias), String.to_lower(name)}, imports(rest)}
    case Con{n, rest}:
      imports(rest)

def simple_scope(ns: List<&2, T.Node>, seen: Bool) -> Bool:
  match ns seen:
    case Nil{} _:
      True{}
    case Con{T.Leaf{L.Tok{1, "namespace", l}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}} False{}:
      simple_scope(rest, True{})
    case Con{T.Leaf{L.Tok{1, "namespace", l}}, rest} _:
      False{}
    case Con{T.Leaf{L.Tok{1, "use", l}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}} +seen:
      simple_scope(rest, seen)
    case Con{T.Leaf{L.Tok{1, "use", l}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Leaf{L.Tok{1, "as", a}}, Con{T.Leaf{L.Tok{1, alias, b}}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}}}} +seen:
      simple_scope(rest, seen)
    case Con{T.Leaf{L.Tok{1, "use", l}}, rest} _:
      False{}
    case Con{n, rest} +seen:
      simple_scope(rest, seen)

def parameter(ns: List<&2, T.Node>, +im: List<&2, Import>, start: Bool) -> List<&2, Import>:
  match ns start:
    case Nil{} _:
      []
    case Con{T.Leaf{L.Tok{1, typ, l}}, Con{T.Leaf{L.Tok{0, name, n}}, Nil{}}} True{}:
      [Import{name, resolve(typ, im)}]
    case Con{T.Leaf{L.Tok{1, typ, l}}, Con{T.Leaf{L.Tok{0, name, n}}, Con{T.Leaf{L.Tok{5, ",", c}}, rest}}} True{}:
      Con{Import{name, resolve(typ, im)}, parameter(rest, im, True{})}
    case Con{T.Leaf{L.Tok{5, ",", c}}, rest} _:
      parameter(rest, im, True{})
    case Con{n, rest} _:
      parameter(rest, im, False{})

def receiver(ps: List<&2, Import>, +name: String) -> String:
  match ps:
    case Nil{}:
      ""
    case Con{Import{+alias, target}, rest}:
      L.sel(String, String.eq(alias, name), u => target, u => receiver(rest, name))

def authorization(ns: List<&2, T.Node>) -> U32:
  match ns:
    case Con{T.Leaf{L.Tok{1, "abort_unless", l}}, Con{T.Grp{40, p, Con{T.Leaf{L.Tok{1, "auth", a}}, Con{T.Grp{40, b, Nil{}}, Con{T.Leaf{L.Tok{5, "->", c}}, Con{T.Leaf{L.Tok{1, "check", d}}, Con{T.Grp{40, e, Nil{}}, Con{T.Leaf{L.Tok{5, ",", f}}, Con{T.Leaf{L.Tok{4, "403", g}}, Nil{}}}}}}}}}, Con{T.Leaf{L.Tok{5, ";", s}}, rest}}}:
      l
    case _:
      0

def condition(ns: List<&2, T.Node>, body: List<&2, T.Node>, ps: List<&2, Import>, path: String, check: U32) -> List<&2, E.Site>:
  match ns:
    case Con{T.Leaf{L.Tok{1, "str_starts_with", l}}, Con{T.Grp{40, a, Con{T.Leaf{L.Tok{0, name, v}}, Con{T.Leaf{L.Tok{5, "->", o}}, Con{T.Leaf{L.Tok{1, "getpathinfo", +m}}, Con{T.Grp{40, p, Nil{}}, Con{T.Leaf{L.Tok{5, ",", c}}, Con{T.Leaf{L.Tok{2, +prefix, s}}, Nil{}}}}}}}}, Nil{}}}:
      +typ = receiver(ps, name)
      +auth = authorization(body)
      L.sel(List<&2, E.Site>, Bool.not(String.is_empty(typ)) && String.starts_with(prefix, "/") && U32.is_lt(0, auth),
        u => [E.Site{path, m, check, auth, typ, prefix}], u => [])
    case _:
      []

def first_check(ns: List<&2, T.Node>, ps: List<&2, Import>, path: String) -> List<&2, E.Site>:
  match ns:
    case Con{T.Leaf{L.Tok{1, "if", line}}, Con{T.Grp{40, c, cond}, Con{T.Grp{123, b, body}, rest}}}:
      condition(cond, body, ps, path, line)
    case _:
      []

def functions(fuel: Nat, ns: List<&2, T.Node>, +im: List<&2, Import>, +path: String) -> E.Evidence:
  match fuel ns:
    case 0n _:
      E.Evidence{[], True{}}
    case 1n+p Nil{}:
      E.Evidence{[], False{}}
    case 1n+(+p) Con{T.Leaf{L.Tok{1, "function", f}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Grp{40, a, params}, Con{T.Grp{123, b, body}, rest}}}}:
      E.merge(E.Evidence{first_check(body, parameter(params, im, True{}), path), False{}}, functions(p, rest, im, path))
    case 1n+(+p) Con{T.Grp{k, l, kids}, rest}:
      E.merge(functions(p, kids, im, path), functions(p, rest, im, path))
    case 1n+p Con{n, rest}:
      functions(p, rest, im, path)

def analyze(+ns: List<&2, T.Node>, path: String, fuel: Nat) -> E.Evidence:
  L.sel(E.Evidence, simple_scope(ns, False{}), u => functions(fuel, ns, imports(ns), path), u => E.Evidence{[], False{}})

def scan(path: String, source: String) -> E.Evidence:
  +tokens = L.qualified(source)
  L.sel(E.Evidence, T.balanced(tokens, []),
    u => E.suppress(analyze(T.tree(L.without_ignores(tokens)), path, 1n+List.length(&2, L.Tok, tokens)), L.ignored_lines(tokens, 0)),
    u => E.Evidence{[], False{}})
