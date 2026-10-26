import Base
import ./json.bend as J
import ./versions.bend as V
import ./catalog.bend as C
import ./lex.bend as L

type Finding is Data:
  Match{line: U32, advisory: C.Advisory, version: String, group: String}
  Unknown{line: U32, reason: String}

def line(f: Finding) -> U32:
  match f:
    case Match{n, a, v, g}:
      n
    case Unknown{n, r}:
      n

def incomplete(f: Finding) -> Bool:
  match f:
    case Unknown{n, r}:
      True{}
    case _:
      False{}

def rule(f: Finding) -> String:
  match f:
    case Match{n, C.Advisory{id, cve, package, lower, upper, fixed, provenance, sources, functions}, v, g}:
      id
    case _:
      "PHP-ADVISORY-INCOMPLETE"

def message(f: Finding) -> String:
  match f:
    case Match{n, C.Advisory{id, cve, package, lower, upper, fixed, provenance, sources, functions}, v, g}:
      cve ++ " / " ++ id ++ ": " ++ package ++ " installed " ++ v ++ " (" ++ g ++
      "); affected >=" ++ lower ++ ",<" ++ upper ++ "; fixed " ++ fixed ++
      "; affected-code evidence unknown; runtime exposure unknown; exploitability unknown; deployment unknown"
    case Unknown{n, r}:
      "dependency advisory analysis unknown: " ++ r

def interval(v: Maybe<&2, V.Version>, lo: Maybe<&2, V.Version>, hi: Maybe<&2, V.Version>) -> Maybe<&2, Bool>:
  match v lo hi:
    case Some{v} Some{lo} Some{hi}:
      Some{V.in_range(v, lo, hi)}
    case _ _ _:
      None{}

def decision(result: Maybe<&2, Bool>, line: U32, a: C.Advisory, version: String, group: String) -> List<&2, Finding>:
  match result:
    case Some{True{}}:
      [Match{line, a, version, group}]
    case Some{False{}}:
      []
    case None{}:
      [Unknown{line, "unsupported installed version " ++ version ++ " in " ++ group ++ "; expected an exact supported SemVer"}]

def records(rs: List<&2, C.Advisory>, +name: String, +version: String, +n: U32, +group: String) -> List<&2, Finding>:
  match rs:
    case Nil{}:
      []
    case Con{C.Advisory{+id, +cve, +package, +lower, +upper, +fixed, +provenance, +sources, +functions}, rest}:
      a = {C.Advisory{id, cve, package, lower, upper, fixed, provenance, sources, functions} : C.Advisory}
      found = L.sel(List<&2, Finding>, String.eq(name, package),
        u => decision(interval(V.read(version), V.read(lower), V.read(upper)), n, a, version, group), u => [])
      List.append(&2, Finding, found, records(rest, name, version, n, group))

def package(name: Maybe<&2, J.Value>, version: Maybe<&2, J.Value>, group: String) -> List<&2, Finding>:
  match name version:
    case Some{J.Str{nl, +name}} Some{J.Str{+n, +version}}:
      L.sel(List<&2, Finding>, String.is_empty(name) || String.is_empty(version),
        u => [Unknown{n, "empty package name or version"}],
        u => records(C.records(), name, version, n, group))
    case _ _:
      [Unknown{1, "package name and version must be strings in " ++ group}]

def entry(v: J.Value, group: String) -> List<&2, Finding>:
  match v:
    case J.Object{+fields}:
      package(J.get(fields, "name"), J.get(fields, "version"), group)
    case _:
      [Unknown{1, "package entry must be an object in " ++ group}]

def entries(vs: List<&2, J.Value>, +group: String) -> List<&2, Finding>:
  match vs:
    case Nil{}:
      []
    case Con{v, rest}:
      List.append(&2, Finding, entry(v, group), entries(rest, group))

def group(v: Maybe<&2, J.Value>, +name: String, required: Bool) -> List<&2, Finding>:
  match v required:
    case None{} False{}:
      []
    case Some{J.Array{vs}} _:
      entries(vs, name)
    case _ _:
      [Unknown{1, name ++ " must be an array"}]

def decoded(v: Maybe<&2, J.Value>) -> List<&2, Finding>:
  match v:
    case Some{J.Object{+fields}}:
      List.append(&2, Finding,
        group(J.get(fields, "packages"), "packages", True{}),
        group(J.get(fields, "packages-dev"), "packages-dev", False{}))
    case _:
      [Unknown{1, "malformed, unsupported, or over-budget composer.lock JSON; expected an object"}]

def finding.le(a: Finding, b: Finding) -> Bool:
  +x = a
  +y = b
  L.sel(Bool, U32.is_eq(line(x), line(y)), u => String.is_le(rule(x), rule(y)), u => U32.is_le(line(x), line(y)))

def scan(s: String) -> List<&2, Finding>:
  List.sort(~Finding, ~finding.le, decoded(J.read(s)))
