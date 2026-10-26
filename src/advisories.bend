import Base
import ./json.bend as J
import ./versions.bend as V
import ./catalog.bend as C
import ./lex.bend as L
import ./symfony.bend as P

type Finding is Data:
  Match{line: U32, advisory: C.Advisory, range: C.AffectedRange, version: String, group: String, sites: List<&2, P.Site>}
  Unknown{line: U32, reason: String}

def line(f: Finding) -> U32:
  match f:
    case Match{n, a, r, v, g, sites}:
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
    case Match{n, C.Advisory{id, cve, profile, ranges, sources, functions}, r, v, g, sites}:
      id
    case _:
      "PHP-ADVISORY-INCOMPLETE"

def range_text(lower: Maybe<&2, String>, upper: String) -> String:
  match lower:
    case None{}:
      "<" ++ upper
    case Some{lo}:
      ">=" ++ lo ++ ",<" ++ upper

def site_text(sites: List<&2, P.Site>) -> String:
  match sites:
    case Nil{}:
      ""
    case Con{P.Site{path, method, check, auth, typ, prefix}, rest}:
      "; possible path-prefix access check at " ++ path ++ ":" ++ U32.show(method) ++
      " (check line " ++ U32.show(check) ++ ", authorization marker line " ++ U32.show(auth) ++
      ", receiver " ++ typ ++ ", prefix " ++ prefix ++ ")" ++ site_text(rest)

def code_text(+sites: List<&2, P.Site>) -> String:
  L.sel(String, List.is_empty(&2, P.Site, sites), u => "; affected-code evidence unknown", u => site_text(sites))

def message(f: Finding) -> String:
  match f:
    case Match{n, C.Advisory{id, cve, profile, ranges, sources, functions}, C.AffectedRange{package, lower, upper, fixed, provenance}, v, g, sites}:
      cve ++ " / " ++ id ++ ": " ++ package ++ " installed " ++ v ++ " (" ++ g ++
      "); affected " ++ range_text(lower, upper) ++ "; fixed " ++ fixed ++ code_text(sites) ++
      "; runtime exposure unknown; exploitability unknown; deployment unknown; middleware registration unknown; server configuration unknown; independent authorization unknown"
    case Unknown{n, r}:
      "dependency advisory analysis unknown: " ++ r

def lower_parsed(v: V.Version, lower: Maybe<&2, V.Version>) -> Bool:
  match lower:
    case Some{lo}:
      Bool.not(V.less(V.cmp(v, lo)))
    case None{}:
      False{}

def lower_ok(v: V.Version, lower: Maybe<&2, String>) -> Bool:
  match lower:
    case None{}:
      True{}
    case Some{lo}:
      lower_parsed(v, V.read(lo))

def upper_ok(v: V.Version, upper: Maybe<&2, V.Version>) -> Bool:
  match upper:
    case Some{hi}:
      V.less(V.cmp(v, hi))
    case None{}:
      False{}

def affected(rs: List<&2, C.AffectedRange>, +name: String, +v: V.Version) -> Maybe<&2, C.AffectedRange>:
  match rs:
    case Nil{}:
      None{}
    case Con{+r, rest}:
      C.AffectedRange{+package, lower, upper, fixed, provenance} = r
      L.sel(Maybe<&2, C.AffectedRange>, String.eq(name, package) && lower_ok(v, lower) && upper_ok(v, V.read(upper)),
        u => Some{r}, u => affected(rest, name, v))

def has_package(rs: List<&2, C.AffectedRange>, +name: String) -> Bool:
  match rs:
    case Nil{}:
      False{}
    case Con{C.AffectedRange{package, lower, upper, fixed, provenance}, rest}:
      String.eq(package, name) || has_package(rest, name)

def matched(r: Maybe<&2, C.AffectedRange>, n: U32, a: C.Advisory, version: String, group: String) -> List<&2, Finding>:
  match r:
    case None{}:
      []
    case Some{r}:
      [Match{n, a, r, version, group, []}]

def decision(v: Maybe<&2, V.Version>, +rs: List<&2, C.AffectedRange>, name: String, n: U32, a: C.Advisory, version: String, group: String) -> List<&2, Finding>:
  match v:
    case None{}:
      [Unknown{n, "unsupported installed version " ++ version ++ " in " ++ group ++ "; expected an exact supported SemVer"}]
    case Some{v}:
      matched(affected(rs, name, v), n, a, version, group)

def records(rs: List<&2, C.Advisory>, +name: String, +version: String, +n: U32, +group: String) -> List<&2, Finding>:
  match rs:
    case Nil{}:
      []
    case Con{+a, rest}:
      C.Advisory{id, cve, profile, +ranges, sources, functions} = a
      found = L.sel(List<&2, Finding>, has_package(ranges, name),
        u => decision(V.read(version), ranges, name, n, a, version, group), u => [])
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

def needs_source(fs: List<&2, Finding>) -> Bool:
  match fs:
    case Nil{}:
      False{}
    case Con{Match{n, C.Advisory{id, cve, profile, ranges, sources, functions}, r, v, g, sites}, rest}:
      String.eq(profile, "symfony-path-prefix") || needs_source(rest)
    case Con{f, rest}:
      needs_source(rest)

def enrich(fs: List<&2, Finding>, +e: P.Evidence) -> List<&2, Finding>:
  match fs:
    case Nil{}:
      []
    case Con{Match{+n, +a, +r, +v, +g, old}, rest}:
      C.Advisory{id, cve, +profile, ranges, sources, functions} = a
      P.Evidence{+sites, +inc} = e
      found = L.sel(List<&2, Finding>, String.eq(profile, "symfony-path-prefix"),
        u => L.sel(List<&2, Finding>, inc,
          v0 => [Match{n, a, r, v, g, []}, Unknown{n, "source evidence analysis exhausted its budget"}],
          v0 => [Match{n, a, r, v, g, sites}]),
        u => [Match{n, a, r, v, g, []}])
      List.append(&2, Finding, found, enrich(rest, P.Evidence{sites, inc}))
    case Con{f, rest}:
      Con{f, enrich(rest, e)}

def finding.le(a: Finding, b: Finding) -> Bool:
  +x = a
  +y = b
  L.sel(Bool, U32.is_eq(line(x), line(y)), u => String.is_le(rule(x), rule(y)), u => U32.is_le(line(x), line(y)))

def scan(s: String) -> List<&2, Finding>:
  List.sort(~Finding, ~finding.le, decoded(J.read(s)))
