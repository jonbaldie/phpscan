import Base
import ./lex.bend as L

type Src is Data:
  Src{path: String, text: String}

type ObservationKind is Data:
  TokenGuard{}
  GuardRoute{}
  DatabaseSelection{}

type ObservationStatus is Data:
  Possible{}
  Unknown{}

type Site is Data:
  Site{path: String, methodLine: U32, checkLine: U32, authorizationLine: U32, receiverType: String, prefix: String}
  Observation{path: String, line: U32, kind: ObservationKind, status: ObservationStatus, detail: String}

type Evidence is Data:
  Evidence{sites: List<&2, Site>, incomplete: Bool}

def kind(k: ObservationKind) -> String:
  match k:
    case TokenGuard{}:
      "token-guard"
    case GuardRoute{}:
      "guard-route"
    case DatabaseSelection{}:
      "database-selection"

def status(s: ObservationStatus) -> String:
  match s:
    case Possible{}:
      "possible"
    case Unknown{}:
      "unknown"

def merge(a: Evidence, b: Evidence) -> Evidence:
  match a b:
    case Evidence{xs, i} Evidence{ys, j}:
      Evidence{List.append(&2, Site, xs, ys), i || j}

def ignored(xs: List<&2, U32>, +line: U32) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{x, rest}:
      U32.is_eq(x, line) || ignored(rest, line)

def line(s: Site) -> U32:
  match s:
    case Site{p, method, c, a, t, s}:
      method
    case Observation{p, l, k, s, d}:
      l

def visible(sites: List<&2, Site>, +lines: List<&2, U32>) -> List<&2, Site>:
  match sites:
    case Nil{}:
      []
    case Con{+site, +rest}:
      L.sel(List<&2, Site>, ignored(lines, line(site)), u => visible(rest, lines), u => Con{site, visible(rest, lines)})

def suppress(e: Evidence, lines: List<&2, U32>) -> Evidence:
  match e:
    case Evidence{sites, inc}:
      Evidence{visible(sites, lines), inc}

def for_profile(sites: List<&2, Site>, +profile: String) -> List<&2, Site>:
  match sites:
    case Nil{}:
      []
    case Con{Site{p, m, c, a, t, s}, rest}:
      +wanted = for_profile(rest, profile)
      L.sel(List<&2, Site>, String.eq(profile, "symfony-path-prefix"), u => Con{Site{p, m, c, a, t, s}, wanted}, u => wanted)
    case Con{Observation{p, l, k, s, d}, rest}:
      +wanted = for_profile(rest, profile)
      L.sel(List<&2, Site>, String.eq(profile, "laravel-token-guard"), u => Con{Observation{p, l, k, s, d}, wanted}, u => wanted)

def possible(sites: List<&2, Site>) -> Bool:
  match sites:
    case Nil{}:
      False{}
    case Con{Site{p, m, c, a, t, s}, rest}:
      True{}
    case Con{Observation{p, l, k, Possible{}, d}, rest}:
      True{}
    case Con{Observation{p, l, k, Unknown{}, d}, rest}:
      possible(rest)
