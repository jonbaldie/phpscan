import Base
import ./lex.bend as L

type Src is Data:
  Src{path: String, text: String}

type ObservationKind is Data:
  TokenGuard{}
  GuardRoute{}
  DatabaseSelection{}
  JsonApiResource{}
  JsonApiRelationships{}
  JsonApiEndpoint{}
  LivewireMethod{}
  LivewireRoute{}
  LivewireMitigation{}

type ObservationStatus is Data:
  Possible{}
  Unknown{}
  Mitigation{}

type Site is Data:
  Site{path: String, methodLine: U32, checkLine: U32, authorizationLine: U32, receiverType: String, prefix: String}
  Observation{path: String, line: U32, kind: ObservationKind, status: ObservationStatus, detail: String}

type Evidence is Data:
  Complete{sites: List<&2, Site>}
  Incomplete{sites: List<&2, Site>}

type Completion is Data:
  Finished{}
  Exhausted{}

def kind(k: ObservationKind) -> String:
  match k:
    case TokenGuard{}:
      "token-guard"
    case GuardRoute{}:
      "guard-route"
    case DatabaseSelection{}:
      "database-selection"
    case JsonApiResource{}:
      "jsonapi-resource"
    case JsonApiRelationships{}:
      "jsonapi-relationships"
    case JsonApiEndpoint{}:
      "jsonapi-endpoint"
    case LivewireMethod{}:
      "livewire-method"
    case LivewireRoute{}:
      "livewire-route"
    case LivewireMitigation{}:
      "livewire-mitigation"

def profile(k: ObservationKind) -> String:
  match k:
    case TokenGuard{}:
      "laravel-token-guard"
    case GuardRoute{}:
      "laravel-token-guard"
    case DatabaseSelection{}:
      "laravel-token-guard"
    case JsonApiResource{}:
      "laravel-jsonapi"
    case JsonApiRelationships{}:
      "laravel-jsonapi"
    case JsonApiEndpoint{}:
      "laravel-jsonapi"
    case LivewireMethod{}:
      "livewire-json-authorize"
    case LivewireRoute{}:
      "livewire-json-authorize"
    case LivewireMitigation{}:
      "livewire-json-authorize"

def status(s: ObservationStatus) -> String:
  match s:
    case Possible{}:
      "possible"
    case Unknown{}:
      "unknown"
    case Mitigation{}:
      "mitigation"

def completion_merge(a: Completion, b: Completion) -> Completion:
  match a b:
    case Finished{} Finished{}:
      Finished{}
    case _ _:
      Exhausted{}

def from_completion(sites: List<&2, Site>, completion: Completion) -> Evidence:
  match completion:
    case Finished{}:
      Complete{sites}
    case Exhausted{}:
      Incomplete{sites}

def sites(e: Evidence) -> List<&2, Site>:
  match e:
    case Complete{xs}:
      xs
    case Incomplete{xs}:
      xs

def merge(a: Evidence, b: Evidence) -> Evidence:
  match a b:
    case Complete{xs} Complete{ys}:
      Complete{List.append(&2, Site, xs, ys)}
    case Complete{xs} Incomplete{ys}:
      Incomplete{List.append(&2, Site, xs, ys)}
    case Incomplete{xs} Complete{ys}:
      Incomplete{List.append(&2, Site, xs, ys)}
    case Incomplete{xs} Incomplete{ys}:
      Incomplete{List.append(&2, Site, xs, ys)}

def ignored(xs: List<&2, U32>, +line: U32) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{x, rest}:
      U32.is_eq(x, line) || ignored(rest, line)

def site_ignored(+lines: List<&2, U32>, +s: Site) -> Bool:
  match s:
    case Site{p, method, c, a, t, u}:
      ignored(lines, method) || ignored(lines, c) || ignored(lines, a)
    case Observation{p, l, k, st, d}:
      ignored(lines, l)

def visible(sites: List<&2, Site>, +lines: List<&2, U32>) -> List<&2, Site>:
  match sites:
    case Nil{}:
      []
    case Con{+site, +rest}:
      L.sel(List<&2, Site>, site_ignored(lines, site), u => visible(rest, lines), u => Con{site, visible(rest, lines)})

def suppress(e: Evidence, lines: List<&2, U32>) -> Evidence:
  match e:
    case Complete{sites}:
      Complete{visible(sites, lines)}
    case Incomplete{sites}:
      Incomplete{visible(sites, lines)}

def for_profile(sites: List<&2, Site>, +wanted_profile: String) -> List<&2, Site>:
  match sites:
    case Nil{}:
      []
    case Con{Site{p, m, c, a, t, s}, rest}:
      +wanted = for_profile(rest, wanted_profile)
      L.sel(List<&2, Site>, String.eq(wanted_profile, "symfony-path-prefix"), u => Con{Site{p, m, c, a, t, s}, wanted}, u => wanted)
    case Con{Observation{p, l, +k, s, d}, rest}:
      +wanted = for_profile(rest, wanted_profile)
      L.sel(List<&2, Site>, String.eq(wanted_profile, profile(k)), u => Con{Observation{p, l, k, s, d}, wanted}, u => wanted)

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
    case Con{Observation{p, l, k, Mitigation{}, d}, rest}:
      possible(rest)
