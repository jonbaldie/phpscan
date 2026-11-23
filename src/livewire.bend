import Base
import ./lex.bend as L
import ./tree.bend as T
import ./profile-input.bend as P
import ./evidence.bend as E
import ./jsonapi.bend as J

type Method is Data:
  Method{path: String, line: U32, name: String, mitigation: Maybe<&2, U32>}

type Component is Data:
  Component{identity: String, methods: List<&2, Method>}

type Collected is Data:
  Collected{components: List<&2, Component>, completion: E.Completion}

def attribute(ns: List<&2, T.Node>, +scope: J.Scope, +target: String) -> Bool:
  match ns:
    case Con{T.Leaf{L.Tok{1, name, l}}, rest}:
      String.eq(J.resolve(name, scope), target) || attribute(rest, scope, target)
    case Con{node, rest}:
      attribute(rest, scope, target)
    case Nil{}:
      False{}

def mitigation(ns: List<&2, T.Node>, +lines: List<&2, U32>) -> Maybe<&2, U32>:
  match ns:
    case Nil{}:
      None{}
    case Con{T.Leaf{L.Tok{0, "this", +line}}, Con{T.Leaf{L.Tok{5, "->", a}}, Con{T.Leaf{L.Tok{1, "authorize", b}}, Con{T.Grp{40, c, args}, rest}}}}:
      L.sel(Maybe<&2, U32>, E.ignored(lines, line), u => mitigation(rest, lines), u => Some{line})
    case Con{n, rest}:
      mitigation(rest, lines)

def method_body(ns: List<&2, T.Node>, lines: List<&2, U32>) -> Maybe<&2, U32>:
  match ns:
    case Nil{}:
      None{}
    case Con{T.Grp{123, l, body}, rest}:
      mitigation(body, lines)
    case Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      None{}
    case Con{n, rest}:
      method_body(rest, lines)

def methods(ns: List<&2, T.Node>, +scope: J.Scope, +path: String, +lines: List<&2, U32>, +auth: Bool, +json: Bool) -> List<&2, Method>:
  match ns:
    case Nil{}:
      []
    case Con{T.Grp{35, +line, +attrs}, rest}:
      +visible = Bool.not(E.ignored(lines, line))
      methods(rest, scope, path, lines, auth || (visible && attribute(attrs, scope, "livewire\\attributes\\authorize")), json || (visible && attribute(attrs, scope, "livewire\\attributes\\json")))
    case Con{T.Leaf{L.Tok{1, "function", +line}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Grp{40, a, args}, +rest}}}:
      +tail = methods(rest, scope, path, lines, False{}, False{})
      L.sel(List<&2, Method>, auth && json && Bool.not(E.ignored(lines, line)), u => Con{Method{path, line, name, method_body(rest, lines)}, tail}, u => tail)
    case Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      methods(rest, scope, path, lines, False{}, False{})
    case Con{T.Grp{123, l, body}, rest}:
      methods(rest, scope, path, lines, False{}, False{})
    case Con{n, rest}:
      methods(rest, scope, path, lines, auth, json)

def add_component(result: Collected, component: Component) -> Collected:
  match result:
    case Collected{cs, done}:
      Collected{Con{component, cs}, done}

def classes(fuel: Nat, ns: List<&2, T.Node>, +scope: J.Scope, +path: String, +lines: List<&2, U32>) -> Collected:
  match fuel ns scope:
    case _ Nil{} _:
      Collected{[], E.Finished{}}
    case 0n _ _:
      Collected{[], E.Exhausted{}}
    case _ _ J.Invalid{}:
      Collected{[], E.Finished{}}
    case 1n+p Con{T.Leaf{L.Tok{1, "class", +line}}, Con{T.Leaf{L.Tok{1, +name, n}}, Con{T.Leaf{L.Tok{1, "extends", e}}, Con{T.Leaf{L.Tok{1, base, b}}, Con{T.Grp{123, c, body}, rest}}}}} J.Scope{+namespace, +im}:
      +ms = L.sel(List<&2, Method>, String.eq(J.resolve(base, J.Scope{namespace, im}), "livewire\\component") && Bool.not(E.ignored(lines, line)),
        u => methods(body, J.Scope{namespace, im}, path, lines, False{}, False{}), u => [])
      add_component(classes(p, rest, J.Scope{namespace, im}, path, lines), Component{J.join(namespace, name), ms})
    case 1n+p Con{T.Leaf{L.Tok{1, "class", l}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Grp{123, c, body}, rest}}} J.Scope{+namespace, im}:
      add_component(classes(p, rest, J.Scope{namespace, im}, path, lines), Component{J.join(namespace, name), []})
    case 1n+p Con{node, rest} _:
      classes(p, rest, scope, path, lines)

def file_input(input: Maybe<&2, P.Input>, path: String) -> Collected:
  match input:
    case None{}:
      Collected{[], E.Finished{}}
    case Some{P.Input{+nodes, tokens, lines, allowance}}:
      classes(allowance, nodes, J.file_scope(nodes), path, lines)

def file(source: E.Src) -> Collected:
  match source:
    case E.Src{path, text}:
      file_input(P.parse(text), path)

def combine(a: Collected, b: Collected) -> Collected:
  match a b:
    case Collected{xs, i} Collected{ys, j}:
      Collected{List.append(&2, Component, xs, ys), E.completion_merge(i, j)}

def collect(sources: List<&2, E.Src>) -> Collected:
  match sources:
    case Nil{}:
      Collected{[], E.Finished{}}
    case Con{source, rest}:
      a b = file(source) collect(rest)
      combine(a, b)

def mitigation_site(m: Maybe<&2, U32>, path: String) -> List<&2, E.Site>:
  match m:
    case None{}:
      []
    case Some{line}:
      [E.Observation{path, line, E.LivewireMitigation{}, E.Mitigation{}, "in-method authorize call; authorization outcome unknown"}]

def method_sites(ms: List<&2, Method>, +identity: String) -> List<&2, E.Site>:
  match ms:
    case Nil{}:
      []
    case Con{Method{+path, line, name, mitig}, rest}:
      Con{E.Observation{path, line, E.LivewireMethod{}, E.Possible{}, "component " ++ identity ++ " method " ++ name ++ "; mounting and runtime authorization unknown"}, List.append(&2, E.Site, mitigation_site(mitig, path), method_sites(rest, identity))}

def component_sites(cs: List<&2, Component>) -> List<&2, E.Site>:
  match cs:
    case Nil{}:
      []
    case Con{Component{id, ms}, rest}:
      List.append(&2, E.Site, method_sites(ms, id), component_sites(rest))

def has_methods(ms: List<&2, Method>) -> Bool:
  match ms:
    case Nil{}:
      False{}
    case Con{x, xs}:
      True{}

def contains_component(cs: List<&2, Component>, +identity: String) -> Bool:
  match cs:
    case Nil{}:
      False{}
    case Con{Component{id, ms}, rest}:
      String.eq(id, identity) || contains_component(rest, identity)

def has_component(cs: List<&2, Component>, +identity: String) -> Bool:
  match cs:
    case Nil{}:
      False{}
    case Con{Component{id, ms}, +rest}:
      L.sel(Bool, String.eq(id, identity), u => has_methods(ms) && Bool.not(contains_component(rest, identity)), u => has_component(rest, identity))

def route_args(ns: List<&2, T.Node>, scope: J.Scope, components: List<&2, Component>) -> Bool:
  match ns:
    case Con{T.Leaf{L.Tok{2, uri, l}}, Con{T.Leaf{L.Tok{5, ",", c}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Leaf{L.Tok{5, "::", d}}, Con{T.Leaf{L.Tok{1, "class", e}}, Nil{}}}}}}:
      has_component(components, J.resolve(name, scope))
    case _:
      False{}

def routes(fuel: Nat, ns: List<&2, T.Node>, +scope: J.Scope, +components: List<&2, Component>, +path: String, +lines: List<&2, U32>, start: Bool) -> E.Evidence:
  match fuel ns scope start:
    case _ Nil{} _ _:
      E.Complete{[]}
    case 0n _ _ _:
      E.Incomplete{[]}
    case _ _ J.Invalid{} _:
      E.Complete{[]}
    case 1n+p Con{T.Leaf{L.Tok{1, facade, +line}}, Con{T.Leaf{L.Tok{5, "::", c}}, Con{T.Leaf{L.Tok{1, "get", g}}, Con{T.Grp{40, a, args}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}}}} _ True{}:
      +tail = routes(p, rest, scope, components, path, lines, True{})
      L.sel(E.Evidence, String.eq(J.resolve(facade, scope), "illuminate\\support\\facades\\route") && Bool.not(E.ignored(lines, line)) && route_args(args, scope, components),
        u => E.merge(E.Complete{[E.Observation{path, line, E.LivewireRoute{}, E.Possible{}, "component route; runtime registration and exposure unknown"}]}, tail), u => tail)
    case 1n+p Con{T.Leaf{L.Tok{5, ";", l}}, rest} _ _:
      routes(p, rest, scope, components, path, lines, True{})
    case 1n+p Con{T.Grp{123, l, body}, rest} _ _:
      routes(p, rest, scope, components, path, lines, True{})
    case 1n+p Con{node, rest} _ _:
      routes(p, rest, scope, components, path, lines, False{})

def route_input(input: Maybe<&2, P.Input>, path: String, components: List<&2, Component>) -> E.Evidence:
  match input:
    case None{}:
      E.Complete{[]}
    case Some{P.Input{+nodes, tokens, lines, allowance}}:
      routes(allowance, nodes, J.file_scope(nodes), components, path, lines, True{})

def route_files(xs: List<&2, E.Src>, +components: List<&2, Component>) -> E.Evidence:
  match xs:
    case Nil{}:
      E.Complete{[]}
    case Con{E.Src{path, text}, rest}:
      a b = route_input(P.parse(text), path, components) route_files(rest, components)
      E.merge(a, b)

def finish(c: Collected, sources: List<&2, E.Src>) -> E.Evidence:
  match c:
    case Collected{+components, completion}:
      E.merge(E.from_completion(component_sites(components), completion), route_files(sources, components))

def scan(sources: List<&2, E.Src>) -> E.Evidence:
  +ordered = List.sort(~E.Src, ~J.source_le, sources)
  finish(collect(ordered), ordered)
