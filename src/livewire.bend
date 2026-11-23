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

type Flag is Data:
  Flag{value: Bool, completion: E.Completion}

type Mitigation is Data:
  Mitigation{line: Maybe<&2, U32>, completion: E.Completion}

type Methods is Data:
  Methods{items: List<&2, Method>, completion: E.Completion}

def merge_flag(result: Flag, value: Bool) -> Flag:
  match result:
    case Flag{found, done}:
      Flag{value || found, done}


def attribute(fuel: Nat, ns: List<&2, T.Node>, +scope: J.Scope, +target: String) -> Flag:
  match fuel ns:
    case _ Nil{}:
      Flag{False{}, E.Finished{}}
    case 0n _:
      Flag{False{}, E.Exhausted{}}
    case 1n+(+p) Con{T.Leaf{L.Tok{1, name, l}}, rest}:
      merge_flag(attribute(p, rest, scope, target), String.eq(J.resolve(name, scope), target))
    case 1n+(+p) Con{node, rest}:
      attribute(p, rest, scope, target)

def merge_mitigation(first: Mitigation, second: Mitigation) -> Mitigation:
  match first second:
    case Mitigation{Some{x}, a} Mitigation{next, b}:
      Mitigation{Some{x}, E.completion_merge(a, b)}
    case Mitigation{None{}, a} Mitigation{next, b}:
      Mitigation{next, E.completion_merge(a, b)}


def mitigation(fuel: Nat, ns: List<&2, T.Node>, +lines: List<&2, U32>) -> Mitigation:
  match fuel ns:
    case _ Nil{}:
      Mitigation{None{}, E.Finished{}}
    case 0n _:
      Mitigation{None{}, E.Exhausted{}}
    case 1n+(+p) Con{T.Leaf{L.Tok{0, "this", +line}}, Con{T.Leaf{L.Tok{5, "->", a}}, Con{T.Leaf{L.Tok{1, "authorize", b}}, Con{T.Grp{40, c, args}, rest}}}}:
      L.sel(Mitigation, E.ignored(lines, line), u => mitigation(p, rest, lines), u => Mitigation{Some{line}, E.Finished{}})
    case 1n+(+p) Con{T.Grp{kind, l, body}, rest}:
      merge_mitigation(mitigation(p, body, lines), mitigation(p, rest, lines))
    case 1n+(+p) Con{n, rest}:
      mitigation(p, rest, lines)

def method_body(fuel: Nat, ns: List<&2, T.Node>, lines: List<&2, U32>) -> Mitigation:
  match fuel ns:
    case _ Nil{}:
      Mitigation{None{}, E.Finished{}}
    case 0n _:
      Mitigation{None{}, E.Exhausted{}}
    case 1n+(+p) Con{T.Grp{123, l, body}, rest}:
      mitigation(p, body, lines)
    case 1n+(+p) Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      Mitigation{None{}, E.Finished{}}
    case 1n+(+p) Con{n, rest}:
      method_body(p, rest, lines)

def finish_method(result: Mitigation, path: String, line: U32, name: String, tail: List<&2, Method>, done: E.Completion) -> Methods:
  match result:
    case Mitigation{mitig, m}:
      Methods{Con{Method{path, line, name, mitig}, tail}, E.completion_merge(done, m)}


def method_found(result: Methods, fuel: Nat, rest: List<&2, T.Node>, path: String, lines: List<&2, U32>, line: U32, name: String, eligible: Bool) -> Methods:
  match result:
    case Methods{+tail, +done}:
      L.sel(Methods, eligible, u => finish_method(method_body(fuel, rest, lines), path, line, name, tail, done), u => Methods{tail, done})


def merge_methods(result: Methods, done: E.Completion) -> Methods:
  match result:
    case Methods{items, c}:
      Methods{items, E.completion_merge(done, c)}


def flag_value(flag: Flag) -> Bool:
  match flag:
    case Flag{value, done}:
      value

def flag_completion(flag: Flag) -> E.Completion:
  match flag:
    case Flag{value, done}:
      done

def methods(fuel: Nat, ns: List<&2, T.Node>, +scope: J.Scope, +path: String, +lines: List<&2, U32>, +auth: Bool, +json: Bool) -> Methods:
  match fuel ns:
    case _ Nil{}:
      Methods{[], E.Finished{}}
    case 0n _:
      Methods{[], E.Exhausted{}}
    case 1n+(+p) Con{T.Grp{35, +line, +attrs}, rest}:
      +visible = Bool.not(E.ignored(lines, line))
      +a = attribute(p, attrs, scope, "livewire\\attributes\\authorize")
      +b = attribute(p, attrs, scope, "livewire\\attributes\\json")
      merge_methods(methods(p, rest, scope, path, lines, auth || (visible && flag_value(a)), json || (visible && flag_value(b))), E.completion_merge(flag_completion(a), flag_completion(b)))
    case 1n+(+p) Con{T.Leaf{L.Tok{1, "function", +line}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Grp{40, a, args}, +rest}}}:
      method_found(methods(p, rest, scope, path, lines, False{}, False{}), p, rest, path, lines, line, name, auth && json && Bool.not(E.ignored(lines, line)))
    case 1n+(+p) Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      methods(p, rest, scope, path, lines, False{}, False{})
    case 1n+(+p) Con{T.Grp{123, l, body}, rest}:
      methods(p, rest, scope, path, lines, False{}, False{})
    case 1n+(+p) Con{n, rest}:
      methods(p, rest, scope, path, lines, auth, json)

def add_component(result: Collected, component: Component) -> Collected:
  match result:
    case Collected{cs, done}:
      Collected{Con{component, cs}, done}

type ClassTail is Data:
  ClassTail{nodes: List<&2, T.Node>, completion: E.Completion}

def class_tail(fuel: Nat, ns: List<&2, T.Node>) -> ClassTail:
  match fuel ns:
    case _ Nil{}:
      ClassTail{[], E.Finished{}}
    case 0n _:
      ClassTail{[], E.Exhausted{}}
    case 1n+(+p) Con{T.Grp{123, l, body}, rest}:
      ClassTail{ns, E.Finished{}}
    case 1n+(+p) Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      ClassTail{rest, E.Finished{}}
    case 1n+(+p) Con{node, rest}:
      class_tail(p, rest)

def tail_rest(tail: ClassTail) -> List<&2, T.Node>:
  match tail:
    case ClassTail{Con{T.Grp{123, l, body}, rest}, done}:
      rest
    case ClassTail{nodes, done}:
      nodes

def tail_methods(tail: ClassTail, allowance: Nat, scope: J.Scope, path: String, lines: List<&2, U32>, eligible: Bool) -> Methods:
  match tail:
    case ClassTail{Con{T.Grp{123, l, body}, rest}, done}:
      merge_methods(L.sel(Methods, eligible, u => methods(allowance, body, scope, path, lines, False{}, False{}), u => Methods{[], E.Finished{}}), done)
    case ClassTail{nodes, done}:
      Methods{[], done}

def finish_class(result: Methods, collected: Collected, identity: String) -> Collected:
  match result collected:
    case Methods{ms, a} Collected{cs, b}:
      Collected{Con{Component{identity, ms}, cs}, E.completion_merge(a, b)}

def classes(fuel: Nat, +allowance: Nat, ns: List<&2, T.Node>, +scope: J.Scope, +path: String, +lines: List<&2, U32>) -> Collected:
  match fuel ns scope:
    case _ Nil{} _:
      Collected{[], E.Finished{}}
    case 0n _ _:
      Collected{[], E.Exhausted{}}
    case _ _ J.Invalid{}:
      Collected{[], E.Finished{}}
    case 1n+(+p) Con{T.Leaf{L.Tok{1, "class", +line}}, Con{T.Leaf{L.Tok{1, +name, n}}, Con{T.Leaf{L.Tok{1, "extends", e}}, Con{T.Leaf{L.Tok{1, base, b}}, rest}}}} J.Scope{+namespace, +im}:
      +tail = class_tail(p, rest)
      finish_class(tail_methods(tail, allowance, J.Scope{namespace, im}, path, lines, String.eq(J.resolve(base, J.Scope{namespace, im}), "livewire\\component") && Bool.not(E.ignored(lines, line))), classes(p, allowance, tail_rest(tail), J.Scope{namespace, im}, path, lines), J.join(namespace, name))
    case 1n+(+p) Con{T.Leaf{L.Tok{1, "class", l}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Grp{123, c, body}, rest}}} J.Scope{+namespace, im}:
      add_component(classes(p, allowance, rest, J.Scope{namespace, im}, path, lines), Component{J.join(namespace, name), []})
    case 1n+(+p) Con{node, rest} _:
      classes(p, allowance, rest, scope, path, lines)

def file_input(input: Maybe<&2, P.Input>, path: String) -> Collected:
  match input:
    case None{}:
      Collected{[], E.Finished{}}
    case Some{P.Input{+nodes, tokens, lines, +allowance}}:
      classes(allowance, allowance, nodes, J.file_scope(nodes), path, lines)

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
    case 1n+(+p) Con{T.Leaf{L.Tok{1, facade, +line}}, Con{T.Leaf{L.Tok{5, "::", c}}, Con{T.Leaf{L.Tok{1, "get", g}}, Con{T.Grp{40, a, args}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}}}} _ True{}:
      +tail = routes(p, rest, scope, components, path, lines, True{})
      L.sel(E.Evidence, String.eq(J.resolve(facade, scope), "illuminate\\support\\facades\\route") && Bool.not(E.ignored(lines, line)) && route_args(args, scope, components),
        u => E.merge(E.Complete{[E.Observation{path, line, E.LivewireRoute{}, E.Possible{}, "component route; runtime registration and exposure unknown"}]}, tail), u => tail)
    case 1n+(+p) Con{T.Leaf{L.Tok{5, ";", l}}, rest} _ _:
      routes(p, rest, scope, components, path, lines, True{})
    case 1n+(+p) Con{T.Grp{123, l, body}, rest} _ _:
      routes(p, rest, scope, components, path, lines, True{})
    case 1n+(+p) Con{node, rest} _ _:
      routes(p, rest, scope, components, path, lines, False{})

def route_input(input: Maybe<&2, P.Input>, path: String, components: List<&2, Component>) -> E.Evidence:
  match input:
    case None{}:
      E.Complete{[]}
    case Some{P.Input{+nodes, tokens, lines, +allowance}}:
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
