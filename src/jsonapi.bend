import Base
import ./lex.bend as L
import ./tree.bend as T
import ./evidence.bend as E

type Relationships is Data:
  Literal{line: U32, names: List<&2, String>}
  Unknown{line: U32, reason: String}

type Resource is Data:
  Resource{identity: String, path: String, line: U32, relationships: Relationships}

type Endpoint is Data:
  Endpoint{path: String, line: U32, route: String, resource: Resource}

type ScanResult is Data:
  ScanResult{resources: List<&2, Resource>, endpoints: List<&2, Endpoint>, incomplete: Bool}

type Import is Data:
  Import{alias: String, target: String}

type Scope is Data:
  Scope{namespace: String, imports: List<&2, Import>}
  Invalid{}

type ClassState is Data:
  Other{}
  ResourceClass{resource: Resource, visible: Bool}
  Ambiguous{}

type Entry is Data:
  Entry{identity: String, state: ClassState}

type Index is Data:
  Index{entries: List<&2, Entry>, uncertain: Bool, incomplete: Bool}

def ignored(xs: List<&2, U32>, +line: U32) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{x, rest}:
      U32.is_eq(x, line) || ignored(rest, line)

def simple_name(s: String, start: Bool) -> Bool:
  match s start:
    case SNil{} False{}:
      True{}
    case SCon{c, rest} True{}:
      L.is_name_start(c) && simple_name(rest, False{})
    case SCon{c, rest} False{}:
      L.is_name_char(c) && simple_name(rest, False{})
    case _ _:
      False{}

def qualified_name(s: String, start: Bool) -> Bool:
  match s start:
    case SNil{} False{}:
      True{}
    case SCon{'\\', rest} False{}:
      qualified_name(rest, True{})
    case SCon{c, rest} True{}:
      L.is_name_start(c) && qualified_name(rest, False{})
    case SCon{c, rest} False{}:
      L.is_name_char(c) && qualified_name(rest, False{})
    case _ _:
      False{}

def absolute(s: String) -> String:
  match s:
    case SCon{'\\', rest}:
      rest
    case s:
      s

def has_alias(xs: List<&2, Import>, +alias: String) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{Import{name, target}, rest}:
      String.eq(name, alias) || has_alias(rest, alias)

def valid_import(name: String, +alias: String, im: List<&2, Import>) -> Bool:
  qualified_name(absolute(name), True{}) && simple_name(alias, True{}) && Bool.not(has_alias(im, alias))

def unsupported_keyword(+name: String) -> Bool:
  String.eq(name, "endif") || String.eq(name, "endwhile") || String.eq(name, "endfor") ||
    String.eq(name, "endforeach") || String.eq(name, "endswitch") || String.eq(name, "enddeclare") ||
    String.eq(name, "__halt_compiler") || String.eq(name, "declare")

def scope(ns: List<&2, T.Node>, namespace: String, +im: List<&2, Import>, leading: Bool) -> Scope:
  match ns leading:
    case Nil{} _:
      Scope{namespace, im}
    case Con{T.Leaf{L.Tok{1, "namespace", l}}, rest} _:
      Invalid{}
    case Con{T.Leaf{L.Tok{1, "use", l}}, Con{T.Leaf{L.Tok{1, +name, n}}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}} True{}:
      +alias = L.strip_ns(name)
      L.sel(Scope, valid_import(name, alias, im), u => scope(rest, namespace, Con{Import{alias, absolute(name)}, im}, True{}), u => Invalid{})
    case Con{T.Leaf{L.Tok{1, "use", l}}, Con{T.Leaf{L.Tok{1, +name, n}}, Con{T.Leaf{L.Tok{1, "as", a}}, Con{T.Leaf{L.Tok{1, +alias, b}}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}}}} True{}:
      L.sel(Scope, valid_import(name, alias, im), u => scope(rest, namespace, Con{Import{alias, absolute(name)}, im}, True{}), u => Invalid{})
    case Con{T.Leaf{L.Tok{1, "use", l}}, rest} _:
      Invalid{}
    case Con{T.Leaf{L.Tok{1, name, l}}, rest} _:
      L.sel(Scope, unsupported_keyword(name), u => Invalid{}, u => scope(rest, namespace, im, False{}))
    case Con{n, rest} _:
      scope(rest, namespace, im, False{})

def namespace_scope(ns: List<&2, T.Node>) -> Scope:
  match ns:
    case Con{T.Leaf{L.Tok{1, "namespace", l}}, Con{T.Leaf{L.Tok{1, +name, n}}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}}:
      L.sel(Scope, qualified_name(name, True{}), u => scope(rest, name, [], True{}), u => Invalid{})
    case ns:
      scope(ns, "", [], True{})

def file_scope(ns: List<&2, T.Node>) -> Scope:
  match ns:
    case Con{T.Leaf{L.Tok{1, "declare", l}}, Con{T.Grp{40, p, Con{T.Leaf{L.Tok{1, "strict_types", s}}, Con{T.Leaf{L.Tok{5, "=", e}}, Con{T.Leaf{L.Tok{4, "1", v}}, Nil{}}}}}, Con{T.Leaf{L.Tok{5, ";", c}}, rest}}}:
      namespace_scope(rest)
    case ns:
      namespace_scope(ns)

def join(+namespace: String, +name: String) -> String:
  L.sel(String, String.is_empty(namespace), u => name, u => namespace ++ "\\" ++ name)

def first_part(s: String, acc: String) -> String & String:
  match s:
    case SNil{}:
      (String.reverse(acc), "")
    case SCon{'\\', rest}:
      (String.reverse(acc), "\\" ++ rest)
    case SCon{c, rest}:
      first_part(rest, SCon{c, acc})

def imported(xs: List<&2, Import>, +head: String, +tail: String, fallback: String) -> String:
  match xs:
    case Nil{}:
      fallback
    case Con{Import{alias, target}, rest}:
      L.sel(String, String.eq(alias, head), u => target ++ tail, u => imported(rest, head, tail, fallback))

def relative(parts: String & String, +name: String, namespace: String, im: List<&2, Import>) -> String:
  match parts:
    case (head, tail):
      L.sel(String, qualified_name(name, True{}), u => imported(im, head, tail, join(namespace, name)), u => "")

def resolve(name: String, sc: Scope) -> String:
  match name sc:
    case SCon{'\\', +rest} _:
      L.sel(String, qualified_name(rest, True{}), u => rest, u => "")
    case +name Scope{namespace, im}:
      relative(first_part(name, ""), name, namespace, im)
    case _ Invalid{}:
      ""

def literal_names(ns: List<&2, T.Node>) -> Maybe<&2, List<&2, String>>:
  match ns:
    case Nil{}:
      Some{[]}
    case Con{T.Leaf{L.Tok{2, name, l}}, Nil{}}:
      Some{[name]}
    case Con{T.Leaf{L.Tok{2, name, l}}, Con{T.Leaf{L.Tok{5, ",", c}}, rest}}:
      do Maybe<&2, List<&2, String>>:
        names : List<&2, String> <- literal_names(rest)
        return Con{name, names}
    case _:
      None{}

def literal_result(names: Maybe<&2, List<&2, String>>, line: U32) -> Relationships:
  match names:
    case Some{xs}:
      Literal{line, xs}
    case None{}:
      Unknown{line, "dynamic relationships"}

def relationship_body(ns: List<&2, T.Node>, method: U32) -> Relationships:
  match ns:
    case Con{T.Leaf{L.Tok{1, "return", +line}}, Con{T.Grp{91, a, values}, Con{T.Leaf{L.Tok{5, ";", e}}, Nil{}}}}:
      literal_result(literal_names(values), line)
    case Con{T.Leaf{L.Tok{1, "return", line}}, rest}:
      Unknown{line, "dynamic relationships"}
    case _:
      Unknown{method, "unsupported relationship body"}

def relationship_method(ns: List<&2, T.Node>, method: U32) -> Relationships:
  match ns:
    case Con{T.Grp{123, b, body}, rest}:
      relationship_body(body, method)
    case Con{T.Leaf{L.Tok{5, ":", c}}, Con{T.Leaf{L.Tok{1, "array", a}}, Con{T.Grp{123, b, body}, rest}}}:
      relationship_body(body, method)
    case _:
      Unknown{method, "unsupported relationship method"}

def relationship_choice(found: Maybe<&2, Relationships>, next: Relationships) -> Maybe<&2, Relationships>:
  match found:
    case None{}:
      Some{next}
    case Some{old}:
      Some{Unknown{0, "duplicate relationship methods"}}

def relationships(ns: List<&2, T.Node>, found: Maybe<&2, Relationships>) -> Relationships:
  match ns:
    case Nil{}:
      match found:
        case None{}:
          Unknown{0, "relationship declaration unavailable"}
        case Some{r}:
          r
    case Con{T.Leaf{L.Tok{1, "function", +line}}, Con{T.Leaf{L.Tok{1, "torelationships", n}}, Con{T.Grp{40, p, params}, +rest}}}:
      relationships(rest, relationship_choice(found, relationship_method(rest, line)))
    case Con{n, rest}:
      relationships(rest, found)

def visible_relationships(r: Relationships, lines: List<&2, U32>) -> Relationships:
  match r:
    case Literal{+line, names}:
      L.sel(Relationships, ignored(lines, line), u => Unknown{0, "relationship declaration suppressed"}, u => Literal{line, names})
    case Unknown{+line, reason}:
      L.sel(Relationships, ignored(lines, line), u => Unknown{0, "relationship declaration suppressed"}, u => Unknown{line, reason})

def insert(entries: List<&2, Entry>, +key: String, state: ClassState) -> List<&2, Entry>:
  match entries:
    case Nil{}:
      [Entry{key, state}]
    case Con{Entry{+identity, old}, +rest}:
      L.sel(List<&2, Entry>, String.eq(identity, key),
        u => Con{Entry{identity, Ambiguous{}}, rest},
        u => Con{Entry{identity, old}, insert(rest, key, state)})

def class_state(base: String, sc: Scope, key: String, path: String, +line: U32, body: List<&2, T.Node>, +lines: List<&2, U32>) -> ClassState:
  L.sel(ClassState, String.eq(resolve(base, sc), "illuminate\\http\\resources\\jsonapi\\jsonapiresource"),
    u => ResourceClass{Resource{key, path, line, visible_relationships(relationships(body, None{}), lines)}, Bool.not(ignored(lines, line))},
    u => Other{})

def skip_statement(ns: List<&2, T.Node>) -> List<&2, T.Node>:
  match ns:
    case Nil{}:
      []
    case Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      rest
    case Con{n, rest}:
      skip_statement(rest)

def class_count(ts: List<&2, L.Tok>) -> Nat:
  match ts:
    case Nil{}:
      0n
    case Con{L.Tok{1, "class", l}, Con{L.Tok{1, name, n}, rest}}:
      1n+class_count(rest)
    case Con{t, rest}:
      class_count(rest)

def declarations(fuel: Nat, ns: List<&2, T.Node>, +sc: Scope, +path: String, +lines: List<&2, U32>, expected: Nat, +entries: List<&2, Entry>) -> Index:
  match fuel ns sc:
    case _ Nil{} _:
      Index{entries, Bool.not(Nat.is_eq(expected, 0n)), False{}}
    case 0n _ _:
      Index{entries, False{}, True{}}
    case _ _ Invalid{}:
      Index{entries, True{}, False{}}
    case 1n+(+p) Con{T.Leaf{L.Tok{1, "class", +line}}, Con{T.Leaf{L.Tok{1, +name, n}}, Con{T.Leaf{L.Tok{1, "extends", e}}, Con{T.Leaf{L.Tok{1, base, b}}, Con{T.Grp{123, c, body}, rest}}}}} Scope{+namespace, +im}:
      +key = join(namespace, name)
      L.sel(Index, simple_name(name, True{}),
        u => declarations(p, rest, Scope{namespace, im}, path, lines, Nat.sub(expected, 1n), insert(entries, key, class_state(base, Scope{namespace, im}, key, path, line, body, lines))),
        u => Index{entries, True{}, False{}})
    case 1n+p Con{T.Leaf{L.Tok{1, "class", l}}, Con{T.Leaf{L.Tok{1, +name, n}}, Con{T.Grp{123, b, body}, rest}}} Scope{+namespace, im}:
      L.sel(Index, simple_name(name, True{}), u => declarations(p, rest, Scope{namespace, im}, path, lines, Nat.sub(expected, 1n), insert(entries, join(namespace, name), Other{})), u => Index{entries, True{}, False{}})
    case 1n+p Con{T.Leaf{L.Tok{1, "class", l}}, rest} _:
      Index{entries, True{}, False{}}
    case 1n+p Con{T.Leaf{L.Tok{1, "final", l}}, rest} _:
      declarations(p, rest, sc, path, lines, expected, entries)
    case 1n+p Con{T.Leaf{L.Tok{1, "abstract", l}}, rest} _:
      declarations(p, rest, sc, path, lines, expected, entries)
    case 1n+p +ns _:
      declarations(p, skip_statement(ns), sc, path, lines, expected, entries)

def index_file(source: E.Src, +entries: List<&2, Entry>) -> Index:
  match source:
    case E.Src{path, text}:
      +tokens = L.qualified(text)
      +nodes = T.tree(L.without_ignores(tokens))
      L.sel(Index, T.balanced(tokens, []),
        u => declarations(1n+List.length(&2, L.Tok, tokens), nodes, file_scope(nodes), path, L.ignored_lines(tokens, 0), class_count(L.without_ignores(tokens)), entries),
        u => Index{entries, True{}, False{}})

def index_flags(index: Index, uncertain: Bool, inc: Bool) -> Index:
  match index:
    case Index{es, u, i}:
      Index{es, uncertain || u, inc || i}

def index_sources(sources: List<&2, E.Src>, index: Index) -> Index:
  match sources index:
    case Nil{} index:
      index
    case Con{source, rest} Index{entries, +uncertain, +inc}:
      index_sources(rest, index_flags(index_file(source, entries), uncertain, inc))

def resource_lookup(entries: List<&2, Entry>, +key: String) -> Maybe<&2, Resource>:
  match entries:
    case Nil{}:
      None{}
    case Con{Entry{identity, ResourceClass{r, True{}}}, rest}:
      L.sel(Maybe<&2, Resource>, String.eq(identity, key), u => Some{r}, u => resource_lookup(rest, key))
    case Con{entry, rest}:
      resource_lookup(rest, key)

def return_class(ns: List<&2, T.Node>) -> String:
  match ns:
    case Con{T.Leaf{L.Tok{1, "new", l}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Grp{40, a, args}, Nil{}}}}:
      name
    case _:
      ""

def closure_class(ns: List<&2, T.Node>) -> String:
  match ns:
    case Con{T.Leaf{L.Tok{1, "return", r}}, Con{T.Leaf{L.Tok{1, "new", l}}, Con{T.Leaf{L.Tok{1, name, n}}, Con{T.Grp{40, a, args}, Con{T.Leaf{L.Tok{5, ";", e}}, Nil{}}}}}}:
      name
    case _:
      ""

def callback_class(ns: List<&2, T.Node>) -> String:
  match ns:
    case Con{T.Leaf{L.Tok{1, "fn", f}}, Con{T.Grp{40, p, params}, Con{T.Leaf{L.Tok{5, "=>", a}}, body}}}:
      return_class(body)
    case Con{T.Leaf{L.Tok{1, "function", f}}, Con{T.Grp{40, p, params}, Con{T.Grp{123, b, body}, Nil{}}}}:
      closure_class(body)
    case _:
      ""

def linked_endpoint(resource: Maybe<&2, Resource>, path: String, line: U32, route: String) -> List<&2, Endpoint>:
  match resource:
    case Some{Resource{key, rp, rl, Literal{rline, names}}}:
      [Endpoint{path, line, route, Resource{key, rp, rl, Literal{rline, names}}}]
    case _:
      []

def route_args(ns: List<&2, T.Node>, sc: Scope, entries: List<&2, Entry>, path: String, line: U32) -> List<&2, Endpoint>:
  match ns:
    case Con{T.Leaf{L.Tok{2, route, l}}, Con{T.Leaf{L.Tok{5, ",", c}}, callback}}:
      linked_endpoint(resource_lookup(entries, resolve(callback_class(callback), sc)), path, line, route)
    case _:
      []

def append_results(a: ScanResult, b: ScanResult) -> ScanResult:
  match a b:
    case ScanResult{rs, es, i} ScanResult{rt, et, j}:
      ScanResult{List.append(&2, Resource, rs, rt), List.append(&2, Endpoint, es, et), i || j}

def after_class(ns: List<&2, T.Node>) -> List<&2, T.Node>:
  match ns:
    case Nil{}:
      []
    case Con{T.Grp{123, l, body}, rest}:
      rest
    case Con{n, rest}:
      after_class(rest)

def route_statement(ns: List<&2, T.Node>, facade: String, +sc: Scope, entries: List<&2, Entry>, path: String, +line: U32, lines: List<&2, U32>) -> List<&2, Endpoint>:
  match ns:
    case Con{T.Leaf{L.Tok{5, "::", c}}, Con{T.Leaf{L.Tok{1, "get", g}}, Con{T.Grp{40, a, args}, Con{T.Leaf{L.Tok{5, ";", e}}, rest}}}}:
      L.sel(List<&2, Endpoint>, String.eq(resolve(facade, sc), "illuminate\\support\\facades\\route") && Bool.not(ignored(lines, line)),
        u => route_args(args, sc, entries, path, line), u => [])
    case _:
      []

def routes(fuel: Nat, ns: List<&2, T.Node>, +sc: Scope, +entries: List<&2, Entry>, +path: String, +lines: List<&2, U32>) -> ScanResult:
  match fuel ns:
    case _ Nil{}:
      ScanResult{[], [], False{}}
    case 0n _:
      ScanResult{[], [], True{}}
    case 1n+p Con{T.Leaf{L.Tok{1, "class", l}}, rest}:
      routes(p, after_class(rest), sc, entries, path, lines)
    case 1n+p Con{T.Leaf{L.Tok{1, "final", l}}, rest}:
      routes(p, rest, sc, entries, path, lines)
    case 1n+p Con{T.Leaf{L.Tok{1, "abstract", l}}, rest}:
      routes(p, rest, sc, entries, path, lines)
    case 1n+(+p) Con{T.Leaf{L.Tok{1, facade, +line}}, +rest}:
      sites = route_statement(rest, facade, sc, entries, path, line, lines)
      append_results(ScanResult{[], sites, False{}}, routes(p, skip_statement(rest), sc, entries, path, lines))
    case 1n+p +ns:
      routes(p, skip_statement(ns), sc, entries, path, lines)

def route_files(sources: List<&2, E.Src>, +entries: List<&2, Entry>) -> ScanResult:
  match sources:
    case Nil{}:
      ScanResult{[], [], False{}}
    case Con{E.Src{path, text}, rest}:
      +tokens = L.qualified(text)
      +nodes = T.tree(L.without_ignores(tokens))
      a b = routes(1n+List.length(&2, L.Tok, tokens), nodes, file_scope(nodes), entries, path, L.ignored_lines(tokens, 0)) route_files(rest, entries)
      append_results(a, b)

def resources(entries: List<&2, Entry>) -> List<&2, Resource>:
  match entries:
    case Nil{}:
      []
    case Con{Entry{key, ResourceClass{resource, True{}}}, rest}:
      Con{resource, resources(rest)}
    case Con{entry, rest}:
      resources(rest)

def source_le(a: E.Src, b: E.Src) -> Bool:
  match a b:
    case E.Src{ap, at} E.Src{bp, bt}:
      String.is_le(ap, bp)

def location_le(+ap: String, +al: U32, ad: String, +bp: String, +bl: U32, bd: String) -> Bool:
  L.sel(Bool, String.eq(ap, bp),
    u => L.sel(Bool, U32.is_eq(al, bl), u => String.is_le(ad, bd), u => U32.is_le(al, bl)),
    u => String.is_le(ap, bp))

def resource_le(a: Resource, b: Resource) -> Bool:
  match a b:
    case Resource{ak, ap, al, ar} Resource{bk, bp, bl, br}:
      location_le(ap, al, ak, bp, bl, bk)

def endpoint_le(a: Endpoint, b: Endpoint) -> Bool:
  match a b:
    case Endpoint{ap, al, ar, Resource{ak, arp, arl, arr}} Endpoint{bp, bl, br, Resource{bk, brp, brl, brr}}:
      location_le(ap, al, ar ++ "\n" ++ ak, bp, bl, br ++ "\n" ++ bk)

def finished(result: ScanResult, entries: List<&2, Entry>, inc: Bool) -> ScanResult:
  match result:
    case ScanResult{rs, es, i}:
      ScanResult{List.sort(~Resource, ~resource_le, resources(entries)), List.sort(~Endpoint, ~endpoint_le, es), inc || i}

def scanned(index: Index, sources: List<&2, E.Src>) -> ScanResult:
  match index:
    case Index{+entries, False{}, inc}:
      finished(route_files(sources, entries), entries, inc)
    case Index{entries, True{}, inc}:
      ScanResult{[], [], inc}

def relationship_detail(r: Relationships) -> String:
  match r:
    case Literal{line, names}:
      "literal declared relationships: [" ++ String.join(names, ", ") ++ "]"
    case Unknown{line, reason}:
      reason ++ "; relationships unknown"

def relationship_observation(r: Relationships, path: String) -> List<&2, E.Site>:
  match r:
    case Literal{+line, names}:
      [E.Observation{path, line, E.JsonApiRelationships{}, E.Possible{}, relationship_detail(Literal{line, names}) ++ "; model resolution unknown"}]
    case Unknown{0, reason}:
      []
    case Unknown{+line, reason}:
      [E.Observation{path, line, E.JsonApiRelationships{}, E.Unknown{}, relationship_detail(Unknown{line, reason}) ++ "; model resolution unknown"}]

def resource_observations(rs: List<&2, Resource>) -> List<&2, E.Site>:
  match rs:
    case Nil{}:
      []
    case Con{Resource{identity, +path, line, +r}, rest}:
      Con{E.Observation{path, line, E.JsonApiResource{}, E.Possible{}, "direct JsonApiResource subclass " ++ identity ++ "; " ++ relationship_detail(r) ++ "; model resolution unknown; runtime registration unknown; exploitability unknown"},
        List.append(&2, E.Site, relationship_observation(r, path), resource_observations(rest))}

def endpoint_observations(es: List<&2, Endpoint>) -> List<&2, E.Site>:
  match es:
    case Nil{}:
      []
    case Con{Endpoint{path, line, route, Resource{identity, rp, rl, r}}, rest}:
      Con{E.Observation{path, line, E.JsonApiEndpoint{}, E.Possible{}, "literal GET " ++ route ++ " returns " ++ identity ++ "; model resolution unknown; runtime registration unknown; exploitability unknown"}, endpoint_observations(rest)}

def evidence(result: ScanResult) -> E.Evidence:
  match result:
    case ScanResult{rs, es, inc}:
      E.Evidence{List.append(&2, E.Site, resource_observations(rs), endpoint_observations(es)), inc}

def scan(sources: List<&2, E.Src>) -> E.Evidence:
  +ordered = List.sort(~E.Src, ~source_le, sources)
  evidence(scanned(index_sources(ordered, Index{[], False{}, False{}}), ordered))
