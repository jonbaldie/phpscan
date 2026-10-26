import Base
import ./lex.bend as L
import ./tree.bend as T
import ./evidence.bend as E

type Field is Data:
  Field{key: String, line: U32, value: List<&2, T.Node>}

type ArrayState is Data:
  ArrayKey{}
  ArrayValue{key: String, line: U32, reversed: List<&2, T.Node>}

type Config is Data:
  Config{path: String, fields: List<&2, Field>, ignores: List<&2, U32>}

type Guard is Data:
  Guard{name: String, provider: String, path: String, line: U32}

type Route is Data:
  Route{guard: String, path: String, line: U32}

type LinkedGuardRoute is Data:
  LinkedGuardRoute{guard: Guard, route: Route}

type Alias is Data:
  Alias{name: String, target: String}

def has_key(fs: List<&2, Field>, +key: String) -> Bool:
  match fs:
    case Nil{}:
      False{}
    case Con{Field{k, l, v}, rest}:
      String.eq(k, key) || has_key(rest, key)

def field(fs: List<&2, Field>, +key: String) -> Maybe<&2, Field>:
  match fs:
    case Nil{}:
      None{}
    case Con{+f, rest}:
      Field{k, l, v} = f
      L.sel(Maybe<&2, Field>, String.eq(k, key), u => Some{f}, u => field(rest, key))

def fields(ns: List<&2, T.Node>, +acc: List<&2, Field>, state: ArrayState) -> Maybe<&2, List<&2, Field>>:
  match ns state:
    case Nil{} ArrayKey{}:
      Some{List.reverse(&2, Field, acc)}
    case Nil{} ArrayValue{k, l, Nil{}}:
      None{}
    case Nil{} ArrayValue{k, l, vs}:
      Some{List.reverse(&2, Field, Con{Field{k, l, List.reverse(&2, T.Node, vs)}, acc})}
    case Con{T.Leaf{L.Tok{2, +k, l}}, Con{T.Leaf{L.Tok{5, "=>", a}}, rest}} ArrayKey{}:
      L.sel(Maybe<&2, List<&2, Field>>, has_key(acc, k), u => None{}, u => fields(rest, acc, ArrayValue{k, l, []}))
    case Con{T.Leaf{L.Tok{5, ",", c}}, rest} ArrayValue{k, l, Nil{}}:
      None{}
    case Con{T.Leaf{L.Tok{5, ",", c}}, rest} ArrayValue{k, l, vs}:
      fields(rest, Con{Field{k, l, List.reverse(&2, T.Node, vs)}, acc}, ArrayKey{})
    case Con{n, rest} ArrayValue{k, l, vs}:
      fields(rest, acc, ArrayValue{k, l, Con{n, vs}})
    case _ _:
      None{}

def array(ns: List<&2, T.Node>) -> Maybe<&2, List<&2, Field>>:
  match ns:
    case Con{T.Grp{91, l, kids}, Nil{}}:
      fields(kids, [], ArrayKey{})
    case _:
      None{}

def field_array(f: Field) -> Maybe<&2, List<&2, Field>>:
  match f:
    case Field{k, l, v}:
      array(v)

def literal(f: Field) -> Maybe<&2, String>:
  match f:
    case Field{k, l, Con{T.Leaf{L.Tok{2, s, n}}, Nil{}}}:
      Some{s}
    case _:
      None{}

def is_false(f: Field) -> Bool:
  match f:
    case Field{k, l, Con{T.Leaf{L.Tok{1, "false", n}}, Nil{}}}:
      True{}
    case _:
      False{}

def field_line(f: Field) -> U32:
  match f:
    case Field{k, l, v}:
      l

def returned(ns: List<&2, T.Node>) -> Maybe<&2, List<&2, Field>>:
  match ns:
    case Con{T.Leaf{L.Tok{1, "return", r}}, Con{T.Grp{91, l, kids}, Con{T.Leaf{L.Tok{5, ";", s}}, Nil{}}}}:
      fields(kids, [], ArrayKey{})
    case _:
      None{}

def parse_config(+path: String, +tokens: List<&2, L.Tok>) -> Maybe<&2, Config>:
  do Maybe<&2, Config>:
    fs : List<&2, Field> <- L.sel(Maybe<&2, List<&2, Field>>, T.balanced(tokens, []),
      u => returned(T.tree(L.without_ignores(tokens))), u => None{})
    return Config{path, fs, L.ignored_lines(tokens, 0)}

def config(xs: List<&2, E.Src>, +path: String) -> Maybe<&2, Config>:
  match xs:
    case Nil{}:
      None{}
    case Con{E.Src{+p, t}, rest}:
      L.sel(Maybe<&2, Config>, String.eq(p, path), u => parse_config(p, L.qualified(t)), u => config(rest, path))

def valid_entries(fs: List<&2, Field>) -> Bool:
  match fs:
    case Nil{}:
      True{}
    case Con{f, rest}:
      Maybe.is_some(&2, List<&2, Field>, field_array(f)) && valid_entries(rest)

def candidate(f: Field, +providers: List<&2, Field>, +path: String, +ignores: List<&2, U32>) -> Maybe<&2, Guard>:
  match f:
    case Field{+name, l, v}:
      do Maybe<&2, Guard>:
        +fs : List<&2, Field> <- array(v)
        +driver : Field <- field(fs, "driver")
        d : String <- literal(driver)
        +provider : Field <- field(fs, "provider")
        +p : String <- literal(provider)
        +hash : Field <- field(fs, "hash")
        pf : Field <- field(providers, p)
        ps : List<&2, Field> <- field_array(pf)
        +pd : Field <- field(ps, "driver")
        typ : String <- literal(pd)
        L.sel(Maybe<&2, Guard>, String.eq(d, "token") && is_false(hash) && String.eq(typ, "eloquent") &&
          Bool.not(E.ignored(ignores, field_line(driver)) || E.ignored(ignores, field_line(provider)) ||
            E.ignored(ignores, field_line(hash)) || E.ignored(ignores, field_line(pd))),
          u => Some{Guard{name, p, path, field_line(driver)}}, u => None{})

def add_candidate(g: Maybe<&2, Guard>, rest: List<&2, Guard>) -> List<&2, Guard>:
  match g:
    case None{}:
      rest
    case Some{g}:
      Con{g, rest}

def candidates(fs: List<&2, Field>, +providers: List<&2, Field>, +path: String, +ignores: List<&2, U32>) -> List<&2, Guard>:
  match fs:
    case Nil{}:
      []
    case Con{f, rest}:
      add_candidate(candidate(f, providers, path, ignores), candidates(rest, providers, path, ignores))

def guards(c: Maybe<&2, Config>) -> List<&2, Guard>:
  match c:
    case None{}:
      []
    case Some{Config{path, +fs, ignores}}:
      parsed = do Maybe<&2, List<&2, Guard>>:
        g : Field <- field(fs, "guards")
        p : Field <- field(fs, "providers")
        +gs : List<&2, Field> <- field_array(g)
        +ps : List<&2, Field> <- field_array(p)
        return L.sel(List<&2, Guard>, valid_entries(gs) && valid_entries(ps), u => candidates(gs, ps, path, ignores), u => [])
      Maybe.default(&2, List<&2, Guard>, parsed, [])

def statements(ns: List<&2, T.Node>, current: List<&2, T.Node>, acc: List<&2, List<&2, T.Node>>) -> Maybe<&2, List<&2, List<&2, T.Node>>>:
  match ns current:
    case Nil{} Nil{}:
      Some{List.reverse(&2, List<&2, T.Node>, acc)}
    case Nil{} _:
      None{}
    case Con{T.Leaf{L.Tok{5, ";", l}}, rest} cur:
      statements(rest, [], Con{List.reverse(&2, T.Node, cur), acc})
    case Con{n, rest} cur:
      statements(rest, Con{n, cur}, acc)

def has_alias(xs: List<&2, Alias>, +name: String) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{Alias{n, t}, rest}:
      String.eq(n, name) || has_alias(rest, name)

def aliases(ss: List<&2, List<&2, T.Node>>, +acc: List<&2, Alias>) -> Maybe<&2, List<&2, Alias>>:
  match ss:
    case Nil{}:
      Some{acc}
    case Con{Con{T.Leaf{L.Tok{1, "use", u}}, Con{T.Leaf{L.Tok{1, +target, t}}, Nil{}}}, rest}:
      +name = L.strip_ns(target)
      L.sel(Maybe<&2, List<&2, Alias>>, has_alias(acc, name), v => None{}, v => aliases(rest, Con{Alias{name, target}, acc}))
    case Con{Con{T.Leaf{L.Tok{1, "use", u}}, Con{T.Leaf{L.Tok{1, target, t}}, Con{T.Leaf{L.Tok{1, "as", a}}, Con{T.Leaf{L.Tok{1, +name, n}}, Nil{}}}}}, rest}:
      L.sel(Maybe<&2, List<&2, Alias>>, has_alias(acc, name), v => None{}, v => aliases(rest, Con{Alias{name, target}, acc}))
    case Con{Con{T.Leaf{L.Tok{1, "use", l}}, ns}, rest}:
      None{}
    case Con{Con{T.Leaf{L.Tok{1, "namespace", l}}, ns}, rest}:
      None{}
    case Con{ns, rest}:
      aliases(rest, acc)

def facade_target(+s: String) -> Bool:
  String.eq(s, "illuminate\\support\\facades\\route") || String.eq(s, "\\illuminate\\support\\facades\\route")

def facade(xs: List<&2, Alias>, +name: String) -> Bool:
  match xs:
    case Nil{}:
      String.eq(name, "\\illuminate\\support\\facades\\route")
    case Con{Alias{n, t}, rest}:
      L.sel(Bool, String.eq(n, name), u => facade_target(t), u => facade(rest, name))

def get_args(ns: List<&2, T.Node>) -> Bool:
  match ns:
    case Con{T.Leaf{L.Tok{2, uri, l}}, Con{T.Leaf{L.Tok{5, ",", c}}, Con{action, rest}}}:
      True{}
    case _:
      False{}

def route(ns: List<&2, T.Node>, im: List<&2, Alias>, path: String, ignores: List<&2, U32>) -> List<&2, Route>:
  match ns:
    case Con{T.Leaf{L.Tok{1, cls, +l}}, Con{T.Leaf{L.Tok{5, "::", a}}, Con{T.Leaf{L.Tok{1, "middleware", m}}, Con{T.Grp{40, p, Con{T.Leaf{L.Tok{2, +auth, s}}, Nil{}}}, Con{T.Leaf{L.Tok{5, "->", o}}, Con{T.Leaf{L.Tok{1, "get", g}}, Con{T.Grp{40, q, args}, Nil{}}}}}}}}:
      L.sel(List<&2, Route>, facade(im, cls) && String.starts_with(auth, "auth:") &&
        U32.is_lt(5, U32.from_nat(String.length(auth))) && get_args(args) && Bool.not(E.ignored(ignores, l)),
        u => [Route{String.drop(auth, 5n), path, l}], u => [])
    case _:
      []

def routes(ss: List<&2, List<&2, T.Node>>, +im: List<&2, Alias>, +path: String, +ignores: List<&2, U32>) -> List<&2, Route>:
  match ss:
    case Nil{}:
      []
    case Con{ns, rest}:
      List.append(&2, Route, route(ns, im, path, ignores), routes(rest, im, path, ignores))

def route_file(path: String, +ts: List<&2, L.Tok>) -> List<&2, Route>:
  parsed = do Maybe<&2, List<&2, Route>>:
    +ss : List<&2, List<&2, T.Node>> <- L.sel(Maybe<&2, List<&2, List<&2, T.Node>>>, T.balanced(ts, []),
      u => statements(T.tree(L.without_ignores(ts)), [], []), u => None{})
    im : List<&2, Alias> <- aliases(ss, [])
    return routes(ss, im, path, L.ignored_lines(ts, 0))
  Maybe.default(&2, List<&2, Route>, parsed, [])

def join(+root: String, +relative: String) -> String:
  L.sel(String, String.ends_with(root, "/"), u => root ++ relative, u => root ++ "/" ++ relative)

def route_sources(xs: List<&2, E.Src>, +prefix: String) -> List<&2, Route>:
  match xs:
    case Nil{}:
      []
    case Con{E.Src{+path, text}, rest}:
      +relative = String.drop(path, String.length(prefix))
      here = L.sel(List<&2, Route>, String.starts_with(path, prefix) && String.ends_with(relative, ".php") &&
        Bool.not(String.contains(relative, "/")), u => route_file(path, L.qualified(text)), u => [])
      List.append(&2, Route, here, route_sources(rest, prefix))

def link_route(+g: Guard, +r: Route) -> List<&2, LinkedGuardRoute>:
  match g r:
    case Guard{name, provider, path, line} Route{other, p, l}:
      L.sel(List<&2, LinkedGuardRoute>, String.eq(name, other), u => [LinkedGuardRoute{g, r}], u => [])

def link_routes(+guard: Guard, rs: List<&2, Route>) -> List<&2, LinkedGuardRoute>:
  match rs:
    case Nil{}:
      []
    case Con{r, rest}:
      List.append(&2, LinkedGuardRoute, link_route(guard, r), link_routes(guard, rest))

def route_sites(links: List<&2, LinkedGuardRoute>) -> List<&2, E.Site>:
  match links:
    case Nil{}:
      []
    case Con{LinkedGuardRoute{g, Route{name, path, line}}, rest}:
      Con{E.Observation{path, line, E.GuardRoute{}, E.Possible{}, "literal auth:" ++ name ++ " middleware on Illuminate\\Support\\Facades\\Route::middleware(...)->get(...)"}, route_sites(rest)}

def linked_sites(links: List<&2, LinkedGuardRoute>) -> List<&2, E.Site>:
  match links:
    case Nil{}:
      []
    case Con{LinkedGuardRoute{Guard{+name, +provider, +path, +line}, r}, rest}:
      Con{E.Observation{path, line, E.TokenGuard{}, E.Possible{}, "literal token guard " ++ name ++ ", hash false, eloquent provider " ++ provider},
        route_sites(Con{LinkedGuardRoute{Guard{name, provider, path, line}, r}, rest})}

def guard_sites(gs: List<&2, Guard>, +rs: List<&2, Route>) -> List<&2, E.Site>:
  match gs:
    case Nil{}:
      []
    case Con{g, rest}:
      List.append(&2, E.Site, linked_sites(link_routes(g, rs)), guard_sites(rest, rs))

def database_literal(s: Maybe<&2, String>, path: String, line: U32) -> E.Site:
  match s:
    case None{}:
      E.Observation{path, line, E.DatabaseSelection{}, E.Unknown{}, "database default is dynamic or unsupported; connection and runtime database unknown"}
    case Some{+s}:
      E.Observation{path, line, E.DatabaseSelection{},
        L.sel(E.ObservationStatus, String.eq(s, "mysql") || String.eq(s, "mariadb"), u => E.Possible{}, u => E.Unknown{}),
        "literal database default " ++ s ++ "; runtime database and provider connection unknown"}

def database_field(f: Maybe<&2, Field>, path: String, ignores: List<&2, U32>) -> List<&2, E.Site>:
  match f:
    case None{}:
      []
    case Some{+f}:
      E.visible([database_literal(literal(f), path, field_line(f))], ignores)

def database(c: Maybe<&2, Config>) -> List<&2, E.Site>:
  match c:
    case None{}:
      []
    case Some{Config{path, fs, ignores}}:
      database_field(field(fs, "default"), path, ignores)

def analyze(+root: String, +sources: List<&2, E.Src>) -> E.Evidence:
  +sites = guard_sites(guards(config(sources, join(root, "config/auth.php"))), route_sources(sources, join(root, "routes/")))
  E.Evidence{L.sel(List<&2, E.Site>, List.is_empty(&2, E.Site, sites), u => [],
    u => List.append(&2, E.Site, sites, database(config(sources, join(root, "config/database.php"))))), False{}}
