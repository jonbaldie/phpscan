import Base
import ../src/evidence.bend as E
import ../src/jsonapi.bend as J
import ../src/laravel.bend as G
import ../src/symfony.bend as S
import ../src/advisories.bend as A
import ../src/lex.bend as L
import ../src/tree.bend as T

def rows(xs: List<&2, E.Site>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{E.Observation{path, line, kind, status, detail}, rest}:
      path ++ ":" ++ U32.show(line) ++ "|" ++ E.kind(kind) ++ "|" ++ E.status(status) ++ "|" ++ detail ++ "\n" ++ rows(rest)
    case Con{E.Site{path, line, check, auth, typ, prefix}, rest}:
      path ++ ":" ++ U32.show(line) ++ "|" ++ typ ++ "|" ++ prefix ++ "\n" ++ rows(rest)

def snapshot(e: E.Evidence) -> String:
  match e:
    case E.Complete{sites}:
      "complete\n" ++ rows(sites)
    case E.Incomplete{sites}:
      "incomplete\n" ++ rows(sites)

def aggregation() -> Bool:
  +a = {[E.Observation{"a", 1, E.JsonApiResource{}, E.Possible{}, "a"}] : List<&2, E.Site>}
  +b = {[E.Observation{"b", 2, E.JsonApiResource{}, E.Unknown{}, "b"}] : List<&2, E.Site>}
  +both = {"a:1|jsonapi-resource|possible|a\nb:2|jsonapi-resource|unknown|b\n" : String}
  String.eq(snapshot(E.merge(E.Complete{a}, E.Complete{b})), "complete\n" ++ both) &&
    String.eq(snapshot(E.merge(E.Incomplete{a}, E.Complete{b})), "incomplete\n" ++ both) &&
    String.eq(snapshot(E.merge(E.Complete{a}, E.Incomplete{b})), "incomplete\n" ++ both) &&
    String.eq(snapshot(E.merge(E.Incomplete{a}, E.Incomplete{b})), "incomplete\n" ++ both) &&
    String.eq(snapshot(E.suppress(E.Incomplete{a}, [1])), "incomplete\n") &&
    String.eq(snapshot(E.suppress(E.Complete{b}, [2])), "complete\n")

def budgets() -> Bool:
  +node = {[T.Leaf{L.Tok{1, "noop", 1}}] : List<&2, T.Node>}
  String.eq(snapshot(J.evidence(J.routes(0n, [], J.Invalid{}, [], "a", []))), "complete\n") &&
    String.eq(snapshot(J.evidence(J.routes(0n, node, J.Invalid{}, [], "a", []))), "incomplete\n") &&
    String.eq(snapshot(J.evidence(J.scanned(J.declarations(0n, [], J.Invalid{}, "a", [], 1n, []), []))), "complete\n") &&
    String.eq(snapshot(J.evidence(J.scanned(J.declarations(0n, node, J.Invalid{}, "a", [], 1n, []), []))), "incomplete\n") &&
    String.eq(snapshot(J.evidence(J.scanned(J.index_flags(J.Index{[], J.Uncertain{}, E.Finished{}}, J.Certain{}, E.Exhausted{}), []))), "incomplete\n") &&
    String.eq(snapshot(S.functions(0n, [], [], "a")), "incomplete\n") &&
    String.eq(snapshot(S.functions(1n, [], [], "a")), "complete\n") &&
    String.eq(snapshot(S.functions(3n, [T.Grp{40, 1, node}, T.Leaf{L.Tok{1, "noop", 1}}], [], "a")), "complete\n")

def relation_source(methods: String) -> String:
  "<?php use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource; class Item extends JsonApiResource { " ++ methods ++ " }"

def relationships() -> Bool:
  +prefix = {"complete\na:1|jsonapi-resource|possible|direct JsonApiResource subclass item; " : String}
  +suffix = {"; relationships unknown; model resolution unknown; runtime registration unknown; exploitability unknown\n" : String}
  String.eq(snapshot(J.scan([E.Src{"a", relation_source("")}])), prefix ++ "relationship declaration unavailable" ++ suffix) &&
    String.eq(snapshot(J.scan([E.Src{"a", relation_source("function toRelationships() { return []; } function toRelationships() { return ['x']; } function toRelationships() { return []; }")}])), prefix ++ "duplicate relationship methods" ++ suffix) &&
    String.eq(snapshot(J.scan([E.Src{"a", relation_source("function toRelationships() { return []; }") ++ " use Other\\Thing;"}])), "complete\n")

def route_rows(rs: List<&2, G.Route>) -> String:
  match rs:
    case Nil{}:
      ""
    case Con{G.Route{guard, path, line}, rest}:
      guard ++ ":" ++ U32.show(line) ++ "\n" ++ route_rows(rest)

def laravel() -> Bool:
  +before = {"<?php\nRoute::middleware('auth:before')->get('/', fn () => [1, 2]);\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:first')->get('/', function () { noop(); });\nRoute::middleware('auth:second')->get('/', fn () => [],);\n" : String}
  String.eq(route_rows(G.route_file("a", before)), "first:4\nsecond:5\n") &&
    String.eq(route_rows(G.route_file("a", before ++ "use Other\\Route;")), "") &&
    String.eq(route_rows(G.route_file("a", before ++ "unfinished()")), "") &&
    String.eq(route_rows(G.route_file("a", before ++ ";;")), "first:4\nsecond:5\n")

def symfony_source(params: String, suffix: String) -> String:
  "<?php namespace App; function handle(" ++ params ++ ") { if (str_starts_with($request->getPathInfo(), '/admin')) { abort_unless(auth()->check(), 403); } } " ++ suffix

def symfony() -> Bool:
  +im = {"use Illuminate\\Http\\Request as Request;" : String}
  +site = {"complete\na:1|Illuminate\\Http\\Request|/admin\n" : String}
  String.eq(snapshot(S.scan("a", symfony_source("Request $request", im))), site) &&
    String.eq(snapshot(S.scan("a", symfony_source("Other|Request $request", im))), "complete\n") &&
    String.eq(snapshot(S.scan("a", symfony_source("Other|Request $ignored, Request $request", im))), site) &&
    String.eq(snapshot(S.scan("a", symfony_source("Request $request", im ++ " namespace Other;"))), "complete\n") &&
    String.eq(snapshot(S.scan("a", symfony_source("Request $request", im ++ " use Other\\Request;"))), "complete\n")

def advisory_rows(fs: List<&2, A.Finding>) -> String:
  match fs:
    case Nil{}:
      ""
    case Con{+f, rest}:
      A.rule(f) ++ "\n" ++ advisory_rows(rest)

def unsupported_advisory() -> Bool:
  String.eq(advisory_rows(A.enrich(A.scan("{\"packages\":[{\"name\":\"livewire/livewire\",\"version\":\"3.6.3\"}]}"), E.Incomplete{[]})), "GHSA-29cq-5w36-x7w3\n")

def main() -> U32:
  L.sel(U32, aggregation(),
    u => L.sel(U32, budgets(),
      u => L.sel(U32, relationships(),
        u => L.sel(U32, laravel(),
          u => L.sel(U32, symfony(), u => L.sel(U32, unsupported_advisory(), u => 0, u => 6), u => 5), u => 4), u => 3), u => 2), u => 1)
