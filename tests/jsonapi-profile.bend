import Base
import ../src/jsonapi.bend as P
import ../src/evidence.bend as E
import ../src/advisories.bend as A
import ../src/catalog.bend as C
import ../src/lex.bend as L

def resource(base: String, imports: String, body: String) -> String:
  "<?php\nnamespace App\\Http\\Resources;\nuse Illuminate\\Http\\Request;\n" ++ imports ++ "\nclass UserResource extends " ++ base ++ "\n{\n    public function toRelationships(Request $request): array\n    {\n        " ++ body ++ "\n    }\n}\n"

def standard() -> String:
  resource("JsonApiResource", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource;", "return ['comments'];")

def route() -> String:
  "<?php\nuse App\\Models\\User;\nuse App\\Http\\Resources\\UserResource;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/users/{user}', fn (User $user) => new UserResource($user));\n"

def rows(sites: List<&2, E.Site>) -> String:
  match sites:
    case Nil{}:
      ""
    case Con{E.Observation{path, line, E.JsonApiRelationships{}, status, detail}, rest}:
      path ++ ":" ++ U32.show(line) ++ "|jsonapi-relationships|" ++ E.status(status) ++ "|" ++ detail ++ "\n" ++ rows(rest)
    case Con{E.Observation{path, line, kind, status, detail}, rest}:
      path ++ ":" ++ U32.show(line) ++ "|" ++ E.kind(kind) ++ "|" ++ E.status(status) ++ "\n" ++ rows(rest)
    case Con{site, rest}:
      "unexpected Symfony site\n" ++ rows(rest)

def snapshot(result: E.Evidence) -> String:
  match result:
    case E.Evidence{sites, False{}}:
      rows(sites)
    case E.Evidence{sites, True{}}:
      "incomplete\n"

def scan(r: String, e: String) -> String:
  snapshot(P.scan([E.Src{"app.php", r}, E.Src{"route.php", e}]))

def declared() -> String:
  "app.php:5|jsonapi-resource|possible\napp.php:9|jsonapi-relationships|possible|literal declared relationships: [comments]; model resolution unknown\n"

def supported() -> Bool:
  String.eq(scan(standard(), route()), "app.php:5|jsonapi-resource|possible\napp.php:9|jsonapi-relationships|possible|literal declared relationships: [comments]; model resolution unknown\nroute.php:5|jsonapi-endpoint|possible\n") &&
    String.eq(scan(resource("ApiBase", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource as ApiBase;", "return ['Comments', 'posts',];"), "<?php use App\\Http\\Resources\\UserResource as ApiUser; use Illuminate\\Support\\Facades\\Route as Router; Router::get('/alias', function ($user) { return new ApiUser($user); });"), "app.php:5|jsonapi-resource|possible\napp.php:9|jsonapi-relationships|possible|literal declared relationships: [Comments, posts]; model resolution unknown\nroute.php:1|jsonapi-endpoint|possible\n") &&
    String.eq(scan(resource("\\Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource", "", "return [];"), "<?php \\Illuminate\\Support\\Facades\\Route::get('/fq', fn () => new \\App\\Http\\Resources\\UserResource());"), "app.php:5|jsonapi-resource|possible\napp.php:9|jsonapi-relationships|possible|literal declared relationships: []; model resolution unknown\nroute.php:1|jsonapi-endpoint|possible\n") &&
    String.eq(scan(standard(), "<?php namespace App\\Http\\Resources; use Illuminate\\Support\\Facades\\Route; Route::get('/local', fn () => new UserResource());"), declared() ++ "route.php:1|jsonapi-endpoint|possible\n") &&
    String.eq(snapshot(P.scan([E.Src{"one.php", standard() ++ "use Illuminate\\Support\\Facades\\Route; Route::get('/same', fn () => new UserResource());"}])), "one.php:5|jsonapi-resource|possible\none.php:9|jsonapi-relationships|possible|literal declared relationships: [comments]; model resolution unknown\none.php:12|jsonapi-endpoint|possible\n") &&
    String.eq(snapshot(P.scan([E.Src{"route.php", route()}, E.Src{"app.php", standard()}])), declared() ++ "route.php:5|jsonapi-endpoint|possible\n")

def rejected() -> Bool:
  String.eq(snapshot(P.scan([])), "") &&
    String.eq(scan("", ""), "") &&
    String.eq(scan(resource("JsonResource", "use Illuminate\\Http\\Resources\\Json\\JsonResource;", "return ['comments'];"), route()), "") &&
    String.eq(scan(resource("JsonApiResource", "", "return ['comments'];"), route()), "") &&
    String.eq(scan(standard(), "<?php namespace Other; use Illuminate\\Support\\Facades\\Route; Route::get('/wrong', fn () => new UserResource());"), declared()) &&
    String.eq(scan(standard(), "<?php use App\\Http\\Resources\\UserResource; Route::get('/implicit', fn () => new UserResource());"), declared()) &&
    String.eq(scan(standard(), "<?php use App\\Http\\Resources\\UserResource; use Illuminate\\Support\\Facades\\Route; Route::get('/extra', function () { log_event(); return new UserResource(); }); Route::get('/post', fn () => factory()); Route::post('/write', fn () => new UserResource());"), declared()) &&
    String.eq(scan(standard(), "<?php use App\\Http\\Resources\\UserResource; use Illuminate\\Support\\Facades\\Route; function hidden() { Route::get('/nested', fn () => new UserResource()); } $x = Route::get('/assigned', fn () => new UserResource());"), declared()) &&
    String.eq(scan("<?php /* " ++ standard() ++ " */", route()), "") &&
    String.eq(scan("<?php $sample = <<<'SAMPLE'\n" ++ standard() ++ "\nSAMPLE;\n", route()), "") &&
    String.eq(scan(standard() ++ "}", route()), "") &&
    String.eq(scan(standard() ++ "namespace Other;", route()), "") &&
    String.eq(scan(resource("JsonApiResource", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource; use Other\\Base as JsonApiResource;", "return ['comments'];"), route()), "") &&
    String.eq(scan(resource("JsonApiResource", "use Illuminate\\Http\\Resources\\JsonApi\\{JsonApiResource};", "return ['comments'];"), route()), "")

def dynamic() -> Bool:
  +expected = {"app.php:5|jsonapi-resource|possible\napp.php:9|jsonapi-relationships|unknown|dynamic relationships; relationships unknown; model resolution unknown\n" : String}
  String.eq(scan(resource("JsonApiResource", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource;", "return $this->relationships();"), route()), expected) &&
    String.eq(scan(resource("JsonApiResource", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource;", "return ['comments' => Other::class];"), route()), expected) &&
    String.eq(scan(resource("JsonApiResource", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource;", "return [...$names];"), route()), expected) &&
    String.eq(scan(resource("JsonApiResource", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource;", "return [\"$dynamic\"];"), route()), expected)

def suppression() -> Bool:
  String.eq(scan(resource("JsonApiResource // phpscan-ignore", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource;", "return ['comments'];"), route()), "") &&
    String.eq(scan(resource("JsonApiResource", "use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource;", "return ['comments']; // phpscan-ignore"), route()), "app.php:5|jsonapi-resource|possible\n") &&
    String.eq(scan(standard(), route() ++ "// phpscan-ignore\n"), declared() ++ "route.php:5|jsonapi-endpoint|possible\n") &&
    String.eq(scan(standard(), "<?php use App\\Http\\Resources\\UserResource; use Illuminate\\Support\\Facades\\Route;\n// phpscan-ignore\nRoute::get('/hidden', fn () => new UserResource());"), declared()) &&
    String.eq(scan("<?php namespace App\\Http\\Resources; use Illuminate\\Http\\Resources\\JsonApi\\JsonApiResource; class UserResource extends JsonApiResource {}", route()), "app.php:1|jsonapi-resource|possible\n")

def collisions() -> Bool:
  String.eq(snapshot(P.scan([E.Src{"app.php", standard()}, E.Src{"duplicate.php", "<?php namespace App\\Http\\Resources; class USERRESOURCE {}"}, E.Src{"route.php", route()}])), "") &&
    String.eq(snapshot(P.scan([E.Src{"app.php", standard()}, E.Src{"duplicate.php", "<?php namespace App\\Http\\Resources;\n// phpscan-ignore\nclass UserResource {}"}, E.Src{"route.php", route()}])), "") &&
    String.eq(snapshot(P.scan([E.Src{"duplicate.php", "<?php namespace App\\Http\\Resources; class UserResource {}"}, E.Src{"route.php", route()}, E.Src{"app.php", standard()}])), "") &&
    String.eq(scan(standard() ++ "function helper() {} class UserResource {}", route()), "") &&
    String.eq(scan(standard() ++ "if (configured()) { class UserResource {} }", route()), "")

def details(e: E.Evidence) -> Bool:
  match e:
    case E.Evidence{Con{E.Observation{"app.php", 5, E.JsonApiResource{}, E.Possible{}, resource}, Con{E.Observation{"app.php", 9, E.JsonApiRelationships{}, E.Possible{}, relationships}, Con{E.Observation{"route.php", 5, E.JsonApiEndpoint{}, E.Possible{}, endpoint}, Nil{}}}}, False{}}:
      String.eq(resource, "direct JsonApiResource subclass app\\http\\resources\\userresource; literal declared relationships: [comments]; model resolution unknown; runtime registration unknown; exploitability unknown") &&
        String.eq(relationships, "literal declared relationships: [comments]; model resolution unknown") &&
        String.eq(endpoint, "literal GET /users/{user} returns app\\http\\resources\\userresource; model resolution unknown; runtime registration unknown; exploitability unknown")
    case _:
      False{}

def filtered(+sites: List<&2, E.Site>) -> Bool:
  String.eq(rows(E.for_profile(sites, "laravel-jsonapi")), "app.php:5|jsonapi-resource|possible\napp.php:9|jsonapi-relationships|possible|literal declared relationships: [comments]; model resolution unknown\nroute.php:5|jsonapi-endpoint|possible\n") &&
    String.eq(rows(E.for_profile(sites, "laravel-token-guard")), "auth.php:2|token-guard|possible\nroute.php:3|guard-route|possible\ndb.php:4|database-selection|unknown\n") &&
    String.eq(rows(E.for_profile(sites, "symfony-path-prefix")), "unexpected Symfony site\n") &&
    String.eq(rows(E.for_profile(sites, "none")), "")

def enriched(fs: List<&2, A.Finding>) -> String:
  match fs:
    case Nil{}:
      ""
    case Con{A.Match{n, C.Advisory{id, cve, profile, ranges, sources, functions}, r, v, g, sites}, rest}:
      id ++ "\n" ++ rows(sites) ++ enriched(rest)
    case Con{A.Unknown{n, reason}, rest}:
      reason ++ "\n" ++ enriched(rest)

def integration(+e: E.Evidence, +sites: List<&2, E.Site>) -> Bool:
  +matches = A.scan("{\"packages\":[{\"name\":\"laravel/framework\",\"version\":\"12.67.0\"}]}")
  filtered(sites) &&
    String.eq(enriched(A.enrich(matches, E.Evidence{sites, False{}})), "GHSA-5wcm-3v2w-8362\napp.php:5|jsonapi-resource|possible\napp.php:9|jsonapi-relationships|possible|literal declared relationships: [comments]; model resolution unknown\nroute.php:5|jsonapi-endpoint|possible\nGHSA-f9x3-7vq9-cph6\nauth.php:2|token-guard|possible\nroute.php:3|guard-route|possible\ndb.php:4|database-selection|unknown\n") &&
    String.eq(enriched(A.enrich(matches, E.Evidence{sites, True{}})), "GHSA-5wcm-3v2w-8362\nsource evidence analysis exhausted its budget\nGHSA-f9x3-7vq9-cph6\nsource evidence analysis exhausted its budget\n") &&
    A.needs_source(matches) && A.needs_profile(matches, "laravel-jsonapi") && A.needs_profile(matches, "laravel-token-guard") &&
    Bool.not(A.needs_profile(matches, "symfony-path-prefix")) &&
    E.possible([E.Observation{"resource.php", 5, E.JsonApiResource{}, E.Possible{}, "resource"}]) &&
    Bool.not(E.possible([E.Observation{"resource.php", 9, E.JsonApiRelationships{}, E.Unknown{}, "dynamic"}])) &&
    details(e)

def combined(e: E.Evidence) -> Bool:
  match e:
    case E.Evidence{+sites, inc}:
      integration(E.Evidence{sites, inc}, List.append(&2, E.Site, sites, [E.Observation{"auth.php", 2, E.TokenGuard{}, E.Possible{}, "guard"}, E.Observation{"route.php", 3, E.GuardRoute{}, E.Possible{}, "route"}, E.Observation{"db.php", 4, E.DatabaseSelection{}, E.Unknown{}, "database"}, E.Site{"symfony.php", 2, 3, 4, "request", "/admin"}]))

def main() -> U32:
  L.sel(U32, supported(),
    u => L.sel(U32, rejected(),
      u => L.sel(U32, dynamic(),
        u => L.sel(U32, suppression(),
          u => L.sel(U32, collisions(),
            u => L.sel(U32, combined(P.scan([E.Src{"app.php", standard()}, E.Src{"route.php", route()}])), u => 0, u => 6), u => 5), u => 4), u => 3), u => 2), u => 1)
