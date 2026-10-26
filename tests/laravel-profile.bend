import Base
import ../src/laravel.bend as P
import ../src/evidence.bend as E
import ../src/advisories.bend as A
import ../src/lex.bend as L

def auth(+driver: String, +provider: String, +hash: String) -> String:
  "<?php\nreturn ['guards' => ['api' => [\n'driver' => " ++ driver ++ ", 'provider' => 'users', 'hash' => " ++ hash ++
  "]], 'providers' => ['users' => ['driver' => " ++ provider ++ ", 'model' => App\\Models\\User::class]]];\n"

def auth.key(key: String) -> String:
  "<?php\nreturn ['guards' => [" ++ key ++ " => ['driver' => 'token', 'provider' => 'users', 'hash' => false]], " ++
    "'providers' => ['users' => ['driver' => 'eloquent']]];"

def route() -> String:
  "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/account', fn () => ['id' => auth()->id()]);\n"

def sources(a: String, db: String, r: String) -> List<&2, E.Src>:
  [E.Src{"project/config/auth.php", a}, E.Src{"project/config/database.php", "<?php\nreturn ['default' => " ++ db ++ "];\n"}, E.Src{"project/routes/api.php", r}]

def profile(a: String, db: String, r: String) -> E.Evidence:
  P.analyze("project", sources(a, db, r))

def observed(e: E.Evidence, +status: String) -> Bool:
  match e:
    case E.Evidence{Con{E.Observation{"project/config/auth.php", 3, E.TokenGuard{}, E.Possible{}, guard},
      Con{E.Observation{"project/routes/api.php", 3, E.GuardRoute{}, E.Possible{}, route},
      Con{E.Observation{"project/config/database.php", 2, E.DatabaseSelection{}, s, detail}, Nil{}}}}, False{}}:
      String.eq(guard, "literal token guard api, hash false, eloquent provider users") &&
        String.eq(route, "literal auth:api middleware on Illuminate\\Support\\Facades\\Route::middleware(...)->get(...)") &&
        String.eq(E.status(s), status)
    case _:
      False{}

def empty(e: E.Evidence) -> Bool:
  match e:
    case E.Evidence{Nil{}, False{}}:
      True{}
    case _:
      False{}

def no_database(e: E.Evidence) -> Bool:
  match e:
    case E.Evidence{Con{E.Observation{p, 3, E.TokenGuard{}, E.Possible{}, d},
      Con{E.Observation{q, 3, E.GuardRoute{}, E.Possible{}, e}, Nil{}}}, False{}}:
      True{}
    case _:
      False{}

def matched(fs: List<&2, A.Finding>, expected: U32) -> Bool:
  U32.is_eq(U32.from_nat(List.length(&2, A.Finding, fs)), expected)

def version(v: String, n: U32) -> Bool:
  matched(A.scan("{\"packages\":[{\"name\":\"laravel/framework\",\"version\":\"" ++ v ++ "\"}]}"), n)

def isolated(fs: List<&2, A.Finding>) -> Bool:
  match fs:
    case Con{A.Match{n, a, r, v, g, Nil{}}, Nil{}}:
      True{}
    case _:
      False{}

def main() -> U32:
  +a = auth("'token'", "'eloquent'", "false")
  +r = route()
  ok = observed(profile(a, "'mysql'", r), "possible") &&
    observed(profile(a, "'mariadb'", r), "possible") &&
    observed(profile(auth("\"token\"", "\"eloquent\"", "false"), "\"mysql\"", r), "possible") &&
    observed(profile(a, "\"my\\sql\"", r), "unknown") &&
    observed(profile(a, "<<<DB\nmysql\nDB\n", r), "unknown") &&
    observed(profile(a, "<<<'DB'\nmysql\nDB\n", r), "unknown") &&
    empty(profile(auth.key("<<<KEY\napi\nKEY\n"), "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api\n')->get('/account', fn () => 1);")) &&
    empty(profile(auth.key("<<<'KEY'\napi\nKEY\n"), "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api\n')->get('/account', fn () => 1);")) &&
    empty(profile(auth("\"t\\oken\"", "'eloquent'", "false"), "'mysql'", r)) &&
    empty(profile(auth("'token'", "\"elo\\quent\"", "false"), "'mysql'", r)) &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware(\"auth:api\")->get(\"/account\", fn () => 1);"), "possible") &&
    empty(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware(\"auth:a\\pi\")->get('/account', fn () => 1);")) &&
    observed(profile(a, "env('DB_CONNECTION')", r), "unknown") &&
    observed(profile(a, "'pgsql'", r), "unknown") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route as R;\nR::middleware('auth:api')->get('/x', fn () => 1);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\n\n\\Illuminate\\Support\\Facades\\Route::middleware('auth:api')->get('/x', fn () => 1);"), "possible") &&
    empty(profile(a, "'mysql'", "<?php use Other\\Route; Route::middleware('auth:api')->get('/x', fn () => 1);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:API')->get('/x', fn () => 1);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; logger(\"Route::middleware('auth:api')->get(...)\");")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; if ($enabled) { Route::middleware('auth:api')->get('/x', fn () => 1); }")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route;\n// phpscan-ignore\nRoute::middleware('auth:api')->get('/x', fn () => 1);")) &&
    empty(profile(auth("'sanctum'", "'eloquent'", "false"), "'mysql'", r)) &&
    empty(profile(auth("'token'", "'custom'", "false"), "'mysql'", r)) &&
    empty(profile(auth("env('AUTH_DRIVER')", "'eloquent'", "false"), "'mysql'", r)) &&
    empty(profile(auth("'token'", "'eloquent'", "true"), "'mysql'", r)) &&
    empty(profile(auth("'token', 'driver' => 'token'", "'eloquent'", "false"), "'mysql'", r)) &&
    empty(profile("<?php return ['guards' => [...$guards], 'providers' => []];", "'mysql'", r)) &&
    empty(profile("<?php logger(['guards' => ['api' => ['driver' => 'token']]]);", "'mysql'", r)) &&
    empty(profile("<?php return ['guards' => [", "'mysql'", r)) &&
    empty(P.analyze("other", sources(a, "'mysql'", r))) &&
    no_database(P.analyze("project", [E.Src{"project/config/auth.php", a}, E.Src{"project/routes/api.php", r}])) &&
    version("0.0.1", 1) && version("12.67.0", 1) && version("12.68.0", 0) &&
    version("13.0.0", 1) && version("13.28.0", 1) && version("13.29.0", 0) &&
    isolated(A.enrich(A.scan("{\"packages\":[{\"name\":\"symfony/http-foundation\",\"version\":\"7.3.6\"}]}"), profile(a, "'mysql'", r)))
  L.sel(U32, ok, u => 0, u => 1)
