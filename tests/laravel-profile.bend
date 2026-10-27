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

def argument_tokens(unpacked: List<&2, L.Tok>, named: List<&2, L.Tok>) -> Bool:
  match unpacked named:
    case Con{L.Tok{5, "...", 1}, Con{L.Tok{0, "actions", 1}, Nil{}}}
      Con{L.Tok{1, "action", 1}, Con{L.Tok{5, ":", 1}, Con{L.Tok{0, "handler", 1}, Nil{}}}}:
      True{}
    case _ _:
      False{}

def context_unknown(+a: String, opening: String, ending: String) -> Bool:
  empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; " ++ opening ++
    " $unused = 1; Route::middleware('auth:api')->get('/x', fn () => 1); " ++ ending ++ ";"))

def route_contexts(+a: String) -> Bool:
  context_unknown(a, "if (false):", "endif") &&
    context_unknown(a, "while (false):", "endwhile") &&
    context_unknown(a, "for (; false;):", "endfor") &&
    context_unknown(a, "foreach ([] as $item):", "endforeach") &&
    context_unknown(a, "switch (1): case 1:", "endswitch") &&
    context_unknown(a, "declare(ticks=1):", "enddeclare") &&
    context_unknown(a, "IF (false):", "ENDIF") &&
    context_unknown(a, "WHILE (false):", "ENDWHILE") &&
    context_unknown(a, "FOR (; false;):", "ENDFOR") &&
    context_unknown(a, "FOREACH ([] as $item):", "ENDFOREACH") &&
    context_unknown(a, "SWITCH (1): case 1:", "ENDSWITCH") &&
    context_unknown(a, "DECLARE(ticks=1):", "ENDDECLARE") &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; __halt_compiler(); Route::middleware('auth:api')->get('/x', fn () => 1);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; __HALT_COMPILER(); Route::middleware('auth:api')->get('/x', fn () => 1);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; __HaLt_CoMpIlEr(); Route::middleware('auth:api')->get('/x', fn () => 1);")) &&
    empty(profile(a, "'mysql'", route() ++ "__halt_compiler(); raw data")) &&
    empty(profile(a, "'mysql'", route() ++ "if (false): $unused = 1; endif;")) &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route; $unused = false;\nRoute::middleware('auth:api')->get('/x', fn () => 1);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route; $text = 'endif endwhile endfor endforeach endswitch enddeclare __halt_compiler';\nRoute::middleware('auth:api')->get('/x', fn () => 1);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route; $text = \"ENDIF ENDWHILE ENDFOR ENDFOREACH ENDSWITCH ENDDECLARE __HALT_COMPILER\";\nRoute::middleware('auth:api')->get('/x', fn () => 1);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route; /* endif endwhile endfor endforeach endswitch enddeclare __halt_compiler */ // ENDIF __HALT_COMPILER\nRoute::middleware('auth:api')->get('/x', fn () => 1);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/x', function () { if (false): endif; while (false): endwhile; for (; false;): endfor; foreach ([] as $item): endforeach; switch (1): case 1: break; endswitch; declare(ticks=1): enddeclare; return ['__halt_compiler', 'ENDIF']; });"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/x', $handler->endif()->endwhile()->endfor()->endforeach()->endswitch()->enddeclare()->__halt_compiler());"), "possible")

def ordered_imports(+a: String) -> Bool:
  empty(profile(a, "'mysql'", "<?php\nRoute::middleware('auth:api')->get('/x', fn () => 1);\nuse Illuminate\\Support\\Facades\\Route;")) &&
    empty(profile(a, "'mysql'", "<?php Route::middleware('auth:api')->get('/x', fn () => 1); use Illuminate\\Support\\Facades\\Route;")) &&
    empty(profile(a, "'mysql'", "<?php\nR::middleware('auth:api')->get('/x', fn () => 1);\nuse Illuminate\\Support\\Facades\\Route as R;")) &&
    empty(profile(a, "'mysql'", "<?php R::middleware('auth:api')->get('/x', fn () => 1); use Illuminate\\Support\\Facades\\Route as R;")) &&
    observed(profile(a, "'mysql'", "<?php R::middleware('auth:api')->get('/before', fn () => 1);\nuse Illuminate\\Support\\Facades\\Route as R;\nR::middleware('auth:api')->get('/after', fn () => 1);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\n\nR::middleware('auth:api')->get('/before', fn () => 1); use Illuminate\\Support\\Facades\\Route as R; R::middleware('auth:api')->get('/after', fn () => 1);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\n\nuse Illuminate\\Support\\Facades\\Route as R; R::middleware('auth:api')->get('/x', fn () => 1);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\n\n\\Illuminate\\Support\\Facades\\Route::middleware('auth:api')->get('/x', fn () => 1); use Other\\Route;"), "possible") &&
    empty(profile(a, "'mysql'", route() ++ "use Illuminate\\Support\\Facades\\Route;")) &&
    empty(profile(a, "'mysql'", route() ++ "use Other\\Route;")) &&
    empty(profile(a, "'mysql'", route() ++ "use Other\\{One, Two};")) &&
    empty(profile(a, "'mysql'", route() ++ "use Other\\One, Other\\Two;")) &&
    empty(profile(a, "'mysql'", route() ++ "namespace Other;"))

def main() -> U32:
  +a = auth("'token'", "'eloquent'", "false")
  +r = route()
  ok = route_contexts(a) && ordered_imports(a) &&
    observed(profile(a, "'mysql'", r), "possible") &&
    observed(profile(a, "'mariadb'", r), "possible") &&
    argument_tokens(L.qualified("<?php ...$actions"), L.qualified("<?php action: $handler")) &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/x', [Controller::class, 'show']);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/x', handler('a', 'b'));"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/x', fn () => 1,);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/x', fn ($a, $b) => [$a, $b]);"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/x', function ($a, $b) use ($c, $d) { return [$a, $b]; });"), "possible") &&
    observed(profile(a, "'mysql'", "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth:api')->get('/x', handler(action: 'show', options: [1, 2]),);"), "possible") &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get();")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x');")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x',);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get(, fn () => 1);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x',, fn () => 1);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x', fn () => 1, 'extra');")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x', fn () => 1, 'extra',);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x', fn () => 1,,);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x', ...$actions);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x', ...['show'],);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x', action: fn () => 1);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get('/x', action: [Controller::class, 'show'],);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get(uri: '/x', action: fn () => 1);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get(...$args);")) &&
    empty(profile(a, "'mysql'", "<?php use Illuminate\\Support\\Facades\\Route; Route::middleware('auth:api')->get($uri, fn () => 1);")) &&
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
    version("0.0.1", 1) && version("12.67.0", 2) && version("12.68.0", 0) &&
    version("13.0.0", 2) && version("13.28.0", 1) && version("13.29.0", 0) &&
    isolated(A.enrich(A.scan("{\"packages\":[{\"name\":\"symfony/http-foundation\",\"version\":\"7.3.6\"}]}"), profile(a, "'mysql'", r)))
  L.sel(U32, ok, u => 0, u => 1)
