import Base
import ../src/lex.bend as L
import ../src/symfony.bend as P
import ../src/evidence.bend as E

def equal(xs: List<&2, L.Tok>, ys: List<&2, L.Tok>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{L.Tok{k, s, l}, ts} Con{L.Tok{j, t, m}, us}:
      U32.is_eq(k, j) && String.eq(s, t) && U32.is_eq(l, m) && equal(ts, us)
    case _ _:
      False{}

def qualified(src: String, expected: List<&2, L.Tok>) -> Bool:
  equal(L.qualified(src), expected)

def symfony.evidence(e: E.Evidence, expected: U32) -> Bool:
  match e:
    case E.Evidence{sites, incomplete}:
      Bool.not(incomplete) && U32.is_eq(U32.from_nat(List.length(&2, E.Site, sites)), expected)

def symfony(prefix: String, expected: U32) -> Bool:
  src = "<?php function access(\\Symfony\\Component\\HttpFoundation\\Request $request) { if (str_starts_with($request->getPathInfo(), " ++ prefix ++ ")) { abort_unless(auth()->check(), 403); } }"
  symfony.evidence(P.scan("access.php", src), expected)

def main() -> U32:
  ok = qualified("<?php \"token\" \"\" 't\\oken'", [L.Tok{2, "token", 1}, L.Tok{2, "", 1}, L.Tok{2, "t\\oken", 1}]) &&
    qualified("<?php 'a\\'b' 'a\\\\b'", [L.Tok{2, "a'b", 1}, L.Tok{2, "a\\b", 1}]) &&
    qualified("<?php \"t\\oken\"; \"mysql\"", [L.Tok{9, "", 1}, L.Tok{5, ";", 1}, L.Tok{2, "mysql", 1}]) &&
    qualified("<?php \"a\\\"b\"; $next", [L.Tok{9, "", 1}, L.Tok{5, ";", 1}, L.Tok{0, "next", 1}]) &&
    qualified("<?php \"a\\\\b\" \"a\\n\" \"a\\$b\"", [L.Tok{9, "", 1}, L.Tok{9, "", 1}, L.Tok{9, "", 1}]) &&
    qualified("<?php \"$value\" \"\\x$value\"", [L.Tok{3, "value ", 1}, L.Tok{3, "value ", 1}]) &&
    qualified("<?php\n\"a\nb\";\n\"c\\\nd\";\n$next", [L.Tok{2, "a\nb", 2}, L.Tok{5, ";", 3}, L.Tok{9, "", 4}, L.Tok{5, ";", 5}, L.Tok{0, "next", 6}]) &&
    qualified("<?php\n\"unterminated\n", [L.Tok{9, "", 2}]) &&
    qualified("<?php \"", [L.Tok{9, "", 1}]) &&
    qualified("<?php \"trailing\\", [L.Tok{9, "", 1}]) &&
    qualified("<?php /* \\ */ \"token\"; // \\\n\"mysql\"", [L.Tok{2, "token", 1}, L.Tok{5, ";", 1}, L.Tok{2, "mysql", 2}]) &&
    qualified("<?php \"t\\oken\"; // phpscan-ignore\n\"mysql\"", [L.Tok{9, "", 1}, L.Tok{5, ";", 1}, L.Tok{8, "", 1}, L.Tok{2, "mysql", 2}]) &&
    equal(L.lex("<?php \"t\\oken\" \"$value\""), [L.Tok{2, "token", 1}, L.Tok{3, "value ", 1}]) &&
    symfony("\"/admin\"", 1) && symfony("\"/ad\\min\"", 0) && symfony("\"/$prefix\"", 0)
  L.sel(U32, ok, u => 0, u => 1)
