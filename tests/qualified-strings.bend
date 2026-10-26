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

def step(st: L.Step, expected: L.Step) -> Bool:
  match st expected:
    case L.Step{rest, line, ts} L.Step{tail, end, us}:
      String.eq(rest, tail) && U32.is_eq(line, end) && equal(ts, us)

def remapping() -> Bool:
  +ts = {[L.Tok{2, "first", 2}, L.Tok{0, "var", 3}, L.Tok{1, "id", 4},
    L.Tok{3, "value ", 5}, L.Tok{4, "42", 6}, L.Tok{2, "second", 7},
    L.Tok{5, ";", 8}, L.Tok{6, "int", 9}, L.Tok{7, "cmd ", 10},
    L.Tok{8, "", 11}, L.Tok{9, "", 12}] : List<&2, L.Tok>}
  step(L.qualified.string.step(False{}, L.Step{"remaining", 13, ts}),
    L.Step{"remaining", 13, [L.Tok{9, "", 2}, L.Tok{0, "var", 3}, L.Tok{1, "id", 4},
      L.Tok{3, "value ", 5}, L.Tok{4, "42", 6}, L.Tok{9, "", 7},
      L.Tok{5, ";", 8}, L.Tok{6, "int", 9}, L.Tok{7, "cmd ", 10},
      L.Tok{8, "", 11}, L.Tok{9, "", 12}]}) &&
    step(L.qualified.string.step(True{}, L.Step{"remaining", 13, ts}), L.Step{"remaining", 13, ts}) &&
    step(L.qualified.string.step(False{}, L.Step{"empty", 14, []}), L.Step{"empty", 14, []})

def block_strings() -> Bool:
  qualified("<?php\n<<<TXT\ntoken\nTXT;\n$next", [L.Tok{9, "", 2}, L.Tok{5, ";", 4}, L.Tok{0, "next", 5}]) &&
    qualified("<?php\n<<<\"TXT\"\ntoken\nTXT;", [L.Tok{9, "", 2}, L.Tok{5, ";", 4}]) &&
    qualified("<?php\n<<<'TXT'\ntoken\nTXT;", [L.Tok{9, "", 2}, L.Tok{5, ";", 4}]) &&
    qualified("<?php\n<<<TXT\nt\\oken\nTXT;", [L.Tok{9, "", 2}, L.Tok{5, ";", 4}]) &&
    qualified("<?php\n<<<'TXT'\nt\\oken\nTXT;", [L.Tok{9, "", 2}, L.Tok{5, ";", 4}]) &&
    qualified("<?php\n<<<TXT\n$value\nTXT; `echo $value`", [L.Tok{3, "value ", 2}, L.Tok{5, ";", 4}, L.Tok{7, "value ", 4}]) &&
    equal(L.lex("<?php\n<<<TXT\nt\\oken\nTXT;\n<<<'TXT'\nt\\oken\nTXT;"),
      [L.Tok{2, "token\n", 2}, L.Tok{5, ";", 4}, L.Tok{2, "t\\oken\n", 5}, L.Tok{5, ";", 7}]) &&
    qualified("<?php\n<<<'TXT'\napi\nTXT; // phpscan-ignore\n// phpscan-ignore\n\"mysql\";",
      [L.Tok{9, "", 2}, L.Tok{5, ";", 4}, L.Tok{8, "", 4}, L.Tok{8, "", 5}, L.Tok{2, "mysql", 6}, L.Tok{5, ";", 6}])

def symfony.evidence(e: E.Evidence, expected: U32) -> Bool:
  match e:
    case E.Evidence{sites, incomplete}:
      Bool.not(incomplete) && U32.is_eq(U32.from_nat(List.length(&2, E.Site, sites)), expected)

def symfony(prefix: String, expected: U32) -> Bool:
  src = "<?php function access(\\Symfony\\Component\\HttpFoundation\\Request $request) { if (str_starts_with($request->getPathInfo(), " ++ prefix ++ ")) { abort_unless(auth()->check(), 403); } }"
  symfony.evidence(P.scan("access.php", src), expected)

def main() -> U32:
  ok = remapping() && block_strings() &&
    qualified("<?php \"token\" \"\" 't\\oken'", [L.Tok{2, "token", 1}, L.Tok{2, "", 1}, L.Tok{2, "t\\oken", 1}]) &&
    qualified("<?php 'a\\'b' 'a\\\\b'", [L.Tok{2, "a'b", 1}, L.Tok{2, "a\\b", 1}]) &&
    qualified("<?php\n'a\nb';\n\"\"", [L.Tok{2, "a\nb", 2}, L.Tok{5, ";", 3}, L.Tok{2, "", 4}]) &&
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
    symfony("\"/admin\"", 1) && symfony("\"/ad\\min\"", 0) && symfony("\"/$prefix\"", 0) &&
    symfony("'/admin'", 1) && symfony("\"/admin\n\"", 1) &&
    symfony("<<<TXT\n/admin\nTXT\n", 0) && symfony("<<<'TXT'\n/admin\nTXT\n", 0) &&
    symfony("`/admin`", 0)
  L.sel(U32, ok, u => 0, u => 1)
