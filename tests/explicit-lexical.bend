import Base
import ../src/lex.bend as L

def equal(xs: List<&2, L.Tok>, ys: List<&2, L.Tok>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{L.Tok{k, s, l}, ts} Con{L.Tok{j, t, m}, us}:
      U32.is_eq(k, j) && String.eq(s, t) && U32.is_eq(l, m) && equal(ts, us)
    case _ _:
      False{}

def tokens(src: String, expected: List<&2, L.Tok>) -> Bool:
  equal(L.lex(src), expected)

def dispatch() -> Bool:
  tokens("HTML\n<?php $a ?>html\n<?= $b ?>tail", [L.Tok{0, "a", 2}, L.Tok{5, ";", 2}, L.Tok{1, "echo", 3}, L.Tok{0, "b", 3}, L.Tok{5, ";", 3}]) &&
    tokens("only HTML\n", []) && tokens("<?=", [L.Tok{1, "echo", 1}]) &&
    tokens("<?PHP\n// comment ?>\n<?= 1", [L.Tok{5, ";", 2}, L.Tok{1, "echo", 3}, L.Tok{4, "1", 3}]) &&
    equal(L.lex.go(0n, L.Step{"$later", 1, [L.Tok{0, "earlier", 1}]}, []), [L.Tok{0, "earlier", 1}]) &&
    equal(L.lex.go(1n, L.Step{"$first $later", 1, []}, []), [L.Tok{0, "first", 1}]) &&
    equal(L.lex.go(0n, L.Step{"", 1, [L.Tok{0, "end", 1}]}, []), [L.Tok{0, "end", 1}])

def interpolation() -> Bool:
  tokens("<?php \"$a {$b->x} ${c[0]}\"", [L.Tok{3, "c b a ", 1}]) &&
    tokens("<?php \"{$a[{nested}]}-$b\"", [L.Tok{3, "b a ", 1}]) &&
    tokens("<?php \"${}\" \"$9\" \"{x}\"", [L.Tok{3, " ", 1}, L.Tok{2, "$9", 1}, L.Tok{2, "{x}", 1}]) &&
    tokens("<?php \"a\\$b\\\"c\\\\d\"", [L.Tok{2, "a$b\"c\\d", 1}]) &&
    tokens("<?php \"a\n\\\n\"; $b", [L.Tok{2, "a\n\n", 1}, L.Tok{5, ";", 3}, L.Tok{0, "b", 3}]) &&
    tokens("<?php \"$name", [L.Tok{3, "name ", 1}]) &&
    tokens("<?php \"{$name", [L.Tok{2, "", 1}]) &&
    tokens("<?php \"${name", [L.Tok{2, "", 1}]) &&
    tokens("<?php \"a$", [L.Tok{2, "a", 1}]) &&
    tokens("<?php \"a{", [L.Tok{2, "a", 1}]) &&
    tokens("<?php \"a\\", [L.Tok{2, "a", 1}]) &&
    tokens("<?php `echo $arg`", [L.Tok{7, "arg ", 1}]) &&
    tokens("<?php \"{$a[\n1]}\"; $b", [L.Tok{3, "a ", 1}, L.Tok{5, ";", 2}, L.Tok{0, "b", 2}])

def documents() -> Bool:
  tokens("<?php\n<<<TXT\n$a\n  TXT; $b", [L.Tok{3, "a ", 2}, L.Tok{5, ";", 4}, L.Tok{0, "b", 4}]) &&
    tokens("<?php\n<<<'TXT'\n$a\\n\nTXT;", [L.Tok{2, "$a\\n\n", 2}, L.Tok{5, ";", 4}]) &&
    tokens("<?php\n<<<\"TXT\"\nTXTtail\nTXT;", [L.Tok{2, "TXTtail\n", 2}, L.Tok{5, ";", 4}]) &&
    tokens("<?php\n<<<TXT\nx TXT\nTXT;", [L.Tok{2, "x TXT\n", 2}, L.Tok{5, ";", 4}]) &&
    tokens("<?php\n<<<TXT\n$a", [L.Tok{3, "a ", 2}]) &&
    tokens("<?php\n<<<'TXT'\n$a", [L.Tok{2, "$a", 2}]) &&
    tokens("<?php <<<TXT", [L.Tok{2, "", 1}]) &&
    tokens("<?php\n<<<TXT\na" ++ SCon{Char.from_u32(0), "$hidden\nTXT;"}, [L.Tok{2, "a", 2}, L.Tok{5, ";", 4}])

def recognizers() -> Bool:
  tokens("<?php ( int ) $a; ( no ) $b; (\nint) $c", [L.Tok{6, "int", 1}, L.Tok{0, "a", 1}, L.Tok{5, ";", 1}, L.Tok{5, "(", 1}, L.Tok{1, "no", 1}, L.Tok{5, ")", 1}, L.Tok{0, "b", 1}, L.Tok{5, ";", 1}, L.Tok{5, "(", 1}, L.Tok{1, "int", 2}, L.Tok{5, ")", 2}, L.Tok{0, "c", 2}]) &&
    tokens("<?php 'a\\'b' 'a\\\\b' 'open", [L.Tok{2, "a'b", 1}, L.Tok{2, "a\\b", 1}, L.Tok{2, "open", 1}]) &&
    tokens("<?php /* open\n", []) &&
    equal(L.qualified("<?php \\Foo\\Bar \"safe\" \"es\\cape\""), [L.Tok{1, "\\foo\\bar", 1}, L.Tok{2, "safe", 1}, L.Tok{9, "", 1}])

def lines_equal(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{x, xs} Con{y, ys}:
      U32.is_eq(x, y) && lines_equal(xs, ys)
    case _ _:
      False{}

def suppression() -> Bool:
  lines_equal(L.ignored_lines([L.Tok{8, "", 0}]), [0]) &&
    lines_equal(L.ignored_lines([L.Tok{8, "", 1}]), [2]) &&
    lines_equal(L.ignored_lines(L.lex("<?php // phpscan-ignore\n$a; // phpscan-ignore\n// phpscan-ignore\n/* phpscan-ignore\n still comment */\n$b")), [2, 2, 4, 5]) &&
    lines_equal(L.ignored_lines(L.lex("<?php // phpscan-ignore\n// phpscan-ignore")), [2, 3]) &&
    lines_equal(L.ignored_lines(L.lex("<?php $a; /* phpscan-ignore\n */ $b;")), [1])

def main() -> U32:
  L.sel(U32, dispatch() && interpolation() && documents() && recognizers() && suppression(), u => 0, u => 1)
