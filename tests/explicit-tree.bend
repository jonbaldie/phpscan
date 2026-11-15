import Base
import ../src/lex.bend as L
import ../src/tree.bend as T

def repaired(ns: List<&2, T.Node>) -> Bool:
  match ns:
    case Con{T.Grp{40, 1, Con{T.Leaf{L.Tok{0, "x", 1}}, Nil{}}}, Con{T.Leaf{L.Tok{0, "y", 1}}, Nil{}}}:
      True{}
    case _:
      False{}

def eof_closed(ns: List<&2, T.Node>) -> Bool:
  match ns:
    case Con{T.Leaf{L.Tok{0, "a", 1}}, Con{T.Grp{91, 1, Con{T.Leaf{L.Tok{0, "b", 1}}, Con{T.Grp{123, 1, Con{T.Leaf{L.Tok{0, "c", 1}}, Nil{}}}, Nil{}}}}, Nil{}}}:
      True{}
    case _:
      False{}

def attribute(ns: List<&2, T.Node>) -> Bool:
  match ns:
    case Con{T.Grp{35, 1, Con{T.Leaf{L.Tok{1, "attr", 1}}, Nil{}}}, Nil{}}:
      True{}
    case _:
      False{}

def main() -> U32:
  ok = T.balanced(L.lex("<?php ($a[$b]) {$c;} #[Attr]")) &&
    T.balanced([]) && Bool.not(T.balanced(L.lex("<?php ($x]"))) &&
    Bool.not(T.balanced(L.lex("<?php )$x"))) && Bool.not(T.balanced(L.lex("<?php ($x"))) &&
    repaired(T.tree(L.lex("<?php )($x]$y}"))) && eof_closed(T.tree(L.lex("<?php $a[$b{$c"))) &&
    attribute(T.tree(L.lex("<?php #[Attr]")))
  L.sel(U32, ok, u => 0, u => 1)
