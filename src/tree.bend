import Base
import ./lex.bend as L

# Grp kinds retain the opener token codes, including 35 for '#['.
type Node is Data:
  Leaf{tok: L.Tok}
  Grp{kind: U32, line: U32, kids: List<&2, Node>}

type BuildContext is Data:
  TreeRoot{}
  OpenGroup{kind: U32, line: U32, saved: List<&2, Node>, outer: BuildContext}

type Delimiter is Data:
  Parenthesis{}
  Bracket{}
  Brace{}

type BalanceContext is Data:
  BalanceRoot{}
  ExpectCloser{delimiter: Delimiter, outer: BalanceContext}

def close_all(context: BuildContext, cur: List<&2, Node>) -> List<&2, Node>:
  match context:
    case TreeRoot{}:
      List.reverse(&2, Node, cur)
    case OpenGroup{k, l, saved, outer}:
      close_all(outer, Con{Grp{k, l, List.reverse(&2, Node, cur)}, saved})

def build.tolerant(ts: List<&2, L.Tok>, cur: List<&2, Node>, context: BuildContext) -> List<&2, Node>:
  match ts context:
    case Nil{} outer:
      close_all(outer, cur)
    case Con{L.Tok{5, "(", l}, rest} outer:
      build.tolerant(rest, [], OpenGroup{40, l, cur, outer})
    case Con{L.Tok{5, "[", l}, rest} outer:
      build.tolerant(rest, [], OpenGroup{91, l, cur, outer})
    case Con{L.Tok{5, "{", l}, rest} outer:
      build.tolerant(rest, [], OpenGroup{123, l, cur, outer})
    case Con{L.Tok{5, "#[", l}, rest} outer:
      build.tolerant(rest, [], OpenGroup{35, l, cur, outer})
    case Con{L.Tok{5, ")", l}, rest} TreeRoot{}:
      build.tolerant(rest, cur, TreeRoot{})
    case Con{L.Tok{5, "]", l}, rest} TreeRoot{}:
      build.tolerant(rest, cur, TreeRoot{})
    case Con{L.Tok{5, "}", l}, rest} TreeRoot{}:
      build.tolerant(rest, cur, TreeRoot{})
    case Con{L.Tok{5, ")", l}, rest} OpenGroup{k, fl, saved, outer}:
      build.tolerant(rest, Con{Grp{k, fl, List.reverse(&2, Node, cur)}, saved}, outer)
    case Con{L.Tok{5, "]", l}, rest} OpenGroup{k, fl, saved, outer}:
      build.tolerant(rest, Con{Grp{k, fl, List.reverse(&2, Node, cur)}, saved}, outer)
    case Con{L.Tok{5, "}", l}, rest} OpenGroup{k, fl, saved, outer}:
      build.tolerant(rest, Con{Grp{k, fl, List.reverse(&2, Node, cur)}, saved}, outer)
    case Con{t, rest} outer:
      build.tolerant(rest, Con{Leaf{t}, cur}, outer)

def closer(delimiter: Delimiter) -> String:
  match delimiter:
    case Parenthesis{}:
      ")"
    case Bracket{}:
      "]"
    case Brace{}:
      "}"

def balanced.go(ts: List<&2, L.Tok>, context: BalanceContext) -> Bool:
  match ts context:
    case Nil{} BalanceRoot{}:
      True{}
    case Nil{} _:
      False{}
    case Con{L.Tok{5, "(", l}, rest} outer:
      balanced.go(rest, ExpectCloser{Parenthesis{}, outer})
    case Con{L.Tok{5, "[", l}, rest} outer:
      balanced.go(rest, ExpectCloser{Bracket{}, outer})
    case Con{L.Tok{5, "#[", l}, rest} outer:
      balanced.go(rest, ExpectCloser{Bracket{}, outer})
    case Con{L.Tok{5, "{", l}, rest} outer:
      balanced.go(rest, ExpectCloser{Brace{}, outer})
    case Con{L.Tok{5, +s, l}, +rest} ExpectCloser{+expected, +outer}:
      L.sel(Bool, String.eq(s, ")") || String.eq(s, "]") || String.eq(s, "}"),
        u => String.eq(s, closer(expected)) && balanced.go(rest, outer),
        u => balanced.go(rest, ExpectCloser{expected, outer}))
    case Con{L.Tok{5, +s, l}, rest} BalanceRoot{}:
      Bool.not(String.eq(s, ")") || String.eq(s, "]") || String.eq(s, "}")) && balanced.go(rest, BalanceRoot{})
    case Con{t, rest} outer:
      balanced.go(rest, outer)

def balanced(ts: List<&2, L.Tok>) -> Bool:
  balanced.go(ts, BalanceRoot{})

def tree(ts: List<&2, L.Tok>) -> List<&2, Node>:
  build.tolerant(ts, [], TreeRoot{})
