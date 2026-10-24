import Base
import ./lex.bend as L

# Bracket tree. A Grp holds the nodes between a matching pair of brackets.
# Grp kinds: 40 '(', 91 '[', 123 '{', 35 '#['.
type Node is Data:
  Leaf{tok: L.Tok}
  Grp{kind: U32, line: U32, kids: List<&2, Node>}

# An open bracket waiting for its closer: the nodes before it, newest first.
type Frame is Data:
  Frame{kind: U32, line: U32, saved: List<&2, Node>}

def close_all(stack: List<&2, Frame>, cur: List<&2, Node>) -> List<&2, Node>:
  match stack:
    case Nil{}:
      List.reverse(&2, Node, cur)
    case Con{Frame{k, l, saved}, st}:
      close_all(st, Con{Grp{k, l, List.reverse(&2, Node, cur)}, saved})

# cur is newest first. Unmatched closers are dropped; mismatched closers
# close the innermost open bracket.
def build(ts: List<&2, L.Tok>, cur: List<&2, Node>, stack: List<&2, Frame>) -> List<&2, Node>:
  match ts stack:
    case Nil{} st:
      close_all(st, cur)
    case Con{L.Tok{5, "(", l}, rest} st:
      build(rest, [], Con{Frame{40, l, cur}, st})
    case Con{L.Tok{5, "[", l}, rest} st:
      build(rest, [], Con{Frame{91, l, cur}, st})
    case Con{L.Tok{5, "{", l}, rest} st:
      build(rest, [], Con{Frame{123, l, cur}, st})
    case Con{L.Tok{5, "#[", l}, rest} st:
      build(rest, [], Con{Frame{35, l, cur}, st})
    case Con{L.Tok{5, ")", l}, rest} Nil{}:
      build(rest, cur, [])
    case Con{L.Tok{5, "]", l}, rest} Nil{}:
      build(rest, cur, [])
    case Con{L.Tok{5, "}", l}, rest} Nil{}:
      build(rest, cur, [])
    case Con{L.Tok{5, ")", l}, rest} Con{Frame{k, fl, saved}, st}:
      build(rest, Con{Grp{k, fl, List.reverse(&2, Node, cur)}, saved}, st)
    case Con{L.Tok{5, "]", l}, rest} Con{Frame{k, fl, saved}, st}:
      build(rest, Con{Grp{k, fl, List.reverse(&2, Node, cur)}, saved}, st)
    case Con{L.Tok{5, "}", l}, rest} Con{Frame{k, fl, saved}, st}:
      build(rest, Con{Grp{k, fl, List.reverse(&2, Node, cur)}, saved}, st)
    case Con{t, rest} st:
      build(rest, Con{Leaf{t}, cur}, st)

def tree(ts: List<&2, L.Tok>) -> List<&2, Node>:
  build(ts, [], [])
