import Base
import ./lex.bend as L
import ./tree.bend as T

type Input is Data:
  Input{nodes: List<&2, T.Node>, tokens: List<&2, L.Tok>, ignores: List<&2, U32>, allowance: Nat}

def halted(ns: List<&2, T.Node>) -> Bool:
  match ns:
    case Nil{}:
      False{}
    case Con{T.Leaf{L.Tok{1, "__halt_compiler", l}}, rest}:
      True{}
    case Con{n, rest}:
      halted(rest)

def grouped(+raw: List<&2, L.Tok>) -> Maybe<&2, Input>:
  +tokens = L.without_ignores(raw)
  +nodes = T.tree(tokens)
  L.sel(Maybe<&2, Input>, halted(nodes), u => None{},
    u => Some{Input{nodes, tokens, L.ignored_lines(raw), 1n+List.length(&2, L.Tok, raw)}})

def parse(source: String) -> Maybe<&2, Input>:
  +raw = L.qualified(source)
  L.sel(Maybe<&2, Input>, T.balanced(raw), u => grouped(raw), u => None{})
