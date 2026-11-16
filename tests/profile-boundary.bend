import Base
import ../src/profile-input.bend as P

def destructure(input: P.Input) -> U32:
  P.Input{nodes, tokens, ignores, allowance} = input
  0

def consume(input: Maybe<&2, P.Input>) -> U32:
  match input:
    case None{}: 1
    case Some{
      P.Input{nodes, tokens, ignores, allowance}}: 0

def main() -> U32:
  consume(P.parse("<?php $value = 1;"))
