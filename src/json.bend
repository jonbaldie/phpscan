import Base
import ./lex.bend as L

type Value is Data:
  Object{fields: List<&2, Field>}
  Array{values: List<&2, Value>}
  Str{line: U32, value: String}
  Other{}

type Field is Data:
  Field{key: String, value: Value}

type Token is Data:
  Punct{value: String}
  Quoted{line: U32, value: String}
  Literal{}

type CodeRest is Data:
  CodeRest{code: U32, rest: String}

type StringRest is Data:
  StringRest{text: String, rest: String}

type Parsed is Data:
  Parsed{value: Value, rest: List<&2, Token>}

def code(r: CodeRest) -> U32:
  match r:
    case CodeRest{n, s}:
      n

def code.rest(r: CodeRest) -> String:
  match r:
    case CodeRest{n, s}:
      s

def text(r: StringRest) -> String:
  match r:
    case StringRest{t, s}:
      t

def text.rest(r: StringRest) -> String:
  match r:
    case StringRest{t, s}:
      s

def value(r: Parsed) -> Value:
  match r:
    case Parsed{v, ts}:
      v

def value.rest(r: Parsed) -> List<&2, Token>:
  match r:
    case Parsed{v, ts}:
      ts

def space(+c: Char) -> Bool:
  Char.is_eq(c, ' ') || Char.is_eq(c, '\t') || Char.is_eq(c, '\r') || Char.is_eq(c, '\n')

def punct(+c: Char) -> Bool:
  Char.is_eq(c, '{') || Char.is_eq(c, '}') || Char.is_eq(c, '[') || Char.is_eq(c, ']') || Char.is_eq(c, ':') || Char.is_eq(c, ',')

def hex(+c: Char) -> Maybe<&2, U32>:
  +n = Char.to_u32(c)
  L.sel(Maybe<&2, U32>, Char.is_digit(c), u => Some{U32.sub(n, 48)},
    u => L.sel(Maybe<&2, U32>, U32.is_le(97, n) && U32.is_le(n, 102), v => Some{U32.sub(n, 87)},
      v => L.sel(Maybe<&2, U32>, U32.is_le(65, n) && U32.is_le(n, 70), w => Some{U32.sub(n, 55)}, w => None{})))

def hex4(s: String) -> Maybe<&2, CodeRest>:
  match s:
    case SCon{a, SCon{b, SCon{c, SCon{d, rest}}}}:
      do Maybe<&2, CodeRest>:
        x : U32 <- hex(a)
        y : U32 <- hex(b)
        z : U32 <- hex(c)
        w : U32 <- hex(d)
        return CodeRest{U32.add(U32.add(U32.mul(x, 4096), U32.mul(y, 256)), U32.add(U32.mul(z, 16), w)), rest}
    case _:
      None{}

type UnicodePhase is Data:
  ScalarUnit{code: U32}
  HighSurrogate{high: U32}
  InvalidSurrogate{}

def unicode.phase(+n: U32) -> UnicodePhase:
  L.sel(UnicodePhase, U32.is_le(55296, n) && U32.is_le(n, 56319), u => HighSurrogate{n},
    u => L.sel(UnicodePhase, U32.is_le(56320, n) && U32.is_le(n, 57343), v => InvalidSurrogate{}, v => ScalarUnit{n}))

def surrogate(+hi: U32, s: String) -> Maybe<&2, CodeRest>:
  match s:
    case SCon{'\\', SCon{'u', rest}}:
      Maybe.bind(&2, CodeRest, CodeRest, hex4(rest), +r => (
        +lo = code(r)
        L.sel(Maybe<&2, CodeRest>, U32.is_le(56320, lo) && U32.is_le(lo, 57343),
          u => Some{CodeRest{U32.add(65536, U32.add(U32.mul(U32.sub(hi, 55296), 1024), U32.sub(lo, 56320))), code.rest(r)}}, u => None{})))
    case _:
      None{}

def unicode(phase: UnicodePhase, s: String) -> Maybe<&2, CodeRest>:
  match phase:
    case ScalarUnit{n}:
      Some{CodeRest{n, s}}
    case HighSurrogate{hi}:
      surrogate(hi, s)
    case InvalidSurrogate{}:
      None{}

def escaped(c: Char) -> Maybe<&2, Char>:
  match c:
    case '"':
      Some{'"'}
    case '\\':
      Some{'\\'}
    case '/':
      Some{'/'}
    case 'b':
      Some{Char.from_u32(8)}
    case 'f':
      Some{Char.from_u32(12)}
    case 'n':
      Some{'\n'}
    case 'r':
      Some{'\r'}
    case 't':
      Some{'\t'}
    case _:
      None{}

def quoted(fuel: Nat, s: String, acc: List<&2, Char>) -> Maybe<&2, StringRest>:
  match fuel s:
    case 1n+p SCon{'"', rest}:
      Some{StringRest{String.from_list(List.reverse(&2, Char, acc)), rest}}
    case 1n+p SCon{'\\', SCon{'u', rest}}:
      Maybe.bind(&2, CodeRest, StringRest, hex4(rest), +r =>
        Maybe.bind(&2, CodeRest, StringRest, unicode(unicode.phase(code(r)), code.rest(r)), +d =>
          quoted(p, code.rest(d), Con{Char.from_u32(code(d)), acc})))
    case 1n+p SCon{'\\', SCon{c, rest}}:
      do Maybe<&2, StringRest>:
        decoded : Char <- escaped(c)
        quoted(p, rest, Con{decoded, acc})
    case 1n+p SCon{+c, rest}:
      L.sel(Maybe<&2, StringRest>, U32.is_lt(Char.to_u32(c), 32), u => None{}, u => quoted(p, rest, Con{c, acc}))
    case _ _:
      None{}

def raw(s: String, +acc: List<&2, Char>) -> StringRest:
  match s:
    case SNil{}:
      StringRest{String.from_list(List.reverse(&2, Char, acc)), ""}
    case SCon{+c, +rest}:
      L.sel(StringRest, space(c) || punct(c),
        u => StringRest{String.from_list(List.reverse(&2, Char, acc)), SCon{c, rest}}, u => raw(rest, Con{c, acc}))

type NumberPhase is Data:
  NumberStart{}
  NumberMinus{}
  NumberZero{}
  NumberInteger{}
  NumberPoint{}
  NumberFraction{}
  NumberExponent{}
  NumberSign{}
  NumberDigits{}
  NumberDead{}

def number.accept(phase: NumberPhase) -> Bool:
  match phase:
    case NumberZero{}:
      True{}
    case NumberInteger{}:
      True{}
    case NumberFraction{}:
      True{}
    case NumberDigits{}:
      True{}
    case _:
      False{}

def number.first(+c: Char) -> NumberPhase:
  L.sel(NumberPhase, Char.is_eq(c, '0'), u => NumberZero{},
    u => L.sel(NumberPhase, Char.is_digit(c), v => NumberInteger{}, v => NumberDead{}))

def number.tail(+c: Char) -> NumberPhase:
  L.sel(NumberPhase, Char.is_eq(c, '.'), u => NumberPoint{},
    u => L.sel(NumberPhase, Char.is_eq(c, 'e') || Char.is_eq(c, 'E'), v => NumberExponent{}, v => NumberDead{}))

def number.step(phase: NumberPhase, +c: Char) -> NumberPhase:
  match phase:
    case NumberStart{}:
      L.sel(NumberPhase, Char.is_eq(c, '-'), u => NumberMinus{}, u => number.first(c))
    case NumberMinus{}:
      number.first(c)
    case NumberZero{}:
      number.tail(c)
    case NumberInteger{}:
      L.sel(NumberPhase, Char.is_digit(c), u => NumberInteger{}, u => number.tail(c))
    case NumberPoint{}:
      L.sel(NumberPhase, Char.is_digit(c), u => NumberFraction{}, u => NumberDead{})
    case NumberFraction{}:
      L.sel(NumberPhase, Char.is_digit(c), u => NumberFraction{},
        u => L.sel(NumberPhase, Char.is_eq(c, 'e') || Char.is_eq(c, 'E'), v => NumberExponent{}, v => NumberDead{}))
    case NumberExponent{}:
      L.sel(NumberPhase, Char.is_eq(c, '+') || Char.is_eq(c, '-'), u => NumberSign{},
        u => L.sel(NumberPhase, Char.is_digit(c), v => NumberDigits{}, v => NumberDead{}))
    case NumberSign{}:
      L.sel(NumberPhase, Char.is_digit(c), u => NumberDigits{}, u => NumberDead{})
    case NumberDigits{}:
      L.sel(NumberPhase, Char.is_digit(c), u => NumberDigits{}, u => NumberDead{})
    case NumberDead{}:
      NumberDead{}

def number(s: String, phase: NumberPhase) -> Bool:
  match s:
    case SNil{}:
      number.accept(phase)
    case SCon{c, rest}:
      number(rest, number.step(phase, c))

type TokenPhase is Data:
  TokenEnd{}
  TokenSpace{char: Char, rest: String}
  TokenPunctuation{char: Char, rest: String}
  TokenQuoted{rest: String}
  TokenRaw{source: String}

def token.phase(s: String) -> TokenPhase:
  match s:
    case SNil{}:
      TokenEnd{}
    case SCon{'"', rest}:
      TokenQuoted{rest}
    case SCon{+c, +rest}:
      L.sel(TokenPhase, space(c), u => TokenSpace{c, rest},
        u => L.sel(TokenPhase, punct(c), v => TokenPunctuation{c, rest}, v => TokenRaw{SCon{c, rest}}))

def lex.phase(fuel: Nat, phase: TokenPhase, +line: U32) -> Maybe<&2, List<&2, Token>>:
  match fuel phase:
    case 1n+p TokenEnd{}:
      Some{[]}
    case 1n+(+p) TokenQuoted{rest}:
      Maybe.bind(&2, StringRest, List<&2, Token>, quoted(p, rest, []), +r =>
        do Maybe<&2, List<&2, Token>>:
          tokens : List<&2, Token> <- lex.phase(p, token.phase(text.rest(r)), line)
          return Con{Quoted{line, text(r)}, tokens})
    case 1n+p TokenSpace{+c, rest}:
      lex.phase(p, token.phase(rest), L.sel(U32, Char.is_eq(c, '\n'), v => U32.add(line, 1), v => line))
    case 1n+p TokenPunctuation{c, rest}:
      do Maybe<&2, List<&2, Token>>:
        tokens : List<&2, Token> <- lex.phase(p, token.phase(rest), line)
        return Con{Punct{SCon{c, SNil{}}}, tokens}
    case 1n+p TokenRaw{source}:
      +r = raw(source, [])
      +t = text(r)
      L.sel(Maybe<&2, List<&2, Token>>, String.eq(t, "true") || String.eq(t, "false") || String.eq(t, "null") || number(t, NumberStart{}),
        w => do Maybe<&2, List<&2, Token>>:
          tokens : List<&2, Token> <- lex.phase(p, token.phase(text.rest(r)), line)
          return Con{Literal{}, tokens}, w => None{})
    case _ _:
      None{}

def lex(fuel: Nat, s: String, +line: U32) -> Maybe<&2, List<&2, Token>>:
  lex.phase(fuel, token.phase(s), line)

def has(fields: List<&2, Field>, +key: String) -> Bool:
  match fields:
    case Nil{}:
      False{}
    case Con{Field{name, v}, rest}:
      String.eq(name, key) || has(rest, key)

type ParsePhase is Data:
  ParseValue{}
  ArrayStart{values: List<&2, Value>}
  ArrayNext{values: List<&2, Value>}
  ObjectStart{fields: List<&2, Field>}
  ObjectNext{fields: List<&2, Field>}
  ObjectKey{fields: List<&2, Field>}

def parse(fuel: Nat, phase: ParsePhase, ts: List<&2, Token>) -> Maybe<&2, Parsed>:
  match fuel phase ts:
    case 1n+p ParseValue{} Con{Quoted{line, v}, rest}:
      Some{Parsed{Str{line, v}, rest}}
    case 1n+p ParseValue{} Con{Literal{}, rest}:
      Some{Parsed{Other{}, rest}}
    case 1n+p ParseValue{} Con{Punct{"["}, rest}:
      parse(p, ArrayStart{[]}, rest)
    case 1n+p ParseValue{} Con{Punct{"{"}, rest}:
      parse(p, ObjectStart{[]}, rest)
    case 1n+p ArrayStart{values} Con{Punct{"]"}, rest}:
      Some{Parsed{Array{List.reverse(&2, Value, values)}, rest}}
    case 1n+(+p) ArrayStart{values} +tokens:
      Maybe.bind(&2, Parsed, Parsed, parse(p, ParseValue{}, tokens), +r =>
        parse(p, ArrayNext{Con{value(r), values}}, value.rest(r)))
    case 1n+p ArrayNext{values} Con{Punct{"]"}, rest}:
      Some{Parsed{Array{List.reverse(&2, Value, values)}, rest}}
    case 1n+(+p) ArrayNext{values} Con{Punct{","}, rest}:
      Maybe.bind(&2, Parsed, Parsed, parse(p, ParseValue{}, rest), +r =>
        parse(p, ArrayNext{Con{value(r), values}}, value.rest(r)))
    case 1n+p ObjectStart{fields} Con{Punct{"}"}, rest}:
      Some{Parsed{Object{List.reverse(&2, Field, fields)}, rest}}
    case 1n+p ObjectStart{fields} tokens:
      parse(p, ObjectKey{fields}, tokens)
    case 1n+p ObjectNext{fields} Con{Punct{"}"}, rest}:
      Some{Parsed{Object{List.reverse(&2, Field, fields)}, rest}}
    case 1n+p ObjectNext{fields} Con{Punct{","}, rest}:
      parse(p, ObjectKey{fields}, rest)
    case 1n+(+p) ObjectKey{+fields} Con{Quoted{line, +key}, Con{Punct{":"}, rest}}:
      L.sel(Maybe<&2, Parsed>, has(fields, key), u => None{},
        u => Maybe.bind(&2, Parsed, Parsed, parse(p, ParseValue{}, rest), +r =>
          parse(p, ObjectNext{Con{Field{key, value(r)}, fields}}, value.rest(r))))
    case _ _ _:
      None{}

def complete(r: Parsed) -> Maybe<&2, Value>:
  match r:
    case Parsed{v, Nil{}}:
      Some{v}
    case _:
      None{}

def read(+s: String) -> Maybe<&2, Value>:
  do Maybe<&2, Value>:
    tokens : List<&2, Token> <- lex(1n+String.length(s), s, 1)
    r : Parsed <- parse(100000n, ParseValue{}, tokens)
    complete(r)

def get(fields: List<&2, Field>, +key: String) -> Maybe<&2, Value>:
  match fields:
    case Nil{}:
      None{}
    case Con{Field{name, v}, rest}:
      L.sel(Maybe<&2, Value>, String.eq(name, key), u => Some{v}, u => get(rest, key))
