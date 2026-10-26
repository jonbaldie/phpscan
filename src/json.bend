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

def surrogate(+hi: U32, s: String) -> Maybe<&2, CodeRest>:
  match s:
    case SCon{'\\', SCon{'u', rest}}:
      Maybe.bind(&2, CodeRest, CodeRest, hex4(rest), +r => (
        +lo = code(r)
        L.sel(Maybe<&2, CodeRest>, U32.is_le(56320, lo) && U32.is_le(lo, 57343),
          u => Some{CodeRest{U32.add(65536, U32.add(U32.mul(U32.sub(hi, 55296), 1024), U32.sub(lo, 56320))), code.rest(r)}}, u => None{})))
    case _:
      None{}

def unicode(+n: U32, +s: String) -> Maybe<&2, CodeRest>:
  L.sel(Maybe<&2, CodeRest>, U32.is_le(55296, n) && U32.is_le(n, 56319), u => surrogate(n, s),
    u => L.sel(Maybe<&2, CodeRest>, U32.is_le(56320, n) && U32.is_le(n, 57343), v => None{}, v => Some{CodeRest{n, s}}))

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
        Maybe.bind(&2, CodeRest, StringRest, unicode(code(r), code.rest(r)), +d =>
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

def number(s: String, +state: U32) -> Bool:
  match s:
    case SNil{}:
      U32.is_eq(state, 2) || U32.is_eq(state, 3) || U32.is_eq(state, 5) || U32.is_eq(state, 8)
    case SCon{+c, rest}:
      +digit = Char.is_digit(c)
      +nonzero = digit && Bool.not(Char.is_eq(c, '0'))
      +exp = Char.is_eq(c, 'e') || Char.is_eq(c, 'E')
      +sign = Char.is_eq(c, '+') || Char.is_eq(c, '-')
      next = L.sel(U32, U32.is_eq(state, 0) && Char.is_eq(c, '-'), u => 1,
        u => L.sel(U32, (U32.is_eq(state, 0) || U32.is_eq(state, 1)) && Char.is_eq(c, '0'), v => 2,
          v => L.sel(U32, (U32.is_eq(state, 0) || U32.is_eq(state, 1) || U32.is_eq(state, 3)) && nonzero, w => 3,
            w => L.sel(U32, U32.is_eq(state, 3) && digit, x => 3,
              x => L.sel(U32, (U32.is_eq(state, 2) || U32.is_eq(state, 3)) && Char.is_eq(c, '.'), y => 4,
                y => L.sel(U32, (U32.is_eq(state, 4) || U32.is_eq(state, 5)) && digit, z => 5,
                  z => L.sel(U32, (U32.is_eq(state, 2) || U32.is_eq(state, 3) || U32.is_eq(state, 5)) && exp, a => 6,
                    a => L.sel(U32, U32.is_eq(state, 6) && sign, b => 7,
                      b => L.sel(U32, (U32.is_eq(state, 6) || U32.is_eq(state, 7) || U32.is_eq(state, 8)) && digit, d => 8, d => 99)))))))))
      number(rest, next)

def lex(fuel: Nat, s: String, +line: U32) -> Maybe<&2, List<&2, Token>>:
  match fuel s:
    case 1n+p SNil{}:
      Some{[]}
    case 1n+(+p) SCon{'"', rest}:
      Maybe.bind(&2, StringRest, List<&2, Token>, quoted(p, rest, []), +r =>
        do Maybe<&2, List<&2, Token>>:
          tokens : List<&2, Token> <- lex(p, text.rest(r), line)
          return Con{Quoted{line, text(r)}, tokens})
    case 1n+(+p) SCon{+c, +rest}:
      L.sel(Maybe<&2, List<&2, Token>>, space(c),
        u => lex(p, rest, L.sel(U32, Char.is_eq(c, '\n'), v => U32.add(line, 1), v => line)),
        u => L.sel(Maybe<&2, List<&2, Token>>, punct(c),
          v => do Maybe<&2, List<&2, Token>>:
            tokens : List<&2, Token> <- lex(p, rest, line)
            return Con{Punct{SCon{c, SNil{}}}, tokens},
          v => (
            +r = raw(SCon{c, rest}, [])
            +t = text(r)
            L.sel(Maybe<&2, List<&2, Token>>, String.eq(t, "true") || String.eq(t, "false") || String.eq(t, "null") || number(t, 0),
              w => do Maybe<&2, List<&2, Token>>:
                tokens : List<&2, Token> <- lex(p, text.rest(r), line)
                return Con{Literal{}, tokens}, w => None{}))))
    case _ _:
      None{}

def has(fields: List<&2, Field>, +key: String) -> Bool:
  match fields:
    case Nil{}:
      False{}
    case Con{Field{name, v}, rest}:
      String.eq(name, key) || has(rest, key)

def parse(fuel: Nat, mode: U32, ts: List<&2, Token>, acc: Value) -> Maybe<&2, Parsed>:
  match fuel mode ts acc:
    case 1n+p 0 Con{Quoted{line, v}, rest} _:
      Some{Parsed{Str{line, v}, rest}}
    case 1n+p 0 Con{Literal{}, rest} _:
      Some{Parsed{Other{}, rest}}
    case 1n+p 0 Con{Punct{"["}, rest} _:
      parse(p, 1, rest, Array{[]})
    case 1n+p 0 Con{Punct{"{"}, rest} _:
      parse(p, 3, rest, Object{[]})
    case 1n+p 1 Con{Punct{"]"}, rest} Array{values}:
      Some{Parsed{Array{List.reverse(&2, Value, values)}, rest}}
    case 1n+(+p) 1 +tokens Array{values}:
      Maybe.bind(&2, Parsed, Parsed, parse(p, 0, tokens, Other{}), +r =>
        parse(p, 2, value.rest(r), Array{Con{value(r), values}}))
    case 1n+p 2 Con{Punct{"]"}, rest} Array{values}:
      Some{Parsed{Array{List.reverse(&2, Value, values)}, rest}}
    case 1n+(+p) 2 Con{Punct{","}, rest} Array{values}:
      Maybe.bind(&2, Parsed, Parsed, parse(p, 0, rest, Other{}), +r =>
        parse(p, 2, value.rest(r), Array{Con{value(r), values}}))
    case 1n+p 3 Con{Punct{"}"}, rest} Object{fields}:
      Some{Parsed{Object{List.reverse(&2, Field, fields)}, rest}}
    case 1n+p 3 +tokens Object{fields}:
      parse(p, 5, tokens, Object{fields})
    case 1n+p 4 Con{Punct{"}"}, rest} Object{fields}:
      Some{Parsed{Object{List.reverse(&2, Field, fields)}, rest}}
    case 1n+p 4 Con{Punct{","}, rest} Object{fields}:
      parse(p, 5, rest, Object{fields})
    case 1n+(+p) 5 Con{Quoted{line, +key}, Con{Punct{":"}, rest}} Object{+fields}:
      L.sel(Maybe<&2, Parsed>, has(fields, key), u => None{},
        u => Maybe.bind(&2, Parsed, Parsed, parse(p, 0, rest, Other{}), +r =>
          parse(p, 4, value.rest(r), Object{Con{Field{key, value(r)}, fields}})))
    case _ _ _ _:
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
    r : Parsed <- parse(100000n, 0, tokens, Other{})
    complete(r)

def get(fields: List<&2, Field>, +key: String) -> Maybe<&2, Value>:
  match fields:
    case Nil{}:
      None{}
    case Con{Field{name, v}, rest}:
      L.sel(Maybe<&2, Value>, String.eq(name, key), u => Some{v}, u => get(rest, key))
