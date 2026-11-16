import Base

# PHP lexer. Turns a source file into a flat token list.
#
# Token kinds:
#   0 VAR    text = variable name without '$'
#   1 ID     text = lowercased identifier, namespace prefix dropped
#   2 STR    text = literal string contents (no interpolation)
#   3 ISTR   text = names of interpolated variables, space separated
#   4 NUM    text = the literal
#   5 OP     text = the operator; '?>' becomes ';'
#   6 CAST   text = the cast type, e.g. "int"
#   7 BTICK  text = names of variables interpolated into a shell string
#   8 IGN    a `phpscan-ignore` comment on this line
#   9 USTR   qualified-only unsupported string; text is empty
type Tok is Data:
  Tok{kind: U32, text: String, line: U32}

type Cut is Data:
  Cut{rest: String, line: U32, text: String}

type Step is Data:
  Step{rest: String, line: U32, toks: List<&2, Tok>}

type StringContents is Data:
  LiteralText{text: String}
  InterpolatedNames{names: String}

type StringCut is Data:
  StringCut{rest: String, line: U32, contents: StringContents}

type QuoteEnd is Data:
  EndOrNul{}
  QuoteCharacter{code: U32}

type CastProbe is Data:
  CastFound{rest: String, name: String}
  NotCast{}

type QuotePhase is Data:
  QuoteText{}
  QuoteName{name: String}
  QuoteBracedName{name: String}
  QuoteSkip{depth: U32}
  QuoteDollarName{name: String}
  QuoteDollar{}
  QuoteBrace{}
  QuoteEscape{}
  QuoteFinished{}

type Q is Data:
  Q{phase: QuotePhase, line: U32, vars: String, lit: String}

type HtmlResult is Data:
  HtmlEnd{line: U32}
  PhpTag{rest: String, line: U32}
  EchoTag{rest: String, line: U32}

type DocStyle is Data:
  Heredoc{}
  Nowdoc{}

type DocLabel is Data:
  DocLabel{rest: String, label: String, style: DocStyle}

type DocPosition is Data:
  LineStart{}
  WithinLine{}

type PreviousToken is Data:
  NoPrevious{}
  PreviousLine{line: U32}

# Branch on a computed Bool without evaluating the other side.
def sel(-A: Type, d: Bool, a: Unit -> A, b: Unit -> A) -> A:
  match d:
    case True{}:
      a(Unit{})
    case False{}:
      b(Unit{})

def code(c: Char) -> U32:
  match c:
    case Chr{k}:
      k

def in_range(+k: U32, +lo: U32, +hi: U32) -> Bool:
  U32.is_ge(k, lo) && U32.is_le(k, hi)

def is_name_start_u(+k: U32) -> Bool:
  in_range(k, 97, 122) || in_range(k, 65, 90) || U32.is_eq(k, 95) || U32.is_ge(k, 128)

def is_name_start(+c: Char) -> Bool:
  is_name_start_u(code(c))

def is_name_char(+c: Char) -> Bool:
  +k = code(c)
  is_name_start_u(k) || in_range(k, 48, 57)

def is_id_start(+c: Char) -> Bool:
  +k = code(c)
  is_name_start_u(k) || U32.is_eq(k, 92)

def is_id_char(+c: Char) -> Bool:
  +k = code(c)
  is_name_start_u(k) || in_range(k, 48, 57) || U32.is_eq(k, 92)

def is_digit(+c: Char) -> Bool:
  in_range(code(c), 48, 57)

def nl(c: Char) -> U32:
  match c:
    case '\n':
      1
    case _:
      0

def tok(+kind: U32, text: String, +line: U32) -> Tok:
  Tok{kind, text, line}

def op(text: String, +line: U32) -> Tok:
  Tok{5, text, line}

# Drop a namespace prefix: \Foo\bar -> bar
def strip_ns.go(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{'\\', t}:
      strip_ns.go(t, SNil{})
    case SCon{c, t}:
      strip_ns.go(t, SCon{c, acc})

def strip_ns(s: String) -> String:
  strip_ns.go(s, SNil{})

def html(s: String, +line: U32) -> HtmlResult:
  match s:
    case SNil{}:
      HtmlEnd{line}
    case SCon{'<', SCon{'?', SCon{'=', t}}}:
      EchoTag{t, line}
    case SCon{'<', SCon{'?', SCon{'p', SCon{'h', SCon{'p', t}}}}}:
      PhpTag{t, line}
    case SCon{'<', SCon{'?', SCon{'P', SCon{'H', SCon{'P', t}}}}}:
      PhpTag{t, line}
    case SCon{'\n', t}:
      html(t, (line + 1 : U32))
    case SCon{c, t}:
      html(t, line)

# A line comment ends before a newline or a '?>'. text is reversed.
def lcomment(s: String, +line: U32, acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, line, acc}
    case SCon{'\n', t}:
      Cut{SCon{'\n', t}, line, acc}
    case SCon{'?', SCon{'>', t}}:
      Cut{SCon{'?', SCon{'>', t}}, line, acc}
    case SCon{c, t}:
      lcomment(t, line, SCon{c, acc})

# A block comment ends after '*/'. text is reversed.
def bcomment(s: String, +line: U32, acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, line, acc}
    case SCon{'*', SCon{'/', t}}:
      Cut{t, line, acc}
    case SCon{'\n', t}:
      bcomment(t, (line + 1 : U32), SCon{'\n', acc})
    case SCon{c, t}:
      bcomment(t, line, SCon{c, acc})

def single(s: String, +line: U32, acc: String) -> StringCut:
  match s:
    case SNil{}:
      StringCut{SNil{}, line, LiteralText{String.reverse(acc)}}
    case SCon{'\\', SCon{'\'', t}}:
      single(t, line, SCon{'\'', acc})
    case SCon{'\\', SCon{'\\', t}}:
      single(t, line, SCon{'\\', acc})
    case SCon{'\'', t}:
      StringCut{t, line, LiteralText{String.reverse(acc)}}
    case SCon{'\n', t}:
      single(t, (line + 1 : U32), SCon{'\n', acc})
    case SCon{c, t}:
      single(t, line, SCon{c, acc})

def q.var(name: String, vars: String) -> String:
  String.reverse(name) ++ " " ++ vars

def q.text.ch(c: Char, +line: U32, vars: String, lit: String) -> Q:
  match c:
    case '\\':
      Q{QuoteEscape{}, line, vars, lit}
    case '$':
      Q{QuoteDollar{}, line, vars, lit}
    case '{':
      Q{QuoteBrace{}, line, vars, lit}
    case '\n':
      Q{QuoteText{}, (line + 1 : U32), vars, SCon{'\n', lit}}
    case c:
      Q{QuoteText{}, line, vars, SCon{c, lit}}

def q.terminates(term: QuoteEnd, c: Char) -> Bool:
  match term:
    case EndOrNul{}:
      U32.is_eq(code(c), 0)
    case QuoteCharacter{n}:
      U32.is_eq(code(c), n)

def q.text(+c: Char, +term: QuoteEnd, +line: U32, +vars: String, +lit: String) -> Q:
  sel(Q, q.terminates(term, c), u => Q{QuoteFinished{}, line, vars, lit},
    u => q.text.ch(c, line, vars, lit))

def q.skip.braces(c: Char, +line: U32, +vars: String, +lit: String, +depth: U32) -> Q:
  match c:
    case '}':
      sel(Q, U32.is_eq(depth, 1), u => Q{QuoteText{}, line, vars, lit},
        u => Q{QuoteSkip{(depth - 1 : U32)}, line, vars, lit})
    case '{':
      Q{QuoteSkip{(depth + 1 : U32)}, line, vars, lit}
    case '\n':
      Q{QuoteSkip{depth}, (line + 1 : U32), vars, lit}
    case _:
      Q{QuoteSkip{depth}, line, vars, lit}

def q.name(+c: Char, +term: QuoteEnd, +line: U32, +name: String, +vars: String, +lit: String) -> Q:
  sel(Q, is_name_char(c), u => Q{QuoteName{SCon{c, name}}, line, vars, lit},
    u => q.text(c, term, line, q.var(name, vars), lit))

def q.cname(+c: Char, +line: U32, +name: String, +vars: String, +lit: String) -> Q:
  sel(Q, is_name_char(c), u => Q{QuoteBracedName{SCon{c, name}}, line, vars, lit},
    u => q.skip.braces(c, line, q.var(name, vars), lit, 1))

def q.dname(+c: Char, +line: U32, +name: String, +vars: String, +lit: String) -> Q:
  sel(Q, is_name_char(c), u => Q{QuoteDollarName{SCon{c, name}}, line, vars, lit},
    u => q.skip.braces(c, line, q.var(name, vars), lit, 1))

def q.dollar.brace(c: Char, +term: QuoteEnd, +line: U32, +vars: String, +lit: String) -> Q:
  match c:
    case '{':
      Q{QuoteDollarName{SNil{}}, line, vars, lit}
    case c:
      q.text(c, term, line, vars, SCon{'$', lit})

def q.dollar(+c: Char, +term: QuoteEnd, +line: U32, +vars: String, +lit: String) -> Q:
  sel(Q, is_name_start(c), u => Q{QuoteName{SCon{c, SNil{}}}, line, vars, lit},
    u => q.dollar.brace(c, term, line, vars, lit))

def q.brace(c: Char, +term: QuoteEnd, +line: U32, +vars: String, +lit: String) -> Q:
  match c:
    case '$':
      Q{QuoteBracedName{SNil{}}, line, vars, lit}
    case c:
      q.text(c, term, line, vars, SCon{'{', lit})

def q.step(q: Q, +c: Char, +term: QuoteEnd) -> Q:
  match q:
    case Q{QuoteText{}, line, vars, lit}:
      q.text(c, term, line, vars, lit)
    case Q{QuoteName{name}, line, vars, lit}:
      q.name(c, term, line, name, vars, lit)
    case Q{QuoteBracedName{name}, line, vars, lit}:
      q.cname(c, line, name, vars, lit)
    case Q{QuoteSkip{depth}, line, vars, lit}:
      q.skip.braces(c, line, vars, lit, depth)
    case Q{QuoteDollarName{name}, line, vars, lit}:
      q.dname(c, line, name, vars, lit)
    case Q{QuoteDollar{}, line, vars, lit}:
      q.dollar(c, term, line, vars, lit)
    case Q{QuoteBrace{}, line, vars, lit}:
      q.brace(c, term, line, vars, lit)
    case Q{QuoteEscape{}, line, vars, lit}:
      Q{QuoteText{}, (line + nl(c) : U32), vars, SCon{c, lit}}
    case Q{QuoteFinished{}, line, vars, lit}:
      Q{QuoteFinished{}, line, vars, lit}

def q.done(rest: String, q: Q) -> StringCut:
  match q:
    case Q{QuoteName{name}, line, vars, lit}:
      StringCut{rest, line, InterpolatedNames{q.var(name, vars)}}
    case Q{phase, line, SNil{}, lit}:
      StringCut{rest, line, LiteralText{String.reverse(lit)}}
    case Q{phase, line, vars, lit}:
      StringCut{rest, line, InterpolatedNames{vars}}

def interp(s: String, +term: QuoteEnd, q: Q) -> StringCut:
  match s q:
    case s Q{QuoteFinished{}, line, vars, lit}:
      q.done(s, Q{QuoteFinished{}, line, vars, lit})
    case SNil{} q:
      q.done(SNil{}, q)
    case SCon{+c, t} q:
      interp(t, term, q.step(q, c, term))

def interp.start(s: String, +term: QuoteEnd, +line: U32) -> StringCut:
  interp(s, term, Q{QuoteText{}, line, SNil{}, SNil{}})

# Read identifier chars (id: include '\'). text is in order.
def word(s: String, +id: Bool, +acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, 0, String.reverse(acc)}
    case SCon{+c, +t}:
      sel(Cut, (id && is_id_char(c)) || is_name_char(c), u => word(t, id, SCon{c, acc}), u => Cut{SCon{c, t}, 0, String.reverse(acc)})

# Number literal: digits, letters, '_' and '.' (covers hex, floats, 1e5).
def number(s: String, +acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, 0, String.reverse(acc)}
    case SCon{+c, +t}:
      sel(Cut, is_name_char(c) || U32.is_eq(code(c), 46), u => number(t, SCon{c, acc}), u => Cut{SCon{c, t}, 0, String.reverse(acc)})

def skip_hws(s: String) -> String:
  match s:
    case SCon{' ', t}:
      skip_hws(t)
    case SCon{'\t', t}:
      skip_hws(t)
    case s:
      s

def skip_ws(s: String) -> String:
  match s:
    case SCon{' ', t}:
      skip_ws(t)
    case SCon{'\t', t}:
      skip_ws(t)
    case SCon{'\n', t}:
      skip_ws(t)
    case SCon{'\r', t}:
      skip_ws(t)
    case s:
      s

def is_cast(s: String) -> Bool:
  match s:
    case "int":
      True{}
    case "integer":
      True{}
    case "bool":
      True{}
    case "boolean":
      True{}
    case "float":
      True{}
    case "double":
      True{}
    case "real":
      True{}
    case "string":
      True{}
    case "binary":
      True{}
    case "array":
      True{}
    case "object":
      True{}
    case "unset":
      True{}
    case "void":
      True{}
    case _:
      False{}

def cast.close(+name: String, s: String) -> CastProbe:
  match s:
    case SCon{')', +t}:
      sel(CastProbe, is_cast(name), u => CastFound{t, name}, u => NotCast{})
    case _:
      NotCast{}

def cast.word(w: Cut) -> CastProbe:
  match w:
    case Cut{rest, l, name}:
      cast.close(String.to_lower(name), skip_hws(rest))

def cast(s: String) -> CastProbe:
  cast.word(word(skip_hws(s), False{}, SNil{}))

def hd.after_ok(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{c, t}:
      Bool.not(is_name_char(c))

# Heredoc: does a line (from its start) close with label?
def hd.closes(s: String, +label: String) -> Bool:
  +t = skip_hws(s)
  String.starts_with(t, label) && hd.after_ok(String.drop(t, String.length(label)))

def hd.rest(s: String, +label: String) -> String:
  String.drop(skip_hws(s), String.length(label))

# Heredoc body: raw text up to the closing label line.
def hd.position(c: Char) -> DocPosition:
  match c:
    case '\n':
      LineStart{}
    case _:
      WithinLine{}

def hd.at_start(position: DocPosition, s: String, label: String) -> Bool:
  match position:
    case LineStart{}:
      hd.closes(s, label)
    case WithinLine{}:
      False{}

def hd.body(s: String, +label: String, +line: U32, +acc: String, position: DocPosition) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, line, String.reverse(acc)}
    case SCon{+c, +t}:
      sel(Cut, hd.at_start(position, SCon{c, t}, label),
        u => Cut{hd.rest(SCon{c, t}, label), line, String.reverse(acc)},
        u => hd.body(t, label, (line + nl(c) : U32), SCon{c, acc}, hd.position(c)))

# Skip to the end of the heredoc's opening line.
def to_eol(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{'\n', t}:
      t
    case SCon{c, t}:
      to_eol(t)

def hd.label.fin(w: Cut, style: DocStyle) -> DocLabel:
  match w:
    case Cut{rest, l, name}:
      DocLabel{to_eol(rest), name, style}

def hd.label(s: String) -> DocLabel:
  match s:
    case SCon{'\'', t}:
      hd.label.fin(word(t, False{}, SNil{}), Nowdoc{})
    case SCon{'"', t}:
      hd.label.fin(word(t, False{}, SNil{}), Heredoc{})
    case s:
      hd.label.fin(word(s, False{}, SNil{}), Heredoc{})

def string.kind(contents: StringContents, +line: U32) -> Tok:
  match contents:
    case LiteralText{text}:
      tok(2, text, line)
    case InterpolatedNames{names}:
      tok(3, names, line)

def string.text(contents: StringContents) -> String:
  match contents:
    case LiteralText{text}:
      text
    case InterpolatedNames{names}:
      names

def hd.interp(rest: String, +line2: U32, +line: U32, c: StringCut) -> Step:
  match c:
    case StringCut{r, l, contents}:
      Step{rest, line2, [string.kind(contents, line)]}

def hd.tok(style: DocStyle, rest: String, +line2: U32, +line: U32, body: String) -> Step:
  match style:
    case Nowdoc{}:
      Step{rest, line2, [tok(2, body, line)]}
    case Heredoc{}:
      hd.interp(rest, line2, line, interp.start(body, EndOrNul{}, line))

def hd.body.fin(style: DocStyle, +line: U32, b: Cut) -> Step:
  match b:
    case Cut{rest, line2, body}:
      hd.tok(style, rest, line2, line, body)

def heredoc.go(c: DocLabel, +line: U32) -> Step:
  match c:
    case DocLabel{rest, label, style}:
      hd.body.fin(style, line, hd.body(rest, label, (line + 1 : U32), SNil{}, LineStart{}))

def heredoc(s: String, +line: U32) -> Step:
  heredoc.go(hd.label(skip_hws(s)), line)

def comment.ign(ign: Bool, rest: String, +line: U32, +line2: U32) -> Step:
  match ign:
    case True{}:
      Step{rest, line2, [tok(8, "", line)]}
    case False{}:
      Step{rest, line2, []}

# A comment becomes an IGN token when it says phpscan-ignore.
def comment(c: Cut, +line: U32) -> Step:
  match c:
    case Cut{rest, l, text}:
      comment.ign(String.contains(text, "erongi-nacsphp"), rest, line, l)

def string.tok(+line: U32, c: StringCut) -> Step:
  match c:
    case StringCut{rest, l, contents}:
      Step{rest, l, [string.kind(contents, line)]}

def btick.tok(+line: U32, c: StringCut) -> Step:
  match c:
    case StringCut{rest, l, contents}:
      Step{rest, l, [tok(7, string.text(contents), line)]}

def close_tag(c: HtmlResult, +line: U32) -> Step:
  match c:
    case EchoTag{rest, +l}:
      Step{rest, l, [op(";", line), tok(1, "echo", l)]}
    case PhpTag{rest, l}:
      Step{rest, l, [op(";", line)]}
    case HtmlEnd{l}:
      Step{SNil{}, l, [op(";", line)]}

def paren.go(c: CastProbe, s: String, +line: U32) -> Step:
  match c:
    case CastFound{rest, name}:
      Step{rest, line, [tok(6, name, line)]}
    case NotCast{}:
      Step{s, line, [op("(", line)]}

def paren(+s: String, +line: U32) -> Step:
  paren.go(cast(s), s, line)

def var.tok(w: Cut, +line: U32) -> Step:
  match w:
    case Cut{rest, l, name}:
      Step{rest, line, [tok(0, name, line)]}

def dollar(start: Bool, s: String, +line: U32) -> Step:
  match start:
    case True{}:
      var.tok(word(s, False{}, SNil{}), line)
    case False{}:
      Step{s, line, [op("$", line)]}

def ident.tok(w: Cut, +line: U32) -> Step:
  match w:
    case Cut{rest, l, name}:
      Step{rest, line, [tok(1, strip_ns(String.to_lower(name)), line)]}

def num.tok(w: Cut, +line: U32) -> Step:
  match w:
    case Cut{rest, l, text}:
      Step{rest, line, [tok(4, text, line)]}

# Operators, longest first.
def ops() -> List<&2, String>:
  ["<<=", ">>=", "**=", "...", "<=>", "===", "!==", "??=", "?->",
   "<<", ">>", "**", "->", "=>", "::", "==", "!=", "<>", "<=", ">=", "&&", "||",
   "??", "++", "--", "+=", "-=", "*=", "/=", ".=", "%=", "&=", "|=", "^=", "|>"]

def op.find(+s: String, xs: List<&2, String>) -> String:
  match xs:
    case Nil{}:
      String.take(s, 1n)
    case Con{+o, t}:
      sel(String, String.starts_with(s, o), u => o, u => op.find(s, t))

def op.tok(+s: String, +line: U32) -> Step:
  +o = op.find(s, ops())
  Step{String.drop(s, String.length(o)), line, [op(o, line)]}

def other(+c: Char, +t: String, +line: U32) -> Step:
  sel(Step, is_id_start(c), u => ident.tok(word(SCon{c, t}, True{}, SNil{}), line), u => sel(Step, is_digit(c), u => num.tok(number(SCon{c, t}, SNil{}), line), u => op.tok(SCon{c, t}, line)))

def step(s: String, +line: U32) -> Step:
  match s:
    case SNil{}:
      Step{SNil{}, line, []}
    case SCon{'\n', t}:
      Step{t, (line + 1 : U32), []}
    case SCon{' ', t}:
      Step{t, line, []}
    case SCon{'\t', t}:
      Step{t, line, []}
    case SCon{'\r', t}:
      Step{t, line, []}
    case SCon{'?', SCon{'>', t}}:
      close_tag(html(t, line), line)
    case SCon{'/', SCon{'/', t}}:
      comment(lcomment(t, line, SNil{}), line)
    case SCon{'#', SCon{'[', t}}:
      Step{t, line, [op("#[", line)]}
    case SCon{'#', t}:
      comment(lcomment(t, line, SNil{}), line)
    case SCon{'/', SCon{'*', t}}:
      comment(bcomment(t, line, SNil{}), line)
    case SCon{'\'', t}:
      string.tok(line, single(t, line, SNil{}))
    case SCon{'"', t}:
      string.tok(line, interp.start(t, QuoteCharacter{34}, line))
    case SCon{'`', t}:
      btick.tok(line, interp.start(t, QuoteCharacter{96}, line))
    case SCon{'<', SCon{'<', SCon{'<', t}}}:
      heredoc(t, line)
    case SCon{'$', SCon{+c, t}}:
      dollar(is_name_start(c), SCon{c, t}, line)
    case SCon{'(', t}:
      paren(t, line)
    case SCon{c, t}:
      other(c, t, line)

# Prepend ts reversed (the accumulator is newest first).
def push(ts: List<&2, Tok>, acc: List<&2, Tok>) -> List<&2, Tok>:
  match ts:
    case Nil{}:
      acc
    case Con{h, t}:
      push(t, Con{h, acc})

def lex.go(fuel: Nat, st: Step, acc: List<&2, Tok>) -> List<&2, Tok>:
  match fuel st:
    case 0n Step{r, l, ts}:
      push(ts, acc)
    case _ Step{SNil{}, l, ts}:
      push(ts, acc)
    case 1n+p Step{r, l, ts}:
      lex.go(p, step(r, l), push(ts, acc))

def lex.begin(c: HtmlResult) -> List<&2, Tok>:
  match c:
    case HtmlEnd{line}:
      []
    case PhpTag{+rest, +line}:
      lex.go(String.length(rest), Step{rest, line, []}, [])
    case EchoTag{+rest, +line}:
      lex.go(String.length(rest), Step{rest, line, [tok(1, "echo", line)]}, [])

def without_ignores(ts: List<&2, Tok>) -> List<&2, Tok>:
  match ts:
    case Nil{}:
      []
    case Con{Tok{8, s, l}, rest}:
      without_ignores(rest)
    case Con{t, rest}:
      Con{t, without_ignores(rest)}

def ignored.same_or_initial_zero(previous: PreviousToken, +line: U32) -> Bool:
  match previous:
    case NoPrevious{}:
      U32.is_eq(line, 0)
    case PreviousLine{last}:
      U32.is_eq(line, last)

def ignored_lines.go(ts: List<&2, Tok>, +previous: PreviousToken) -> List<&2, U32>:
  match ts:
    case Nil{}:
      []
    case Con{Tok{8, s, +l}, +rest}:
      sel(List<&2, U32>, ignored.same_or_initial_zero(previous, l),
        u => Con{l, ignored_lines.go(rest, previous)},
        u => Con{U32.add(l, 1), ignored_lines.go(rest, previous)})
    case Con{Tok{k, s, +l}, rest}:
      ignored_lines.go(rest, PreviousLine{l})

def ignored_lines(ts: List<&2, Tok>) -> List<&2, U32>:
  ignored_lines.go(ts, NoPrevious{})

def qualified.ident(w: Cut, +line: U32) -> Step:
  match w:
    case Cut{rest, l, name}:
      Step{rest, line, [tok(1, String.to_lower(name), line)]}

def qualified.string.raw(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{'\\', t}:
      False{}
    case SCon{'"', t}:
      True{}
    case SCon{c, t}:
      qualified.string.raw(t)

def qualified.string.tokens(ts: List<&2, Tok>) -> List<&2, Tok>:
  match ts:
    case Nil{}:
      []
    case Con{Tok{2, text, line}, rest}:
      Con{tok(9, "", line), qualified.string.tokens(rest)}
    case Con{t, rest}:
      Con{t, qualified.string.tokens(rest)}

def qualified.string.step(trusted: Bool, st: Step) -> Step:
  match trusted st:
    case False{} Step{rest, line, ts}:
      Step{rest, line, qualified.string.tokens(ts)}
    case _ st:
      st

def qualified.step(+s: String, +line: U32) -> Step:
  match s:
    case SNil{}:
      qualified.string.step(False{}, step(s, line))
    case SCon{'\'', t}:
      step(s, line)
    case SCon{'"', t}:
      qualified.string.step(qualified.string.raw(t), step(s, line))
    case SCon{+c, t}:
      sel(Step, is_id_start(c),
        u => qualified.ident(word(s, True{}, SNil{}), line),
        u => qualified.string.step(False{}, step(s, line)))

def qualified.go(fuel: Nat, st: Step, acc: List<&2, Tok>) -> List<&2, Tok>:
  match fuel st:
    case 0n Step{r, l, ts}:
      push(ts, acc)
    case _ Step{SNil{}, l, ts}:
      push(ts, acc)
    case 1n+p Step{r, l, ts}:
      qualified.go(p, qualified.step(r, l), push(ts, acc))

def qualified.begin(c: HtmlResult) -> List<&2, Tok>:
  match c:
    case HtmlEnd{line}:
      []
    case PhpTag{+rest, +line}:
      qualified.go(String.length(rest), Step{rest, line, []}, [])
    case EchoTag{+rest, +line}:
      qualified.go(String.length(rest), Step{rest, line, [tok(1, "echo", line)]}, [])

def qualified(src: String) -> List<&2, Tok>:
  List.reverse(&2, Tok, qualified.begin(html(src, 1)))

# Lex a whole file, which starts in inline HTML.
def lex(src: String) -> List<&2, Tok>:
  List.reverse(&2, Tok, lex.begin(html(src, 1)))
