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

# What a sub-lexer answers: the rest of the input, the line it ends on, the
# text it read and a small code (meaning depends on the sub-lexer).
type Cut is Data:
  Cut{rest: String, line: U32, text: String, n: U32}

# One step of the main loop: the rest, the line, and tokens newest first.
type Step is Data:
  Step{rest: String, line: U32, toks: List<&2, Tok>}

# Interpolation scanner state (double quotes, backticks, heredocs).
#   mode 0 text, 1 in $name, 2 in {$name, 3 skipping {..} expr, 4 in ${name,
#   5 after '$', 6 after '{', 7 after '\', 99 finished
type Q is Data:
  Q{mode: U32, line: U32, name: String, vars: String, lit: String, depth: U32}

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

# Inline HTML until an open tag. n: 0 end of input, 1 <?php, 2 <?=
def html(s: String, +line: U32) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, line, "", 0}
    case SCon{'<', SCon{'?', SCon{'=', t}}}:
      Cut{t, line, "", 2}
    case SCon{'<', SCon{'?', SCon{'p', SCon{'h', SCon{'p', t}}}}}:
      Cut{t, line, "", 1}
    case SCon{'<', SCon{'?', SCon{'P', SCon{'H', SCon{'P', t}}}}}:
      Cut{t, line, "", 1}
    case SCon{'\n', t}:
      html(t, (line + 1 : U32))
    case SCon{c, t}:
      html(t, line)

# A line comment ends before a newline or a '?>'. text is reversed.
def lcomment(s: String, +line: U32, acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, line, acc, 0}
    case SCon{'\n', t}:
      Cut{SCon{'\n', t}, line, acc, 0}
    case SCon{'?', SCon{'>', t}}:
      Cut{SCon{'?', SCon{'>', t}}, line, acc, 0}
    case SCon{c, t}:
      lcomment(t, line, SCon{c, acc})

# A block comment ends after '*/'. text is reversed.
def bcomment(s: String, +line: U32, acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, line, acc, 0}
    case SCon{'*', SCon{'/', t}}:
      Cut{t, line, acc, 0}
    case SCon{'\n', t}:
      bcomment(t, (line + 1 : U32), SCon{'\n', acc})
    case SCon{c, t}:
      bcomment(t, line, SCon{c, acc})

def single(s: String, +line: U32, acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, line, String.reverse(acc), 0}
    case SCon{'\\', SCon{'\'', t}}:
      single(t, line, SCon{'\'', acc})
    case SCon{'\\', SCon{'\\', t}}:
      single(t, line, SCon{'\\', acc})
    case SCon{'\'', t}:
      Cut{t, line, String.reverse(acc), 0}
    case SCon{'\n', t}:
      single(t, (line + 1 : U32), SCon{'\n', acc})
    case SCon{c, t}:
      single(t, line, SCon{c, acc})

# Interpolation scanner transitions.
def q.var(name: String, vars: String) -> String:
  String.reverse(name) ++ " " ++ vars

def q.text.ch(+c: Char, +line: U32, name: String, vars: String, lit: String) -> Q:
  match c:
    case '\\':
      Q{7, line, name, vars, lit, 0}
    case '$':
      Q{5, line, name, vars, lit, 0}
    case '{':
      Q{6, line, name, vars, lit, 0}
    case '\n':
      Q{0, (line + 1 : U32), name, vars, SCon{'\n', lit}, 0}
    case c:
      Q{0, line, name, vars, SCon{c, lit}, 0}

def q.text.go(fin: Bool, +c: Char, +line: U32, name: String, vars: String, lit: String) -> Q:
  match fin:
    case True{}:
      Q{99, line, name, vars, lit, 0}
    case False{}:
      q.text.ch(c, line, name, vars, lit)

# The mode-0 transition on c (shared by states that hand a char back to text).
def q.text(+c: Char, +term: U32, +line: U32, name: String, vars: String, lit: String) -> Q:
  q.text.go(U32.is_eq(code(c), term), c, line, name, vars, lit)

def q.skip.close(last: Bool, +line: U32, name: String, vars: String, lit: String, +depth: U32) -> Q:
  match last:
    case True{}:
      Q{0, line, name, vars, lit, 0}
    case False{}:
      Q{3, line, name, vars, lit, (depth - 1 : U32)}

# Skipping a {...} expression: depth counts open braces.
def q.skip(+c: Char, +line: U32, name: String, vars: String, lit: String, +depth: U32) -> Q:
  match c:
    case '}':
      q.skip.close(U32.is_eq(depth, 1), line, name, vars, lit, depth)
    case '{':
      Q{3, line, name, vars, lit, (depth + 1 : U32)}
    case '\n':
      Q{3, (line + 1 : U32), name, vars, lit, depth}
    case _:
      Q{3, line, name, vars, lit, depth}

# In $name: a name char extends it; anything else ends it and is text.
def q.name(more: Bool, +c: Char, +term: U32, +line: U32, name: String, vars: String, lit: String) -> Q:
  match more:
    case True{}:
      Q{1, line, SCon{c, name}, vars, lit, 0}
    case False{}:
      q.text(c, term, line, SNil{}, q.var(name, vars), lit)

# In {$name: a name char extends it; anything else ends it, then skip to '}'.
def q.cname(more: Bool, +c: Char, +line: U32, name: String, vars: String, lit: String) -> Q:
  match more:
    case True{}:
      Q{2, line, SCon{c, name}, vars, lit, 0}
    case False{}:
      q.skip(c, line, SNil{}, q.var(name, vars), lit, 1)

# In ${name: '}' ends it; a name char extends it; else skip to '}'.
def q.dname(more: Bool, +c: Char, +line: U32, name: String, vars: String, lit: String) -> Q:
  match more:
    case True{}:
      Q{4, line, SCon{c, name}, vars, lit, 0}
    case False{}:
      q.skip(c, line, SNil{}, q.var(name, vars), lit, 1)

def q.dollar.brace(+c: Char, +term: U32, +line: U32, name: String, vars: String, lit: String) -> Q:
  match c:
    case '{':
      Q{4, line, SNil{}, vars, lit, 0}
    case c:
      q.text(c, term, line, name, vars, SCon{'$', lit})

# After '$': a name start opens $name, '{' opens ${name}, else '$' is text.
def q.dollar(start: Bool, +c: Char, +term: U32, +line: U32, name: String, vars: String, lit: String) -> Q:
  match start:
    case True{}:
      Q{1, line, SCon{c, SNil{}}, vars, lit, 0}
    case False{}:
      q.dollar.brace(c, term, line, name, vars, lit)

# After '{': '$' opens {$name, else '{' is text.
def q.brace(+c: Char, +term: U32, +line: U32, name: String, vars: String, lit: String) -> Q:
  match c:
    case '$':
      Q{2, line, SNil{}, vars, lit, 0}
    case c:
      q.text(c, term, line, name, vars, SCon{'{', lit})

def q.step(q: Q, +c: Char, +term: U32) -> Q:
  match q:
    case Q{0, line, name, vars, lit, d}:
      q.text(c, term, line, name, vars, lit)
    case Q{1, line, name, vars, lit, d}:
      q.name(is_name_char(c), c, term, line, name, vars, lit)
    case Q{2, line, name, vars, lit, d}:
      q.cname(is_name_char(c), c, line, name, vars, lit)
    case Q{3, line, name, vars, lit, d}:
      q.skip(c, line, name, vars, lit, d)
    case Q{4, line, name, vars, lit, d}:
      q.dname(is_name_char(c), c, line, name, vars, lit)
    case Q{5, line, name, vars, lit, d}:
      q.dollar(is_name_start(c), c, term, line, name, vars, lit)
    case Q{6, line, name, vars, lit, d}:
      q.brace(c, term, line, name, vars, lit)
    case Q{7, line, name, vars, lit, d}:
      Q{0, (line + nl(c) : U32), name, vars, SCon{c, lit}, 0}
    case Q{m, line, name, vars, lit, d}:
      Q{m, line, name, vars, lit, d}

# Close the scan: n = 1 when any variable was interpolated. text is the
# variable list when n = 1, else the literal contents.
def q.done(rest: String, q: Q) -> Cut:
  match q:
    case Q{1, line, name, vars, lit, d}:
      Cut{rest, line, q.var(name, vars), 1}
    case Q{m, line, name, SNil{}, lit, d}:
      Cut{rest, line, String.reverse(lit), 0}
    case Q{m, line, name, vars, lit, d}:
      Cut{rest, line, vars, 1}

# Scan an interpolating string up to the char with code term (0: to the end).
def interp(s: String, +term: U32, q: Q) -> Cut:
  match s q:
    case s Q{99, line, name, vars, lit, d}:
      q.done(s, Q{99, line, name, vars, lit, d})
    case SNil{} q:
      q.done(SNil{}, q)
    case SCon{+c, t} q:
      interp(t, term, q.step(q, c, term))

def interp.start(s: String, +term: U32, +line: U32) -> Cut:
  interp(s, term, Q{0, line, SNil{}, SNil{}, SNil{}, 0})

# Read identifier chars (id: include '\'). text is in order.
def word(s: String, +id: Bool, +acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, 0, String.reverse(acc), 0}
    case SCon{+c, +t}:
      sel(Cut, (id && is_id_char(c)) || is_name_char(c), u => word(t, id, SCon{c, acc}), u => Cut{SCon{c, t}, 0, String.reverse(acc), 0})

# Number literal: digits, letters, '_' and '.' (covers hex, floats, 1e5).
def number(s: String, +acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, 0, String.reverse(acc), 0}
    case SCon{+c, +t}:
      sel(Cut, is_name_char(c) || U32.is_eq(code(c), 46), u => number(t, SCon{c, acc}), u => Cut{SCon{c, t}, 0, String.reverse(acc), 0})

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

def cast.close(+name: String, s: String) -> Cut:
  match s:
    case SCon{')', t}:
      Cut{t, 0, name, Bool.to_u32(is_cast(name))}
    case _:
      Cut{SNil{}, 0, "", 0}

def cast.word(w: Cut) -> Cut:
  match w:
    case Cut{rest, l, name, n}:
      cast.close(String.to_lower(name), skip_hws(rest))

# After '(': ( spaces* name spaces* ). n = 1 when it is a cast.
def cast(s: String) -> Cut:
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
def hd.body(s: String, +label: String, +line: U32, +acc: String, +bol: Bool) -> Cut:
  match s:
    case SNil{}:
      Cut{SNil{}, line, String.reverse(acc), 0}
    case SCon{+c, +t}:
      sel(Cut, bol && hd.closes(SCon{c, t}, label), u => Cut{hd.rest(SCon{c, t}, label), line, String.reverse(acc), 0}, u => hd.body(t, label, (line + nl(c) : U32), SCon{c, acc}, U32.is_eq(nl(c), 1)))

# Skip to the end of the heredoc's opening line.
def to_eol(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{'\n', t}:
      t
    case SCon{c, t}:
      to_eol(t)

def hd.label.fin(w: Cut, +n: U32) -> Cut:
  match w:
    case Cut{rest, l, name, k}:
      Cut{to_eol(rest), 0, name, n}

# n: 0 heredoc (interpolates), 1 nowdoc
def hd.label(s: String) -> Cut:
  match s:
    case SCon{'\'', t}:
      hd.label.fin(word(t, False{}, SNil{}), 1)
    case SCon{'"', t}:
      hd.label.fin(word(t, False{}, SNil{}), 0)
    case s:
      hd.label.fin(word(s, False{}, SNil{}), 0)

def hd.interp(rest: String, +line2: U32, +line: U32, c: Cut) -> Step:
  match c:
    case Cut{r, l, text, n}:
      Step{rest, line2, [tok((2 + n : U32), text, line)]}

def hd.tok(+nowdoc: U32, rest: String, +line2: U32, +line: U32, body: String) -> Step:
  match nowdoc:
    case 1:
      Step{rest, line2, [tok(2, body, line)]}
    case _:
      hd.interp(rest, line2, line, interp.start(body, 0, line))

def hd.body.fin(+nowdoc: U32, +line: U32, b: Cut) -> Step:
  match b:
    case Cut{rest, line2, body, k}:
      hd.tok(nowdoc, rest, line2, line, body)

def heredoc.go(c: Cut, +line: U32) -> Step:
  match c:
    case Cut{rest, l, label, nowdoc}:
      hd.body.fin(nowdoc, line, hd.body(rest, label, (line + 1 : U32), SNil{}, True{}))

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
    case Cut{rest, l, text, n}:
      comment.ign(String.contains(text, "erongi-nacsphp"), rest, line, l)

def string.tok(+line: U32, c: Cut) -> Step:
  match c:
    case Cut{rest, l, text, n}:
      Step{rest, l, [tok((2 + n : U32), text, line)]}

def btick.tok(+line: U32, c: Cut) -> Step:
  match c:
    case Cut{rest, l, text, n}:
      Step{rest, l, [tok(7, text, line)]}

def close_tag(c: Cut, +line: U32) -> Step:
  match c:
    case Cut{rest, +l, text, 2}:
      Step{rest, l, [op(";", line), tok(1, "echo", l)]}
    case Cut{rest, l, text, n}:
      Step{rest, l, [op(";", line)]}

def paren.go(c: Cut, s: String, +line: U32) -> Step:
  match c:
    case Cut{rest, l, name, 1}:
      Step{rest, line, [tok(6, name, line)]}
    case Cut{rest, l, name, n}:
      Step{s, line, [op("(", line)]}

def paren(+s: String, +line: U32) -> Step:
  paren.go(cast(s), s, line)

def var.tok(w: Cut, +line: U32) -> Step:
  match w:
    case Cut{rest, l, name, n}:
      Step{rest, line, [tok(0, name, line)]}

def dollar(start: Bool, s: String, +line: U32) -> Step:
  match start:
    case True{}:
      var.tok(word(s, False{}, SNil{}), line)
    case False{}:
      Step{s, line, [op("$", line)]}

def ident.tok(w: Cut, +line: U32) -> Step:
  match w:
    case Cut{rest, l, name, n}:
      Step{rest, line, [tok(1, strip_ns(String.to_lower(name)), line)]}

def num.tok(w: Cut, +line: U32) -> Step:
  match w:
    case Cut{rest, l, text, n}:
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
      string.tok(line, interp.start(t, 34, line))
    case SCon{'`', t}:
      btick.tok(line, interp.start(t, 96, line))
    case SCon{'<', SCon{'<', SCon{'<', t}}}:
      heredoc(t, line)
    case SCon{'$', SCon{+c, t}}:
      dollar(is_name_start(c), SCon{c, t}, line)
    case SCon{'(', t}:
      paren(t, line)
    case SCon{c, t}:
      other(c, t, line)

def lex.start(+n: U32, +line: U32) -> List<&2, Tok>:
  match n:
    case 2:
      [tok(1, "echo", line)]
    case _:
      []

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

def lex.begin(c: Cut) -> List<&2, Tok>:
  match c:
    case Cut{+rest, +line, text, n}:
      lex.go(String.length(rest), Step{rest, line, lex.start(n, line)}, [])

def without_ignores(ts: List<&2, Tok>) -> List<&2, Tok>:
  match ts:
    case Nil{}:
      []
    case Con{Tok{8, s, l}, rest}:
      without_ignores(rest)
    case Con{t, rest}:
      Con{t, without_ignores(rest)}

def ignored_lines(ts: List<&2, Tok>, +last: U32) -> List<&2, U32>:
  match ts:
    case Nil{}:
      []
    case Con{Tok{8, s, +l}, +rest}:
      sel(List<&2, U32>, U32.is_eq(l, last), u => Con{l, ignored_lines(rest, last)}, u => Con{U32.add(l, 1), ignored_lines(rest, last)})
    case Con{Tok{k, s, +l}, rest}:
      ignored_lines(rest, l)

def qualified.ident(w: Cut, +line: U32) -> Step:
  match w:
    case Cut{rest, l, name, n}:
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

def qualified.string.step(trusted: Bool, st: Step) -> Step:
  match trusted st:
    case False{} Step{rest, line, Con{Tok{2, text, start}, Nil{}}}:
      Step{rest, line, [tok(9, "", start)]}
    case _ st:
      st

def qualified.step(+s: String, +line: U32) -> Step:
  match s:
    case SNil{}:
      step(s, line)
    case SCon{'"', t}:
      qualified.string.step(qualified.string.raw(t), step(s, line))
    case SCon{+c, t}:
      sel(Step, is_id_start(c),
        u => qualified.ident(word(s, True{}, SNil{}), line),
        u => step(s, line))

def qualified.go(fuel: Nat, st: Step, acc: List<&2, Tok>) -> List<&2, Tok>:
  match fuel st:
    case 0n Step{r, l, ts}:
      push(ts, acc)
    case _ Step{SNil{}, l, ts}:
      push(ts, acc)
    case 1n+p Step{r, l, ts}:
      qualified.go(p, qualified.step(r, l), push(ts, acc))

def qualified.begin(c: Cut) -> List<&2, Tok>:
  match c:
    case Cut{+rest, +line, text, n}:
      qualified.go(String.length(rest), Step{rest, line, lex.start(n, line)}, [])

def qualified(src: String) -> List<&2, Tok>:
  List.reverse(&2, Tok, qualified.begin(html(src, 1)))

# Lex a whole file, which starts in inline HTML.
def lex(src: String) -> List<&2, Tok>:
  List.reverse(&2, Tok, lex.begin(html(src, 1)))
