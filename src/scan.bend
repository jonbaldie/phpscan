import Base
import ./lex.bend as L
import ./tree.bend as T

# Taint analysis over the bracket tree.
#
# A taint is a U32 of vulnerability classes the value can still reach:
#   1 sql  2 cmd  4 code  8 xss  16 file  32 include  64 ssrf  128 deser
#   256 header  512 varoverwrite
# Request input carries all of them (1023). A sanitizer clears the classes it
# defends; a sink reports when its class bit is still set.

type Finding is Data:
  Finding{line: U32, cls: U32, sink: String}

# Analysis state: variable taints, findings, returned taints, and sink classes
# reached after a decoder restored a function parameter's taint.
type St is Data:
  St{env: Map<&2, U32>, fs: List<&2, Finding>, ret: U32, revived: U32}

# A result: the value's taint, argument taints (for argument lists), state.
type Res is Data:
  Res{t: U32, ts: List<&2, U32>, st: St}

# Function summary: taint returned with clean arguments, then per argument
# the classes that flow to the return value or reach sinks, normally or after
# a decoder restores taint cleared by the caller.
type Sum is Data:
  NoSum{}
  Sum{src: U32, props: List<&2, U32>, sinks: List<&2, U32>, revived: List<&2, U32>}

type Seed is Data:
  SrcSeed{}
  MarkerSeed{}

# A builtin model. result = (OR of args in ra, minus clr) | src, plus the
# receiver when rcv is 1. Reports cls sc when the OR of args in sa has it.
type Model is Data:
  Model{sc: U32, sa: U32, ra: U32, clr: U32, src: U32, rcv: U32}

type Two is Data:
  Two{a: List<&2, T.Node>, b: List<&2, T.Node>}

type Sp is Data:
  Sp{lhs: List<&2, T.Node>, op: String, rhs: List<&2, T.Node>}

type Three is Data:
  Three{a: List<&2, T.Node>, b: List<&2, T.Node>, c: List<&2, T.Node>}

# A pending call: kind 0 function, 1 method, 2 static method, 3 dynamic.
type CallI is Data:
  CallI{kind: U32, name: String, cls: String, line: U32, recv: U32, spec: U32, cb: String, args: List<&2, T.Node>, rest: List<&2, T.Node>}

type Param is Data:
  Param{name: String, num: Bool}

type Decl is Data:
  Decl{key: String, ps: List<&2, Param>, body: List<&2, T.Node>}

# ---------------------------------------------------------------- basics

def ALL() -> U32:
  4294967295

def SRC() -> U32:
  1023

# Internal summary-only marker for request taint, not a vulnerability class.
def SUMMARY_MARKER() -> U32:
  1024

# Internal flag marking taint restored by a decoder during summary analysis.
def RESTORED() -> U32:
  2048

def tor(a: U32, b: U32) -> U32:
  U32.or(a, b)

def tclr(a: U32, c: U32) -> U32:
  U32.and(a, U32.not(c))

def nz(a: U32) -> Bool:
  Bool.not(U32.is_zero(a))

def b2t(b: Bool, +t: U32) -> U32:
  match b:
    case True{}:
      t
    case False{}:
      0

def env.snd(r: Map<&2, U32> & U32) -> U32:
  match r:
    case (m, v):
      v

def env.get(env: Map<&2, U32>, key: String, +d: U32) -> U32:
  env.snd(Map.get(U32, d, env, key))

def env.set(env: Map<&2, U32>, key: String, +t: U32) -> Map<&2, U32>:
  Map.set(&2, U32, env, key, t)

def env.join.go(kvs: List<&2, Sigma<&2, &2, String, _ => U32>>, +pre: Map<&2, U32>) -> Map<&2, U32>:
  match kvs:
    case Nil{}:
      pre
    case Con{(+k, +v), t}:
      env.join.go(t, env.set(pre, k, tor(v, env.get(pre, k, 0))))

# Pointwise OR: a variable after a branch may hold either value.
def env.join(pre: Map<&2, U32>, post: Map<&2, U32>) -> Map<&2, U32>:
  env.join.go(Map.to_list(&2, U32, post), pre)

def sum.snd(r: Map<&2, Sum> & Sum) -> Sum:
  match r:
    case (m, v):
      v

def sum.get(sums: Map<&2, Sum>, key: String) -> Sum:
  sum.snd(Map.get(Sum, NoSum{}, sums, key))

def or_list(ts: List<&2, U32>) -> U32:
  match ts:
    case Nil{}:
      0
    case Con{t, rest}:
      tor(t, or_list(rest))

# OR of the taints whose position bit is set in mask.
def mask_or(ts: List<&2, U32>, +mask: U32) -> U32:
  match ts:
    case Nil{}:
      0
    case Con{t, rest}:
      tor(b2t(nz(U32.and(mask, 1)), t), mask_or(rest, U32.shr(mask)))

def tail(ts: List<&2, U32>) -> List<&2, U32>:
  match ts:
    case Nil{}:
      []
    case Con{t, rest}:
      rest

def fs.add(+fs: List<&2, Finding>, +line: U32, +cls: U32, sink: String) -> List<&2, Finding>:
  L.sel(List<&2, Finding>, nz(cls), u => Con{Finding{line, cls, sink}, fs}, u => fs)

def is.restored(taint: U32) -> Bool:
  nz(U32.and(taint, RESTORED()))

# Encode sink classes reached after decoding above bit 9 for summary extraction.
def sink.bits(+taint: U32, cls: U32) -> U32:
  +hit = U32.and(taint, cls)
  +factor = U32.add(1, b2t(is.restored(taint), 1024))
  U32.mul(hit, factor)

# One finding per class bit set in bits.
def fs.bits(n: Nat, +bits: U32, +bit: U32, +fs: List<&2, Finding>, +line: U32, +sink: String) -> List<&2, Finding>:
  match n:
    case 0n:
      fs
    case 1n+p:
      fs.bits(p, bits, U32.shl(bit), fs.add(fs, line, U32.and(bits, bit), sink), line, sink)

def st.find(st: St, +line: U32, +bits: U32, +sink: String) -> St:
  match st:
    case St{env, fs, ret, revived}:
      +normal = U32.and(bits, SRC())
      +restore = U32.and(U32.shrn(bits, 10n), SRC())
      St{env, fs.bits(10n, U32.or(normal, restore), 1, fs, line, sink), ret, tor(revived, restore)}

def st.ret(st: St, +t: U32) -> St:
  match st:
    case St{env, fs, ret, revived}:
      St{env, fs, tor(ret, t), revived}

def st.env(st: St) -> Map<&2, U32>:
  match st:
    case St{env, fs, ret, revived}:
      env

def st.revived(st: St) -> U32:
  match st:
    case St{env, fs, ret, revived}:
      revived

# ---------------------------------------------------------------- nodes

def leaf_is(n: T.Node, +kind: U32, +text: String) -> Bool:
  match n:
    case T.Leaf{L.Tok{k, s, l}}:
      U32.is_eq(k, kind) && String.eq(s, text)
    case T.Grp{k, l, ks}:
      False{}

def is_op(+n: T.Node, +text: String) -> Bool:
  leaf_is(n, 5, text)

def is_id(+n: T.Node, +text: String) -> Bool:
  leaf_is(n, 1, text)

def node_line(n: T.Node) -> U32:
  match n:
    case T.Leaf{L.Tok{k, s, l}}:
      l
    case T.Grp{k, l, ks}:
      l

def first_line(ns: List<&2, T.Node>) -> U32:
  match ns:
    case Nil{}:
      0
    case Con{n, rest}:
      node_line(n)

# Keywords after which an operator is unary.
def prefix_kw(s: String) -> Bool:
  match s:
    case "new":
      True{}
    case "clone":
      True{}
    case "print":
      True{}
    case "echo":
      True{}
    case "return":
      True{}
    case "yield":
      True{}
    case "throw":
      True{}
    case "include":
      True{}
    case "include_once":
      True{}
    case "require":
      True{}
    case "require_once":
      True{}
    case "and":
      True{}
    case "or":
      True{}
    case "xor":
      True{}
    case "instanceof":
      True{}
    case "as":
      True{}
    case "case":
      True{}
    case "else":
      True{}
    case "fn":
      True{}
    case "function":
      True{}
    case _:
      False{}

def is_operand(n: T.Node) -> Bool:
  match n:
    case T.Leaf{L.Tok{0, s, l}}:
      True{}
    case T.Leaf{L.Tok{1, s, l}}:
      Bool.not(prefix_kw(s))
    case T.Leaf{L.Tok{2, s, l}}:
      True{}
    case T.Leaf{L.Tok{3, s, l}}:
      True{}
    case T.Leaf{L.Tok{4, s, l}}:
      True{}
    case T.Leaf{L.Tok{7, s, l}}:
      True{}
    case T.Leaf{L.Tok{5, "++", l}}:
      True{}
    case T.Leaf{L.Tok{5, "--", l}}:
      True{}
    case T.Leaf{t}:
      False{}
    case T.Grp{k, l, ks}:
      True{}

def is_asg(s: String) -> Bool:
  match s:
    case "=":
      True{}
    case "+=":
      True{}
    case "-=":
      True{}
    case "*=":
      True{}
    case "/=":
      True{}
    case ".=":
      True{}
    case "%=":
      True{}
    case "**=":
      True{}
    case "??=":
      True{}
    case "&=":
      True{}
    case "|=":
      True{}
    case "^=":
      True{}
    case "<<=":
      True{}
    case ">>=":
      True{}
    case _:
      False{}

# Binding levels, loosest first. 0 means not a binary operator.
#   1 =>  2 and/or/xor  3 assignment  4 ?:  5 ??  6 ||  7 &&  8 | ^ &
#   9 comparison  10 |>  11 .  12 << >>  13 + -  14 * / %  15 **
def op_level(+s: String) -> U32:
  match s:
    case "=>":
      1
    case "?":
      4
    case "??":
      5
    case "||":
      6
    case "&&":
      7
    case "|":
      8
    case "^":
      8
    case "&":
      8
    case "==":
      9
    case "!=":
      9
    case "===":
      9
    case "!==":
      9
    case "<>":
      9
    case "<=>":
      9
    case "<":
      9
    case ">":
      9
    case "<=":
      9
    case ">=":
      9
    case "|>":
      10
    case ".":
      11
    case "<<":
      12
    case ">>":
      12
    case "+":
      13
    case "-":
      13
    case "*":
      14
    case "/":
      14
    case "%":
      14
    case "**":
      15
    case _:
      L.sel(U32, is_asg(s), u => 3, u => 0)

def id_level(s: String) -> U32:
  match s:
    case "and":
      2
    case "or":
      2
    case "xor":
      2
    case "instanceof":
      9
    case _:
      0

def bin_level(n: T.Node) -> U32:
  match n:
    case T.Leaf{L.Tok{5, s, l}}:
      op_level(s)
    case T.Leaf{L.Tok{1, s, l}}:
      id_level(s)
    case T.Leaf{t}:
      0
    case T.Grp{k, l, ks}:
      0

# 0 combine to clean, 1 union.
def level_mode(lv: U32) -> U32:
  match lv:
    case 1:
      1
    case 5:
      1
    case 11:
      1
    case _:
      0

def min_level(ns: List<&2, T.Node>, prev: Bool, +best: U32) -> U32:
  match ns:
    case Nil{}:
      best
    case Con{+n, rest}:
      +lv = b2t(prev, bin_level(n))
      min_level(rest, is_operand(n), L.sel(U32, nz(lv) && U32.is_lt(lv, best), u => lv, u => best))

def at_level(+n: T.Node, prev: Bool, +lv: U32) -> Bool:
  prev && U32.is_eq(bin_level(n), lv)

def split_level.go(ns: List<&2, T.Node>, +lv: U32, prev: Bool, +cur: List<&2, T.Node>, +acc: List<&2, List<&2, T.Node>>) -> List<&2, List<&2, T.Node>>:
  match ns:
    case Nil{}:
      List.reverse(&2, List<&2, T.Node>, Con{List.reverse(&2, T.Node, cur), acc})
    case Con{+n, +rest}:
      L.sel(List<&2, List<&2, T.Node>>, at_level(n, prev, lv), u => split_level.go(rest, lv, False{}, [], Con{List.reverse(&2, T.Node, cur), acc}), u => split_level.go(rest, lv, is_operand(n), Con{n, cur}, acc))

def split_level(ns: List<&2, T.Node>, +lv: U32) -> List<&2, List<&2, T.Node>>:
  split_level.go(ns, lv, False{}, [], [])

def split_all.go(ns: List<&2, T.Node>, +text: String, +cur: List<&2, T.Node>, +acc: List<&2, List<&2, T.Node>>) -> List<&2, List<&2, T.Node>>:
  match ns:
    case Nil{}:
      List.reverse(&2, List<&2, T.Node>, Con{List.reverse(&2, T.Node, cur), acc})
    case Con{+n, +rest}:
      L.sel(List<&2, List<&2, T.Node>>, is_op(n, text), u => split_all.go(rest, text, [], Con{List.reverse(&2, T.Node, cur), acc}), u => split_all.go(rest, text, Con{n, cur}, acc))

def drop_empty(xs: List<&2, List<&2, T.Node>>) -> List<&2, List<&2, T.Node>>:
  match xs:
    case Nil{}:
      []
    case Con{Nil{}, rest}:
      drop_empty(rest)
    case Con{x, rest}:
      Con{x, drop_empty(rest)}

# Split on every top-level operator `text`; drops empty trailing parts.
def split_all(ns: List<&2, T.Node>, +text: String) -> List<&2, List<&2, T.Node>>:
  drop_empty(split_all.go(ns, text, [], []))

def split_at.go(ns: List<&2, T.Node>, +kind: U32, +text: String, +acc: List<&2, T.Node>) -> Two:
  match ns:
    case Nil{}:
      Two{List.reverse(&2, T.Node, acc), []}
    case Con{+n, +rest}:
      L.sel(Two, leaf_is(n, kind, text), u => Two{List.reverse(&2, T.Node, acc), rest}, u => split_at.go(rest, kind, text, Con{n, acc}))

# Split at the first top-level token (kind, text), dropping it.
def split_at(ns: List<&2, T.Node>, +kind: U32, +text: String) -> Two:
  split_at.go(ns, kind, text, [])

def split_asg.go(ns: List<&2, T.Node>, +acc: List<&2, T.Node>) -> Sp:
  match ns:
    case Nil{}:
      Sp{List.reverse(&2, T.Node, acc), "", []}
    case Con{T.Leaf{L.Tok{5, +s, +l}}, +rest}:
      L.sel(Sp, is_asg(s), u => Sp{List.reverse(&2, T.Node, acc), s, rest}, u => split_asg.go(rest, Con{T.Leaf{L.Tok{5, s, l}}, acc}))
    case Con{n, rest}:
      split_asg.go(rest, Con{n, acc})

def tern.go(c: List<&2, T.Node>, r: Two) -> Three:
  match r:
    case Two{a, b}:
      Three{c, a, b}

def tern.split(t: Two) -> Three:
  match t:
    case Two{c, rest}:
      tern.go(c, split_at(rest, 5, ":"))

def node_kids(n: T.Node) -> List<&2, T.Node>:
  match n:
    case T.Leaf{t}:
      [T.Leaf{t}]
    case T.Grp{k, l, ks}:
      ks

# Strip a `name:` named-argument prefix and `...` spread.
def arg_strip(ns: List<&2, T.Node>) -> List<&2, T.Node>:
  match ns:
    case Con{T.Leaf{L.Tok{1, s, l}}, Con{T.Leaf{L.Tok{5, ":", l2}}, rest}}:
      rest
    case Con{T.Leaf{L.Tok{5, "...", l}}, rest}:
      rest
    case _:
      ns

def args_strip(xs: List<&2, List<&2, T.Node>>) -> List<&2, List<&2, T.Node>>:
  match xs:
    case Nil{}:
      []
    case Con{x, rest}:
      Con{arg_strip(x), args_strip(rest)}

def args_of(ns: List<&2, T.Node>) -> List<&2, List<&2, T.Node>>:
  args_strip(split_all(ns, ","))

# All variable names under a node list (for destructuring targets).
def vars_in(ns: List<&2, T.Node>, acc: List<&2, String>) -> List<&2, String>:
  match ns:
    case Nil{}:
      acc
    case Con{T.Leaf{L.Tok{0, s, l}}, rest}:
      vars_in(rest, Con{s, acc})
    case Con{T.Grp{k, l, ks}, rest}:
      vars_in(rest, vars_in(ks, acc))
    case Con{n, rest}:
      vars_in(rest, acc)

def env.set_all(vs: List<&2, String>, +env: Map<&2, U32>, +t: U32) -> Map<&2, U32>:
  match vs:
    case Nil{}:
      env
    case Con{v, rest}:
      env.set_all(rest, env.set(env, v, t), t)

# ---------------------------------------------------------------- sources

def server_safe(k: String) -> Bool:
  match k:
    case "REQUEST_METHOD":
      True{}
    case "DOCUMENT_ROOT":
      True{}
    case "SCRIPT_FILENAME":
      True{}
    case "SCRIPT_NAME":
      True{}
    case "REMOTE_ADDR":
      True{}
    case "REMOTE_PORT":
      True{}
    case "SERVER_ADDR":
      True{}
    case "SERVER_PORT":
      True{}
    case "SERVER_SOFTWARE":
      True{}
    case "SERVER_PROTOCOL":
      True{}
    case "GATEWAY_INTERFACE":
      True{}
    case "REQUEST_TIME":
      True{}
    case "REQUEST_TIME_FLOAT":
      True{}
    case "HTTPS":
      True{}
    case "CONTENT_LENGTH":
      True{}
    case _:
      False{}

def files_safe(k: String) -> Bool:
  match k:
    case "tmp_name":
      True{}
    case "size":
      True{}
    case "error":
      True{}
    case _:
      False{}

# Taint of a superglobal given the nodes after it; 65535 if not one.
def sg(name: String, rest: List<&2, T.Node>) -> U32:
  match name rest:
    case "_GET" r:
      SRC()
    case "_POST" r:
      SRC()
    case "_REQUEST" r:
      SRC()
    case "_COOKIE" r:
      SRC()
    case "_SERVER" Con{T.Grp{91, l, Con{T.Leaf{L.Tok{2, k, l2}}, Nil{}}}, r}:
      L.sel(U32, server_safe(k), u => 0, u => SRC())
    case "_SERVER" r:
      SRC()
    case "_FILES" Con{T.Grp{91, l, a}, Con{T.Grp{91, l2, Con{T.Leaf{L.Tok{2, k, l3}}, Nil{}}}, r}}:
      L.sel(U32, files_safe(k), u => 0, u => SRC())
    case "_FILES" r:
      SRC()
    case "_ENV" r:
      0
    case "GLOBALS" r:
      0
    case n r:
      65535

def istr.var(+env: Map<&2, U32>, v: String) -> U32:
  match v:
    case "_GET":
      SRC()
    case "_POST":
      SRC()
    case "_REQUEST":
      SRC()
    case "_COOKIE":
      SRC()
    case "_SERVER":
      SRC()
    case "_FILES":
      SRC()
    case _:
      env.get(env, v, 0)

def istr.go(vs: List<&2, String>, +env: Map<&2, U32>) -> U32:
  match vs:
    case Nil{}:
      0
    case Con{v, rest}:
      tor(istr.var(env, v), istr.go(rest, env))

# Interpolated strings hold their variable names, space separated.
def istr(+env: Map<&2, U32>, text: String) -> U32:
  istr.go(String.split(text, ' '), env)

# ---------------------------------------------------------------- models

def m.unknown() -> Model:
  Model{0, 0, ALL(), 0, 0, 0}

def m.clean() -> Model:
  Model{0, 0, 0, 0, 0, 0}

def m.src() -> Model:
  Model{0, 0, 0, 0, SRC(), 0}

def m.san(+c: U32) -> Model:
  Model{0, 0, ALL(), c, 0, 0}

def m.sink(+c: U32, +sa: U32, +ra: U32) -> Model:
  Model{c, sa, ra, 0, 0, 0}

def XSS_SAFE() -> U32:
  264

def ENC_SAFE() -> U32:
  271

# Functions whose result cannot carry attacker-controlled text.
type EntM is Data:
  EntM{k: String, m: Model}

def entm.find(es: List<&2, EntM>, +name: String, d: Model) -> Model:
  match es:
    case Nil{}:
      d
    case Con{EntM{k, m}, rest}:
      L.sel(Model, String.eq(k, name), u => m, u => entm.find(rest, name, d))

def clean_fn.tab() -> List<&2, EntM>:
  Con{EntM{"intval", m.clean()},
  Con{EntM{"absint", m.clean()},
  Con{EntM{"floatval", m.clean()},
  Con{EntM{"doubleval", m.clean()},
  Con{EntM{"boolval", m.clean()},
  Con{EntM{"count", m.clean()},
  Con{EntM{"sizeof", m.clean()},
  Con{EntM{"strlen", m.clean()},
  Con{EntM{"mb_strlen", m.clean()},
  Con{EntM{"md5", m.clean()},
  Con{EntM{"sha1", m.clean()},
  Con{EntM{"crc32", m.clean()},
  Con{EntM{"hash", m.clean()},
  Con{EntM{"hash_hmac", m.clean()},
  Con{EntM{"password_hash", m.clean()},
  Con{EntM{"isset", m.clean()},
  Con{EntM{"empty", m.clean()},
  Con{EntM{"is_numeric", m.clean()},
  Con{EntM{"is_int", m.clean()},
  Con{EntM{"is_string", m.clean()},
  Con{EntM{"is_array", m.clean()},
  Con{EntM{"in_array", m.clean()},
  Con{EntM{"array_key_exists", m.clean()},
  Con{EntM{"strpos", m.clean()},
  Con{EntM{"stripos", m.clean()},
  Con{EntM{"strrpos", m.clean()},
  Con{EntM{"strcmp", m.clean()},
  Con{EntM{"strcasecmp", m.clean()},
  Con{EntM{"preg_match", m.clean()},
  Con{EntM{"preg_match_all", m.clean()},
  Con{EntM{"ctype_digit", m.clean()},
  Con{EntM{"ctype_alnum", m.clean()},
  Con{EntM{"ctype_alpha", m.clean()},
  Con{EntM{"file_exists", m.clean()},
  Con{EntM{"is_file", m.clean()},
  Con{EntM{"is_dir", m.clean()},
  Con{EntM{"date", m.clean()},
  Con{EntM{"gmdate", m.clean()},
  Con{EntM{"strtotime", m.clean()},
  Con{EntM{"time", m.clean()},
  Con{EntM{"round", m.clean()},
  Con{EntM{"floor", m.clean()},
  Con{EntM{"ceil", m.clean()},
  Con{EntM{"abs", m.clean()},
  Con{EntM{"number_format", m.clean()},
  Con{EntM{"get_filter_request_var", m.clean()},
  Con{EntM{"wp_verify_nonce", m.clean()},
  Con{EntM{"check_admin_referer", m.clean()},
  Con{EntM{"current_user_can", m.clean()},
  Con{EntM{"sanitize_key", m.clean()},
  Con{EntM{"sanitize_email", m.clean()},
  Con{EntM{"sanitize_title", m.clean()},
  Con{EntM{"wp_create_nonce", m.clean()},
  Con{EntM{"uniqid", m.clean()},
  Con{EntM{"rand", m.clean()},
  Con{EntM{"mt_rand", m.clean()},
  Con{EntM{"random_int", m.clean()},
  Con{EntM{"gettype", m.clean()},
  Con{EntM{"function_exists", m.clean()},
  Con{EntM{"defined", m.clean()},
  Nil{}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}

def clean_fn(+name: String) -> Model:
  entm.find(clean_fn.tab(), name, m.unknown())

def fmodel.tab() -> List<&2, EntM>:
  Con{EntM{"system", m.sink(2, 1, ALL())},
  Con{EntM{"exec", m.sink(2, 1, ALL())},
  Con{EntM{"passthru", m.sink(2, 1, 0)},
  Con{EntM{"shell_exec", m.sink(2, 1, ALL())},
  Con{EntM{"popen", m.sink(2, 1, 0)},
  Con{EntM{"proc_open", m.sink(2, 1, 0)},
  Con{EntM{"pcntl_exec", m.sink(2, 3, 0)},
  Con{EntM{"mail", m.sink(2, 16, 0)},
  Con{EntM{"eval", m.sink(4, 1, 0)},
  Con{EntM{"assert", m.sink(4, 1, 0)},
  Con{EntM{"create_function", m.sink(4, ALL(), 0)},
  Con{EntM{"call_user_func", m.sink(4, 1, ALL())},
  Con{EntM{"call_user_func_array", m.sink(4, 1, ALL())},
  Con{EntM{"unserialize", m.sink(128, 1, ALL())},
  Con{EntM{"maybe_unserialize", m.sink(128, 1, ALL())},
  Con{EntM{"file_get_contents", m.sink(16, 1, ALL())},
  Con{EntM{"fopen", m.sink(16, 1, ALL())},
  Con{EntM{"file", m.sink(16, 1, ALL())},
  Con{EntM{"readfile", m.sink(16, 1, 0)},
  Con{EntM{"unlink", m.sink(16, 1, 0)},
  Con{EntM{"rmdir", m.sink(16, 1, 0)},
  Con{EntM{"mkdir", m.sink(16, 1, 0)},
  Con{EntM{"opendir", m.sink(16, 1, 0)},
  Con{EntM{"scandir", m.sink(16, 1, ALL())},
  Con{EntM{"file_put_contents", m.sink(16, 1, 0)},
  Con{EntM{"copy", m.sink(16, 3, 0)},
  Con{EntM{"rename", m.sink(16, 3, 0)},
  Con{EntM{"move_uploaded_file", m.sink(16, 2, 0)},
  Con{EntM{"simplexml_load_file", m.sink(16, 1, ALL())},
  Con{EntM{"parse_ini_file", m.sink(16, 1, ALL())},
  Con{EntM{"highlight_file", m.sink(16, 1, 0)},
  Con{EntM{"show_source", m.sink(16, 1, 0)},
  Con{EntM{"curl_init", m.sink(64, 1, 0)},
  Con{EntM{"fsockopen", m.sink(64, 1, 0)},
  Con{EntM{"get_headers", m.sink(64, 1, ALL())},
  Con{EntM{"wp_remote_get", m.sink(64, 1, ALL())},
  Con{EntM{"wp_remote_post", m.sink(64, 1, ALL())},
  Con{EntM{"wp_remote_request", m.sink(64, 1, ALL())},
  Con{EntM{"header", m.sink(256, 1, 0)},
  Con{EntM{"wp_redirect", m.sink(256, 1, 0)},
  Con{EntM{"mysql_query", m.sink(1, 1, 0)},
  Con{EntM{"mysql_unbuffered_query", m.sink(1, 1, 0)},
  Con{EntM{"mysqli_query", m.sink(1, 3, 0)},
  Con{EntM{"mysqli_multi_query", m.sink(1, 3, 0)},
  Con{EntM{"mysqli_real_query", m.sink(1, 3, 0)},
  Con{EntM{"mysqli_prepare", m.sink(1, 3, 0)},
  Con{EntM{"pg_query", m.sink(1, 3, 0)},
  Con{EntM{"pg_send_query", m.sink(1, 3, 0)},
  Con{EntM{"sqlite_query", m.sink(1, 3, 0)},
  Con{EntM{"odbc_exec", m.sink(1, 2, 0)},
  Con{EntM{"printf", m.sink(8, ALL(), 0)},
  Con{EntM{"vprintf", m.sink(8, ALL(), 0)},
  Con{EntM{"print_r", m.sink(8, 1, ALL())},
  Con{EntM{"exit", m.sink(8, 1, 0)},
  Con{EntM{"die", m.sink(8, 1, 0)},
  Con{EntM{"wp_die", m.sink(8, 3, 0)},
  Con{EntM{"extract", m.sink(512, 1, 0)},
  Con{EntM{"getallheaders", m.src()},
  Con{EntM{"apache_request_headers", m.src()},
  Con{EntM{"get_nfilter_request_var", m.src()},
  Con{EntM{"get_request_var", m.src()},
  Con{EntM{"request", m.src()},
  Con{EntM{"htmlspecialchars", m.san(XSS_SAFE())},
  Con{EntM{"htmlentities", m.san(XSS_SAFE())},
  Con{EntM{"strip_tags", m.san(XSS_SAFE())},
  Con{EntM{"esc_html", m.san(XSS_SAFE())},
  Con{EntM{"esc_attr", m.san(XSS_SAFE())},
  Con{EntM{"esc_textarea", m.san(XSS_SAFE())},
  Con{EntM{"esc_js", m.san(XSS_SAFE())},
  Con{EntM{"esc_url", m.san(XSS_SAFE())},
  Con{EntM{"esc_html__", m.san(XSS_SAFE())},
  Con{EntM{"esc_attr__", m.san(XSS_SAFE())},
  Con{EntM{"wp_kses", m.san(XSS_SAFE())},
  Con{EntM{"wp_kses_post", m.san(XSS_SAFE())},
  Con{EntM{"wp_strip_all_tags", m.san(XSS_SAFE())},
  Con{EntM{"sanitize_text_field", m.san(XSS_SAFE())},
  Con{EntM{"sanitize_textarea_field", m.san(XSS_SAFE())},
  Con{EntM{"urlencode", m.san(ENC_SAFE())},
  Con{EntM{"rawurlencode", m.san(ENC_SAFE())},
  Con{EntM{"base64_encode", m.san(ENC_SAFE())},
  Con{EntM{"http_build_query", m.san(ENC_SAFE())},
  Con{EntM{"addslashes", m.san(1)},
  Con{EntM{"mysql_real_escape_string", m.san(1)},
  Con{EntM{"mysql_escape_string", m.san(1)},
  Con{EntM{"mysqli_real_escape_string", m.san(1)},
  Con{EntM{"esc_sql", m.san(1)},
  Con{EntM{"pg_escape_string", m.san(1)},
  Con{EntM{"pg_escape_literal", m.san(1)},
  Con{EntM{"sqlite_escape_string", m.san(1)},
  Con{EntM{"escapeshellarg", m.san(2)},
  Con{EntM{"escapeshellcmd", m.san(2)},
  Con{EntM{"cacti_escapeshellarg", m.san(2)},
  Con{EntM{"basename", m.san(48)},
  Con{EntM{"sanitize_file_name", m.san(48)},
  Nil{}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}

def fmodel(+name: String) -> Model:
  entm.find(fmodel.tab(), name, clean_fn(name))

def request_recv(cls: String) -> Bool:
  match cls:
    case "request":
      True{}
    case "req":
      True{}
    case "this->request":
      True{}
    case _:
      False{}

def raw_method(+name: String) -> Bool:
  String.ends_with(name, "raw") && Bool.not(String.eq(name, "raw"))

def mmodel.name(+name: String) -> Model:
  match name:
    case "query":
      m.sink(1, 1, 0)
    case "exec":
      m.sink(1, 1, 0)
    case "multi_query":
      m.sink(1, 1, 0)
    case "real_query":
      m.sink(1, 1, 0)
    case "get_results":
      m.sink(1, 1, 0)
    case "get_row":
      m.sink(1, 1, 0)
    case "get_var":
      m.sink(1, 1, 0)
    case "get_col":
      m.sink(1, 1, 0)
    case "prepare":
      m.sink(1, 1, 0)
    case "real_escape_string":
      m.san(1)
    case "escape_string":
      m.san(1)
    case "quote":
      m.san(1)
    case "escape":
      m.san(1)
    case _:
      L.sel(Model, raw_method(name), u => m.sink(1, 1, ALL()), u => Model{0, 0, ALL(), 0, 0, 1})

def mmodel(+name: String, cls: String) -> Model:
  L.sel(Model, request_recv(cls), u => m.src(), u => mmodel.name(name))

def smodel(cls: String, +name: String) -> Model:
  match cls:
    case "db":
      L.sel(Model, String.eq(name, "raw") || String.eq(name, "select") || String.eq(name, "statement") || String.eq(name, "unprepared") || String.eq(name, "insert") || String.eq(name, "update") || String.eq(name, "delete"), u => m.sink(1, 1, 0), u => mmodel.name(name))
    case "request":
      m.src()
    case _:
      mmodel.name(name)

# Calls whose meaning depends on literal arguments.
#   1 result is request input  2 result is clean  4 curl_setopt URL
#   5 dispatch to a literal callback  6 parse_str into the local scope
def first_str(ps: List<&2, List<&2, T.Node>>) -> String:
  match ps:
    case Con{Con{T.Leaf{L.Tok{2, s, l}}, Nil{}}, r}:
      s
    case _:
      ""

def has_validate(ns: List<&2, T.Node>) -> Bool:
  match ns:
    case Nil{}:
      False{}
    case Con{T.Leaf{L.Tok{1, +s, l}}, rest}:
      String.starts_with(s, "filter_validate") || String.starts_with(s, "filter_sanitize_number") || has_validate(rest)
    case Con{T.Grp{k, l, ks}, rest}:
      has_validate(ks) || has_validate(rest)
    case Con{n, rest}:
      has_validate(rest)

def nth_is_id(ps: List<&2, List<&2, T.Node>>, n: Nat, +text: String) -> Bool:
  match ps n:
    case Nil{} k:
      False{}
    case Con{Con{T.Leaf{L.Tok{1, s, l}}, Nil{}}, r} 0n:
      String.eq(s, text)
    case Con{x, r} 0n:
      False{}
    case Con{x, r} 1n+p:
      nth_is_id(r, p, text)

def input_wrapper(+s: String) -> Bool:
  String.eq(s, "php://input")

def last_str(ns: List<&2, T.Node>, +acc: String) -> String:
  match ns:
    case Nil{}:
      acc
    case Con{T.Leaf{L.Tok{2, s, l}}, rest}:
      last_str(rest, s)
    case Con{n, rest}:
      last_str(rest, acc)

# The function name a literal callback refers to, or "".
def cb_name(ps: List<&2, List<&2, T.Node>>) -> String:
  match ps:
    case Con{Con{T.Leaf{L.Tok{2, s, l}}, Nil{}}, r}:
      String.to_lower(s)
    case Con{Con{T.Grp{91, l, ks}, Nil{}}, r}:
      "->" ++ String.to_lower(last_str(ks, ""))
    case Con{Con{T.Leaf{L.Tok{1, "array", l}}, Con{T.Grp{40, l2, ks}, Nil{}}}, r}:
      "->" ++ String.to_lower(last_str(ks, ""))
    case _:
      ""

def spec.fn(name: String, +ps: List<&2, List<&2, T.Node>>) -> U32:
  match name:
    case "file_get_contents":
      L.sel(U32, input_wrapper(first_str(ps)), u => 1, u => 0)
    case "fopen":
      L.sel(U32, input_wrapper(first_str(ps)), u => 1, u => 0)
    case "file":
      L.sel(U32, input_wrapper(first_str(ps)), u => 1, u => 0)
    case "filter_input":
      L.sel(U32, has_validate(List.concat(&2, T.Node, ps)), u => 2, u => 1)
    case "filter_var":
      L.sel(U32, has_validate(List.concat(&2, T.Node, ps)), u => 2, u => 0)
    case "filter_input_array":
      1
    case "curl_setopt":
      L.sel(U32, nth_is_id(ps, 1n, "curlopt_url"), u => 4, u => 0)
    case "call_user_func":
      L.sel(U32, String.is_empty(cb_name(ps)) || String.eq(cb_name(ps), "->"), u => 0, u => 5)
    case "call_user_func_array":
      L.sel(U32, String.is_empty(cb_name(ps)) || String.eq(cb_name(ps), "->"), u => 0, u => 5)
    case "parse_str":
      L.sel(U32, U32.is_eq(U32.from_nat(List.length(&2, List<&2, T.Node>, ps)), 1), u => 6, u => 0)
    case "html_entity_decode":
      7
    case "htmlspecialchars_decode":
      7
    case "wp_kses_decode_entities":
      7
    case _:
      0

def spec(+kind: U32, +name: String, +ps: List<&2, List<&2, T.Node>>) -> U32:
  L.sel(U32, U32.is_ne(kind, 0), u => 0, u => spec.fn(name, ps))

# ---------------------------------------------------------------- calls

def m.known(m: Model) -> Bool:
  match m:
    case Model{sc, sa, ra, clr, src, rcv}:
      nz(sc) || nz(clr) || nz(src) || Bool.not(U32.is_eq(ra, ALL()))

def model_apply(m: Model, +ts: List<&2, U32>, +rv: U32, st: St, +line: U32, +name: String) -> Res:
  match m:
    case Model{sc, sa, ra, clr, src, rcv}:
      Res{tor(tor(tclr(mask_or(ts, ra), clr), src), b2t(nz(rcv), rv)), [], st.find(st, line, sink.bits(mask_or(ts, sa), sc), name)}

# OR over i of ts[i] & ms[i].
def zip_or(ts: List<&2, U32>, ms: List<&2, U32>) -> U32:
  match ts ms:
    case Con{t, tr} Con{m, mr}:
      tor(U32.and(t, m), zip_or(tr, mr))
    case a b:
      0

# Apply decoder-restored sink classes when the corresponding argument has
# any remaining request taint, even if the caller cleared that sink's class.
def zip_revived(ts: List<&2, U32>, revived: List<&2, U32>) -> U32:
  match ts revived:
    case Con{t, tr} Con{r, rr}:
      tor(b2t(nz(U32.and(t, SRC())), r), zip_revived(tr, rr))
    case a b:
      0

def sum_apply(s: Sum, +m: Model, +ts: List<&2, U32>, +rv: U32, st: St, +line: U32, +name: String) -> Res:
  match s:
    case NoSum{}:
      model_apply(m, ts, rv, st, line, name)
    case Sum{src, props, sinks, revived}:
      +normal = zip_or(ts, sinks)
      +restored = zip_revived(ts, revived)
      +hits = U32.or(normal, U32.shln(restored, 10n))
      Res{tor(src, zip_or(ts, props)), [], st.find(st, line, hits, name ++ "()")}

# Builtin models win for methods (query, prepare, ...) unless unknown.
def meth_apply(+m: Model, s: Sum, +ts: List<&2, U32>, +rv: U32, +st: St, +line: U32, +name: String) -> Res:
  L.sel(Res, m.known(m), u => model_apply(m, ts, rv, st, line, name), u => sum_apply(s, m, ts, rv, st, line, name))

def cb_model(m: Model, +u: U32) -> U32:
  match m:
    case Model{sc, sa, ra, clr, src, rcv}:
      tor(tclr(b2t(nz(ra), u), clr), src)

def cb_sum(s: Sum, m: Model, +u: U32) -> U32:
  match s:
    case NoSum{}:
      cb_model(m, u)
    case Sum{src, props, sinks, revived}:
      tor(src, U32.and(u, or_list(props)))

def cb_mod(+cb: String) -> Model:
  L.sel(Model, String.starts_with(cb, "->"), u => mmodel.name(String.drop(cb, 2n)), u => fmodel(cb))

# Taint returned by a call through a literal callback, given the OR of the
# arguments passed on to it.
def cb_apply(+cb: String, +u: U32, +cx: Map<&2, Sum>) -> U32:
  +mo = cb_mod(cb)
  L.sel(U32, m.known(mo), u2 => cb_model(mo, u), u2 => cb_sum(sum.get(cx, cb), mo, u))

def call_apply(ci: CallI, +ts: List<&2, U32>, +st: St, +cx: Map<&2, Sum>) -> Res:
  match ci:
    case CallI{k, n, c, l, rv, 1, cb, a, r}:
      Res{SRC(), [], st}
    case CallI{k, n, c, l, rv, 2, cb, a, r}:
      Res{0, [], st}
    case CallI{k, n, c, l, rv, 4, cb, a, r}:
      Res{0, [], st.find(st, l, sink.bits(mask_or(ts, 4), 64), "curl_setopt")}
    case CallI{k, n, c, l, rv, 5, cb, a, r}:
      Res{cb_apply(cb, or_list(tail(ts)), cx), [], st}
    case CallI{k, n, c, l, rv, 6, cb, a, r}:
      model_apply(m.sink(512, 1, 0), ts, rv, st, l, n)
    # Decoding restores classes, and marks summary flows for restored sinks.
    case CallI{k, n, c, l, rv, 7, cb, a, r}:
      +taint = mask_or(ts, 1)
      +out = b2t(nz(U32.and(taint, SRC())), SRC())
      +restored = b2t(nz(U32.and(taint, SUMMARY_MARKER())), RESTORED())
      Res{U32.or(out, restored), [], st}
    case CallI{0, +n, c, l, rv, s, cb, a, r}:
      sum_apply(sum.get(cx, n), fmodel(n), ts, rv, st, l, n)
    case CallI{1, +n, c, l, rv, s, cb, a, r}:
      meth_apply(mmodel(n, c), sum.get(cx, "->" ++ n), ts, rv, st, l, "->" ++ n)
    case CallI{2, +n, c, l, rv, s, cb, a, r}:
      meth_apply(smodel(c, n), sum.get(cx, "->" ++ n), ts, rv, st, l, "::" ++ n)
    case CallI{k, n, c, l, rv, s, cb, a, r}:
      Res{or_list(ts), [], st.find(st, l, sink.bits(rv, 4), "dynamic call")}

def mk_call(+kind: U32, +name: String, cls: String, line: U32, recv: U32, +args: List<&2, T.Node>, rest: List<&2, T.Node>) -> CallI:
  +ps = args_of(args)
  CallI{kind, name, cls, line, recv, spec(kind, name, ps), cb_name(ps), args, rest}

def ci_args(ci: CallI) -> List<&2, T.Node>:
  match ci:
    case CallI{k, n, c, l, rv, s, cb, a, r}:
      a

def ci_rest(ci: CallI) -> List<&2, T.Node>:
  match ci:
    case CallI{k, n, c, l, rv, s, cb, a, r}:
      r

# ---------------------------------------------------------------- shapes

def two.b(t: Two) -> List<&2, T.Node>:
  match t:
    case Two{a, b}:
      b

def split_asg(ns: List<&2, T.Node>) -> Sp:
  split_asg.go(ns, [])

def clean_prefix(op: String) -> Bool:
  match op:
    case "!":
      True{}
    case "-":
      True{}
    case "+":
      True{}
    case "~":
      True{}
    case "++":
      True{}
    case "--":
      True{}
    case _:
      False{}

def int_cast(c: String) -> Bool:
  match c:
    case "int":
      True{}
    case "integer":
      True{}
    case "float":
      True{}
    case "double":
      True{}
    case "real":
      True{}
    case "bool":
      True{}
    case "boolean":
      True{}
    case "void":
      True{}
    case "unset":
      True{}
    case _:
      False{}

def var_t(+name: String, rest: List<&2, T.Node>, +env: Map<&2, U32>) -> U32:
  +g = sg(name, rest)
  L.sel(U32, U32.is_eq(g, 65535), u => env.get(env, name, 0), u => g)

def pkey(+path: String, pr: String) -> String:
  L.sel(String, String.is_empty(path), u => "", u => path ++ "->" ++ pr)

# `new X(args) rest`: the constructor arguments and a member chain, if any.
def new_split(ns: List<&2, T.Node>) -> Two:
  match ns:
    case Nil{}:
      Two{[], []}
    case Con{T.Grp{40, l, ks}, Con{T.Leaf{L.Tok{5, "->", l2}}, rest}}:
      Two{ks, Con{T.Leaf{L.Tok{5, "->", l2}}, rest}}
    case Con{T.Grp{40, l, ks}, Con{T.Leaf{L.Tok{5, "?->", l2}}, rest}}:
      Two{ks, Con{T.Leaf{L.Tok{5, "?->", l2}}, rest}}
    case Con{T.Grp{40, l, ks}, rest}:
      Two{ks, []}
    case Con{T.Grp{123, l, ks}, rest}:
      Two{[], []}
    case Con{n, rest}:
      new_split(rest)

# Closure: Two{arrow body expression, block body statements}.
def clo_split(ns: List<&2, T.Node>) -> Two:
  match ns:
    case Nil{}:
      Two{[], []}
    case Con{T.Leaf{L.Tok{5, "=>", l}}, rest}:
      Two{rest, []}
    case Con{T.Grp{123, l, ks}, rest}:
      Two{[], ks}
    case Con{n, rest}:
      clo_split(rest)

def asg_val(op: String, +old: U32, +t: U32) -> U32:
  match op:
    case "=":
      t
    case ".=":
      tor(old, t)
    case "??=":
      tor(old, t)
    case _:
      old

def asg_weak(op: String, +t: U32) -> U32:
  match op:
    case "=":
      t
    case ".=":
      t
    case "??=":
      t
    case _:
      0

def assign(lhs: List<&2, T.Node>, +op: String, +t: U32, +env: Map<&2, U32>) -> Map<&2, U32>:
  match lhs:
    case Con{T.Leaf{L.Tok{0, +v, l}}, Nil{}}:
      env.set(env, v, asg_val(op, env.get(env, v, 0), t))
    case Con{T.Leaf{L.Tok{0, v, l}}, Con{T.Leaf{L.Tok{5, "->", l2}}, Con{T.Leaf{L.Tok{1, pr, l3}}, Nil{}}}}:
      +k = v ++ "->" ++ pr
      env.set(env, k, asg_val(op, env.get(env, k, 0), t))
    case Con{T.Leaf{L.Tok{0, v, l}}, Con{T.Leaf{L.Tok{5, "->", l2}}, Con{T.Leaf{L.Tok{1, pr, l3}}, more}}}:
      +k = v ++ "->" ++ pr
      env.set(env, k, tor(env.get(env, k, 0), asg_weak(op, t)))
    case Con{T.Leaf{L.Tok{0, +v, l}}, more}:
      env.set(env, v, tor(env.get(env, v, 0), asg_weak(op, t)))
    case Con{T.Grp{91, l, ks}, Nil{}}:
      env.set_all(vars_in(ks, []), env, t)
    case Con{T.Leaf{L.Tok{1, "list", l}}, Con{T.Grp{40, l2, ks}, Nil{}}}:
      env.set_all(vars_in(ks, []), env, t)
    case _:
      env

def asg_st(lhs: List<&2, T.Node>, +op: String, +t: U32, st: St) -> Res:
  match st:
    case St{env, fs, ret, revived}:
      Res{t, [], St{assign(lhs, op, t, env), fs, ret, revived}}

# How an expression starts:
#   100 empty  110 print  111 include/require  112 yield/throw  102 closure
#   otherwise the loosest binary operator level, 0 for a primary.
def lead_kw(+s: String, +ns: List<&2, T.Node>) -> U32:
  match s:
    case "print":
      110
    case "include":
      111
    case "include_once":
      111
    case "require":
      111
    case "require_once":
      111
    case "yield":
      112
    case "throw":
      112
    case "fn":
      102
    case "function":
      102
    case _:
      L.sel(U32, U32.is_eq(min_level(ns, False{}, 99), 99), u => 0, u => min_level(ns, False{}, 99))

def lead(ns: List<&2, T.Node>) -> U32:
  match ns:
    case Nil{}:
      100
    case Con{T.Leaf{L.Tok{1, "static", l}}, Con{T.Leaf{L.Tok{1, "fn", l2}}, rest}}:
      102
    case Con{T.Leaf{L.Tok{1, "static", l}}, Con{T.Leaf{L.Tok{1, "function", l2}}, rest}}:
      102
    case Con{T.Leaf{L.Tok{1, +s, l}}, rest}:
      lead_kw(s, Con{T.Leaf{L.Tok{1, s, l}}, rest})
    case +ns2:
      +lv = min_level(ns2, False{}, 99)
      L.sel(U32, U32.is_eq(lv, 99), u => 0, u => lv)

def for_parts(xs: List<&2, List<&2, T.Node>>) -> List<&2, List<&2, T.Node>>:
  match xs:
    case Nil{}:
      []
    case Con{x, rest}:
      List.append(&2, List<&2, T.Node>, args_of(x), for_parts(rest))

# Statement kinds, see StmtsD.
def kw_kind(s: String) -> U32:
  match s:
    case "echo":
      3
    case "return":
      4
    case "if":
      5
    case "elseif":
      5
    case "while":
      5
    case "switch":
      5
    case "for":
      6
    case "foreach":
      7
    case "else":
      8
    case "do":
      8
    case "try":
      8
    case "finally":
      8
    case "case":
      9
    case "class":
      11
    case "interface":
      11
    case "trait":
      11
    case "enum":
      11
    case "abstract":
      1
    case "final":
      1
    case "readonly":
      1
    case "namespace":
      12
    case "use":
      13
    case "global":
      13
    case "const":
      13
    case "break":
      13
    case "continue":
      13
    case "goto":
      13
    case "endif":
      13
    case "endwhile":
      13
    case "endfor":
      13
    case "endforeach":
      13
    case "endswitch":
      13
    case "enddeclare":
      13
    case "catch":
      15
    case "declare":
      15
    case "default":
      16
    case _:
      14

def stmt_kind(ns: List<&2, T.Node>) -> U32:
  match ns:
    case Nil{}:
      0
    case Con{T.Leaf{L.Tok{5, ";", l}}, r}:
      1
    case Con{T.Grp{35, l, ks}, r}:
      1
    case Con{T.Grp{123, l, ks}, r}:
      2
    case Con{T.Leaf{L.Tok{1, "function", l}}, Con{T.Leaf{L.Tok{1, n, l2}}, r}}:
      10
    case Con{T.Leaf{L.Tok{1, "function", l}}, Con{T.Leaf{L.Tok{5, "&", l2}}, Con{T.Leaf{L.Tok{1, n, l3}}, r}}}:
      10
    case Con{T.Leaf{L.Tok{1, "static", l}}, Con{T.Leaf{L.Tok{0, n, l2}}, r}}:
      1
    case Con{T.Leaf{L.Tok{1, kw, l}}, r}:
      kw_kind(kw)
    case _:
      14

# Body after a control header: 0 block, 1 skip a token, 2 statement keyword,
# 3 a single expression statement, 4 nothing.
def body_kind(ns: List<&2, T.Node>) -> U32:
  match ns:
    case Nil{}:
      4
    case Con{T.Grp{123, l, ks}, r}:
      0
    case Con{T.Leaf{L.Tok{5, ":", l}}, r}:
      1
    case Con{T.Leaf{L.Tok{5, ";", l}}, r}:
      1
    case Con{T.Leaf{L.Tok{1, kw, l}}, r}:
      L.sel(U32, U32.is_eq(kw_kind(kw), 14), u => 3, u => 2)
    case _:
      3

# Skip a declaration: up to and including its `{..}` body, or its `;`.
def skip_brace(ns: List<&2, T.Node>) -> List<&2, T.Node>:
  match ns:
    case Nil{}:
      []
    case Con{T.Grp{123, l, ks}, rest}:
      rest
    case Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      rest
    case Con{n, rest}:
      skip_brace(rest)

# `namespace X;` or `namespace X { .. }`: continue with what follows.
def ns_body(ns: List<&2, T.Node>) -> List<&2, T.Node>:
  match ns:
    case Nil{}:
      []
    case Con{T.Grp{123, l, ks}, rest}:
      List.append(&2, T.Node, ks, rest)
    case Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      rest
    case Con{n, rest}:
      ns_body(rest)

# What to do with the result of a sub-job.
type Kont is Data:
  KSink{cls: U32, line: U32, name: String}
  KMask{m: U32}
  KOr{t: U32}
  KAsg{lhs: List<&2, T.Node>, op: String}
  KTern{a: List<&2, T.Node>, b: List<&2, T.Node>}
  KParts{mode: U32, ps: List<&2, List<&2, T.Node>>, acc: U32}
  KArgs{ps: List<&2, List<&2, T.Node>>, acc: List<&2, U32>}
  KPipe{ps: List<&2, List<&2, T.Node>>, line: U32}
  KPost{path: String, ns: List<&2, T.Node>}
  KPostI{t: U32, ns: List<&2, T.Node>}
  KCall{ci: CallI}
  KClo{env: Map<&2, U32>, ret: U32}
  KStmts{ns: List<&2, T.Node>}
  KBlock{pre: Map<&2, U32>}
  KHdr{ns: List<&2, T.Node>}
  KFe{target: List<&2, T.Node>, rest: List<&2, T.Node>}
  KRet{}

# ---------------------------------------------------------------- analyzer

type Job is Data:
  JDone{r: Res}
  JThen{j: Job, k: Kont}
  Ex{ns: List<&2, T.Node>, st: St}
  Prim{ns: List<&2, T.Node>, st: St}
  Post{t: U32, path: String, ns: List<&2, T.Node>, st: St}
  Call{ci: CallI, st: St}
  Parts{mode: U32, ps: List<&2, List<&2, T.Node>>, st: St, acc: U32}
  Args{ps: List<&2, List<&2, T.Node>>, st: St, acc: List<&2, U32>}
  PipeS{ps: List<&2, List<&2, T.Node>>, line: U32, st: St}
  PipeC{name: String, part: List<&2, T.Node>, t: U32, st: St, line: U32}
  Stmts{ns: List<&2, T.Node>, st: St}
  Block{ns: List<&2, T.Node>, st: St}
  Body{ns: List<&2, T.Node>, st: St}

def st_ret(st: St) -> U32:
  match st:
    case St{env, fs, ret, revived}:
      ret

def st.fs(st: St) -> List<&2, Finding>:
  match st:
    case St{env, fs, ret, revived}:
      fs

def st.join(pre: Map<&2, U32>, st: St) -> St:
  match st:
    case St{env, fs, ret, revived}:
      St{env.join(pre, env), fs, ret, revived}

def st.restore(env: Map<&2, U32>, ret: U32, st: St) -> St:
  match st:
    case St{env2, fs, ret2, revived}:
      St{env, fs, ret, revived}

def st.set_all(vs: List<&2, String>, +t: U32, st: St) -> St:
  match st:
    case St{env, fs, ret, revived}:
      St{env.set_all(vs, env, t), fs, ret, revived}

def drop1(ns: List<&2, T.Node>) -> List<&2, T.Node>:
  match ns:
    case Nil{}:
      []
    case Con{n, rest}:
      rest

# A `name(...)` first-class callable in a pipe, or "".
def pipe_name(ns: List<&2, T.Node>) -> String:
  match ns:
    case Con{T.Leaf{L.Tok{1, n, l}}, Con{T.Grp{40, l2, Con{T.Leaf{L.Tok{5, "...", l3}}, Nil{}}}, Nil{}}}:
      n
    case _:
      ""

def k.tern(a: List<&2, T.Node>, b: List<&2, T.Node>, t: U32, st: St) -> Job:
  match a:
    case Nil{}:
      Parts{1, [b], st, t}
    case Con{x, xs}:
      Parts{1, [Con{x, xs}, b], st, 0}

def k.pipe(ps: List<&2, List<&2, T.Node>>, +line: U32, +t: U32, st: St) -> Job:
  match ps:
    case Nil{}:
      JDone{Res{t, [], st}}
    case Con{+x, rest}:
      JThen{PipeC{pipe_name(x), x, t, st, line}, KPipe{rest, line}}

def step_k(r: Res, k: Kont, +cx: Map<&2, Sum>) -> Job:
  match r:
    case Res{t, ts, st}:
      match k:
        case KSink{cls, line, name}:
          JDone{Res{0, [], st.find(st, line, sink.bits(t, cls), name)}}
        case KMask{m}:
          JDone{Res{U32.and(t, m), [], st}}
        case KOr{t2}:
          JDone{Res{tor(t, t2), [], st}}
        case KAsg{lhs, op}:
          JDone{asg_st(lhs, op, t, st)}
        case KTern{a, b}:
          k.tern(a, b, t, st)
        case KParts{mode, ps, acc}:
          Parts{mode, ps, st, tor(acc, t)}
        case KArgs{ps, acc}:
          Args{ps, st, Con{t, acc}}
        case KPipe{ps, line}:
          k.pipe(ps, line, t, st)
        case KPost{path, ns}:
          Post{t, path, ns, st}
        case KPostI{t0, ns}:
          Post{t0, "", ns, st}
        case KCall{+ci}:
          JThen{JDone{call_apply(ci, ts, st, cx)}, KPost{"", ci_rest(ci)}}
        case KClo{env, ret}:
          JDone{Res{0, [], st.restore(env, ret, st)}}
        case KStmts{ns}:
          Stmts{ns, st}
        case KBlock{pre}:
          JDone{Res{0, [], st.join(pre, st)}}
        case KHdr{ns}:
          Body{ns, st}
        case KFe{target, rest}:
          Body{rest, st.set_all(vars_in(target, []), t, st)}
        case KRet{}:
          JDone{Res{0, [], st.ret(st, t)}}

def j.asg(sp: Sp, st: St) -> Job:
  match sp:
    case Sp{lhs, op, rhs}:
      JThen{Ex{rhs, st}, KAsg{lhs, op}}

def j.tern(th: Three, st: St) -> Job:
  match th:
    case Three{c, a, b}:
      JThen{Ex{c, st}, KTern{a, b}}

def j.clo(two: Two, +st: St) -> Job:
  match two:
    case Two{Nil{}, b}:
      JThen{Stmts{b, st}, KClo{st.env(st), st_ret(st)}}
    case Two{a, b}:
      JThen{Ex{a, st}, KClo{st.env(st), st_ret(st)}}

def j.new(two: Two, st: St) -> Job:
  match two:
    case Two{args, after}:
      JThen{JThen{Args{args_of(args), st, []}, KMask{0}}, KPost{"", after}}

def j.exl(ns: List<&2, T.Node>, +code: U32, st: St) -> Job:
  match ns:
    case Nil{}:
      JDone{Res{0, [], st}}
    case Con{+h, +rest}:
      match code:
        case 110:
          JThen{Ex{rest, st}, KSink{8, node_line(h), "print"}}
        case 111:
          JThen{Ex{rest, st}, KSink{32, node_line(h), "include"}}
        case 112:
          Ex{rest, st}
        case 102:
          j.clo(clo_split(Con{h, rest}), st)
        case 3:
          j.asg(split_asg(Con{h, rest}), st)
        case 4:
          j.tern(tern.split(split_at(Con{h, rest}, 5, "?")), st)
        case 10:
          PipeS{split_level(Con{h, rest}, 10), node_line(h), st}
        case 0:
          Prim{Con{h, rest}, st}
        case _:
          Parts{level_mode(code), split_level(Con{h, rest}, code), st, 0}

# Token kind of a leaf (0..8) or bracket kind of a group (35, 40, 91, 123).
def node_code(n: T.Node) -> U32:
  match n:
    case T.Leaf{L.Tok{k, s, l}}:
      k
    case T.Grp{k, l, ks}:
      k

def leaf_text(n: T.Node) -> String:
  match n:
    case T.Leaf{L.Tok{k, s, l}}:
      s
    case T.Grp{k, l, ks}:
      ""

def id_code(s: String) -> U32:
  match s:
    case "new":
      1
    case "clone":
      2
    case "match":
      3
    case "array":
      4
    case "list":
      4
    case "isset":
      5
    case "empty":
      5
    case _:
      0

def arrow_code(s: String) -> U32:
  match s:
    case "->":
      1
    case "?->":
      1
    case "::":
      2
    case _:
      0

def j.match(rest: List<&2, T.Node>, st: St) -> Job:
  match rest:
    case Con{T.Grp{40, l2, c}, Con{T.Grp{123, l3, arms}, r}}:
      JThen{Parts{1, Con{c, args_of(arms)}, st, 0}, KPost{"", r}}
    case other:
      Post{0, "", other, st}

def j.arr(rest: List<&2, T.Node>, st: St) -> Job:
  match rest:
    case Con{T.Grp{40, l2, ks}, r}:
      JThen{Parts{1, args_of(ks), st, 0}, KPost{"", r}}
    case other:
      Post{0, "", other, st}

def j.isset(rest: List<&2, T.Node>, st: St) -> Job:
  match rest:
    case Con{T.Grp{40, l2, ks}, r}:
      Post{0, "", r, st}
    case other:
      Post{0, "", other, st}

# `C::m(args)` or `C::x`.
def j.static(rest: List<&2, T.Node>, +c: String, +t: U32, st: St) -> Job:
  match rest:
    case Con{T.Leaf{L.Tok{1, m, l3}}, Con{T.Grp{40, l4, args}, r}}:
      Call{mk_call(2, m, c, l3, t, args, r), st}
    case Con{x, r}:
      Post{0, "", r, st}
    case Nil{}:
      Post{0, "", [], st}

def j.idcall(rest: List<&2, T.Node>, +s: String, +l: U32, +st: St) -> Job:
  match rest:
    case Con{T.Grp{40, l2, args}, r}:
      Call{mk_call(0, s, "", l, 0, args, r), st}
    case Con{T.Leaf{L.Tok{5, +op, +l2}}, +r}:
      L.sel(Job, String.eq(op, "::"), u => j.static(r, s, 0, st), u => Post{0, "", Con{T.Leaf{L.Tok{5, op, l2}}, r}, st})
    case other:
      Post{0, "", other, st}

def j.id(rest: List<&2, T.Node>, code: U32, +s: String, +l: U32, st: St) -> Job:
  match code:
    case 1:
      j.new(new_split(rest), st)
    case 2:
      Prim{rest, st}
    case 3:
      j.match(rest, st)
    case 4:
      j.arr(rest, st)
    case 5:
      j.isset(rest, st)
    case _:
      j.idcall(rest, s, l, st)

def j.prim1(+rest: List<&2, T.Node>, code: U32, +s: String, +l: U32, +h: T.Node, +st: St) -> Job:
  match code:
    case 5:
      L.sel(Job, clean_prefix(s), u => JThen{Prim{rest, st}, KMask{0}}, u => Prim{rest, st})
    case 6:
      L.sel(Job, int_cast(s), u => JThen{Prim{rest, st}, KMask{0}}, u => Prim{rest, st})
    case 1:
      j.id(rest, id_code(s), s, l, st)
    case 0:
      Post{var_t(s, rest, st.env(st)), s, rest, st}
    case 3:
      Post{istr(st.env(st), s), "", rest, st}
    case 7:
      +t = istr(st.env(st), s)
      Post{t, "", rest, st.find(st, l, sink.bits(t, 2), "backtick")}
    case 40:
      JThen{Ex{node_kids(h), st}, KPost{"", rest}}
    case 91:
      JThen{Parts{1, args_of(node_kids(h)), st, 0}, KPost{"", rest}}
    case 123:
      Prim{rest, st}
    case 35:
      Prim{rest, st}
    case _:
      Post{0, "", rest, st}

def j.prim(ns: List<&2, T.Node>, st: St) -> Job:
  match ns:
    case Nil{}:
      JDone{Res{0, [], st}}
    case Con{+h, rest}:
      j.prim1(rest, node_code(h), leaf_text(h), node_line(h), h, st)

def j.arrow2(r: List<&2, T.Node>, +m: String, +l2: U32, +t: U32, +path: String, +st: St) -> Job:
  match r:
    case Con{T.Grp{40, l3, args}, r2}:
      Call{mk_call(1, m, path, l2, t, args, r2), st}
    case other:
      +k = pkey(path, m)
      Post{env.get(st.env(st), k, t), k, other, st}

def j.arrow(rest: List<&2, T.Node>, +t: U32, +path: String, +st: St) -> Job:
  match rest:
    case Con{T.Leaf{L.Tok{1, m, l2}}, r}:
      j.arrow2(r, m, l2, t, path, st)
    case Con{x, r}:
      Post{t, "", r, st}
    case Nil{}:
      Post{t, "", [], st}

def j.postop(+rest: List<&2, T.Node>, code: U32, +t: U32, +path: String, +st: St) -> Job:
  match code:
    case 1:
      j.arrow(rest, t, path, st)
    case 2:
      j.static(rest, "", t, st)
    case _:
      Post{t, path, rest, st}

def j.post1(+rest: List<&2, T.Node>, code: U32, +s: String, +h: T.Node, +t: U32, +path: String, +st: St) -> Job:
  match code:
    case 91:
      JThen{Ex{node_kids(h), st}, KPostI{t, rest}}
    case 123:
      JThen{Ex{node_kids(h), st}, KPostI{t, rest}}
    case 40:
      Call{mk_call(3, "", "", node_line(h), t, node_kids(h), rest), st}
    case 5:
      j.postop(rest, arrow_code(s), t, path, st)
    case _:
      Post{t, path, rest, st}

def j.post(t: U32, path: String, ns: List<&2, T.Node>, st: St) -> Job:
  match ns:
    case Nil{}:
      JDone{Res{t, [], st}}
    case Con{+h, rest}:
      j.post1(rest, node_code(h), leaf_text(h), h, t, path, st)

def j.echo(two: Two, line: U32, st: St) -> Job:
  match two:
    case Two{e, rest}:
      JThen{JThen{Args{args_of(e), st, []}, KSink{8, line, "echo"}}, KStmts{rest}}

def j.ret(two: Two, st: St) -> Job:
  match two:
    case Two{e, rest}:
      JThen{JThen{Ex{e, st}, KRet{}}, KStmts{rest}}

def j.exs(two: Two, st: St) -> Job:
  match two:
    case Two{e, rest}:
      JThen{Ex{e, st}, KStmts{rest}}

def j.bodye(two: Two, st: St) -> Job:
  match two:
    case Two{e, rest}:
      JThen{Block{e, st}, KStmts{rest}}

def j.fe(two: Two, rest: List<&2, T.Node>, st: St) -> Job:
  match two:
    case Two{e, target}:
      JThen{Ex{e, st}, KFe{target, rest}}

def j.block(ns: List<&2, T.Node>, st: St) -> Job:
  match ns:
    case Con{T.Grp{k, l, ks}, rest}:
      JThen{Block{ks, st}, KStmts{rest}}
    case Con{n, rest}:
      Stmts{rest, st}
    case Nil{}:
      JDone{Res{0, [], st}}

# After `if`/`while`/`switch`/`for`/`foreach`/`catch`: `(header) body`.
def j.hdr(ns: List<&2, T.Node>, +code: U32, st: St) -> Job:
  match ns:
    case Con{T.Grp{40, l, hdr}, rest}:
      match code:
        case 5:
          JThen{Ex{hdr, st}, KHdr{rest}}
        case 6:
          JThen{Parts{0, for_parts(split_all(hdr, ";")), st, 0}, KHdr{rest}}
        case 7:
          j.fe(split_at(hdr, 1, "as"), rest, st)
        case _:
          Body{rest, st}
    case Con{n, rest}:
      Stmts{rest, st}
    case Nil{}:
      JDone{Res{0, [], st}}

def j.default(ns: List<&2, T.Node>, st: St) -> Job:
  match ns:
    case Con{T.Leaf{L.Tok{5, ":", l}}, rest}:
      Stmts{rest, st}
    case other:
      Stmts{other, st}

def j.stmts(code: U32, +ns: List<&2, T.Node>, st: St) -> Job:
  match code:
    case 0:
      JDone{Res{0, [], st}}
    case 1:
      Stmts{drop1(ns), st}
    case 2:
      j.block(ns, st)
    case 3:
      j.echo(split_at(drop1(ns), 5, ";"), first_line(ns), st)
    case 4:
      j.ret(split_at(drop1(ns), 5, ";"), st)
    case 5:
      j.hdr(drop1(ns), 5, st)
    case 6:
      j.hdr(drop1(ns), 6, st)
    case 7:
      j.hdr(drop1(ns), 7, st)
    case 15:
      j.hdr(drop1(ns), 15, st)
    case 8:
      Body{drop1(ns), st}
    case 9:
      Stmts{two.b(split_at(drop1(ns), 5, ":")), st}
    case 16:
      j.default(drop1(ns), st)
    case 10:
      Stmts{skip_brace(drop1(ns)), st}
    case 11:
      Stmts{skip_brace(drop1(ns)), st}
    case 12:
      Stmts{ns_body(drop1(ns)), st}
    case 13:
      Stmts{two.b(split_at(drop1(ns), 5, ";")), st}
    case 14:
      j.exs(split_at(ns, 5, ";"), st)
    case _:
      Stmts{drop1(ns), st}

def j.body(code: U32, +ns: List<&2, T.Node>, st: St) -> Job:
  match code:
    case 0:
      j.block(ns, st)
    case 1:
      Stmts{drop1(ns), st}
    case 2:
      Stmts{ns, st}
    case 3:
      j.bodye(split_at(ns, 5, ";"), st)
    case _:
      JDone{Res{0, [], st}}

def step(j: Job, +cx: Map<&2, Sum>) -> Job:
  match j:
    case Ex{+ns, st}:
      j.exl(ns, lead(ns), st)
    case Prim{ns, st}:
      j.prim(ns, st)
    case Post{t, path, ns, st}:
      j.post(t, path, ns, st)
    case Call{+ci, st}:
      JThen{Args{args_of(ci_args(ci)), st, []}, KCall{ci}}
    case Parts{mode, Nil{}, st, acc}:
      JDone{Res{b2t(nz(mode), acc), [], st}}
    case Parts{mode, Con{x, rest}, st, acc}:
      JThen{Ex{x, st}, KParts{mode, rest, acc}}
    case Args{Nil{}, st, +acc}:
      JDone{Res{or_list(acc), List.reverse(&2, U32, acc), st}}
    case Args{Con{x, rest}, st, acc}:
      JThen{Ex{x, st}, KArgs{rest, acc}}
    case PipeS{Nil{}, line, st}:
      JDone{Res{0, [], st}}
    case PipeS{Con{x, rest}, line, st}:
      JThen{Ex{x, st}, KPipe{rest, line}}
    case PipeC{"", part, t, st, line}:
      JThen{Ex{part, st}, KOr{t}}
    case PipeC{name, part, t, st, line}:
      JDone{call_apply(CallI{0, name, "", line, 0, 0, "", [], []}, [t], st, cx)}
    case Stmts{+ns, st}:
      j.stmts(stmt_kind(ns), ns, st)
    case Block{ns, +st}:
      JThen{Stmts{ns, st}, KBlock{st.env(st)}}
    case Body{+ns, st}:
      j.body(body_kind(ns), ns, st)
    case JDone{r}:
      JDone{r}
    case JThen{j2, k}:
      JThen{j2, k}

# Evaluate a job. The fuel bounds the evaluation depth; running out yields a
# cls-0 "fuel" finding so the caller can report an incomplete analysis.
def an(fuel: Nat, job: Job, +cx: Map<&2, Sum>) -> Res:
  match fuel:
    case 0n:
      Res{0, [], St{MTip{}, [Finding{0, 0, "fuel"}], 0, 0}}
    case 1n+(+p):
      match job:
        case JDone{r}:
          r
        case JThen{j, k}:
          an(p, step_k(an(p, j, cx), k, cx), cx)
        case j:
          an(p, step(j, cx), cx)

# ---------------------------------------------------------------- declarations

# Body of a declaration and what follows it: `{..}` or `;` (abstract).
def brace_split(ns: List<&2, T.Node>) -> Two:
  match ns:
    case Nil{}:
      Two{[], []}
    case Con{T.Grp{123, l, ks}, rest}:
      Two{ks, rest}
    case Con{T.Leaf{L.Tok{5, ";", l}}, rest}:
      Two{[], rest}
    case Con{n, rest}:
      brace_split(rest)

# A parameter type word: 1 numeric, 0 neutral, 2 anything else.
def ptype(s: String) -> U32:
  match s:
    case "int":
      1
    case "float":
      1
    case "bool":
      1
    case "true":
      1
    case "false":
      1
    case "null":
      0
    case "public":
      0
    case "private":
      0
    case "protected":
      0
    case "readonly":
      0
    case _:
      2

# state: 0 no type yet, 1 numeric types only, 2 another type.
def ptype_st(+st: U32, +p: U32) -> U32:
  L.sel(U32, U32.is_eq(p, 0), u => st, u => L.sel(U32, U32.is_eq(p, 2) || U32.is_eq(st, 2), v => 2, v => 1))

def param.go(ns: List<&2, T.Node>, +st: U32) -> Param:
  match ns:
    case Nil{}:
      Param{"", False{}}
    case Con{T.Leaf{L.Tok{0, v, l}}, r}:
      Param{v, U32.is_eq(st, 1)}
    case Con{T.Leaf{L.Tok{1, s, l}}, r}:
      param.go(r, ptype_st(st, ptype(s)))
    case Con{n, r}:
      param.go(r, st)

def params.go(xs: List<&2, List<&2, T.Node>>) -> List<&2, Param>:
  match xs:
    case Nil{}:
      []
    case Con{x, rest}:
      Con{param.go(x, 0), params.go(rest)}

def params(ps: List<&2, T.Node>) -> List<&2, Param>:
  params.go(split_all(ps, ","))

type DW is Data:
  DW{ns: List<&2, T.Node>, inclass: Bool}

type DS is Data:
  DS{work: List<&2, DW>, acc: List<&2, Decl>}

def decl_code(s: String) -> U32:
  match s:
    case "function":
      1
    case "class":
      2
    case "interface":
      2
    case "trait":
      2
    case "enum":
      2
    case _:
      0

def drop_amp(ns: List<&2, T.Node>) -> List<&2, T.Node>:
  match ns:
    case Con{T.Leaf{L.Tok{5, "&", l}}, r}:
      r
    case other:
      other

def dkey(ic: Bool, +name: String) -> String:
  match ic:
    case True{}:
      "->" ++ String.to_lower(name)
    case False{}:
      String.to_lower(name)

def dstep.fn2(two: Two, +key: String, ps: List<&2, Param>, +ic: Bool, work: List<&2, DW>, acc: List<&2, Decl>) -> DS:
  match two:
    case Two{+body, after}:
      DS{Con{DW{body, False{}}, Con{DW{after, ic}, work}}, Con{Decl{key, ps, body}, acc}}

def dstep.fn(rest: List<&2, T.Node>, +ic: Bool, work: List<&2, DW>, acc: List<&2, Decl>) -> DS:
  match rest:
    case Con{T.Leaf{L.Tok{1, name, l}}, Con{T.Grp{40, l2, ps}, r}}:
      dstep.fn2(brace_split(r), dkey(ic, name), params(ps), ic, work, acc)
    case other:
      DS{Con{DW{other, ic}, work}, acc}

def dstep.cls(two: Two, +ic: Bool, work: List<&2, DW>, acc: List<&2, Decl>) -> DS:
  match two:
    case Two{body, after}:
      DS{Con{DW{body, True{}}, Con{DW{after, ic}, work}}, acc}

def dstep.id(code: U32, rest: List<&2, T.Node>, +ic: Bool, work: List<&2, DW>, acc: List<&2, Decl>) -> DS:
  match code:
    case 1:
      dstep.fn(drop_amp(rest), ic, work, acc)
    case 2:
      dstep.cls(brace_split(rest), ic, work, acc)
    case _:
      DS{Con{DW{rest, ic}, work}, acc}

def dstep.h(code: U32, +s: String, +h: T.Node, +rest: List<&2, T.Node>, +ic: Bool, work: List<&2, DW>, acc: List<&2, Decl>) -> DS:
  match code:
    case 1:
      dstep.id(decl_code(s), rest, ic, work, acc)
    case 123:
      DS{Con{DW{node_kids(h), ic}, Con{DW{rest, ic}, work}}, acc}
    case 40:
      DS{Con{DW{node_kids(h), False{}}, Con{DW{rest, ic}, work}}, acc}
    case 91:
      DS{Con{DW{node_kids(h), False{}}, Con{DW{rest, ic}, work}}, acc}
    case _:
      DS{Con{DW{rest, ic}, work}, acc}

def dstep.w(ns: List<&2, T.Node>, ic: Bool, work: List<&2, DW>, acc: List<&2, Decl>) -> DS:
  match ns:
    case Nil{}:
      DS{work, acc}
    case Con{+h, rest}:
      dstep.h(node_code(h), leaf_text(h), h, rest, ic, work, acc)

def dstep(ds: DS) -> DS:
  match ds:
    case DS{Nil{}, acc}:
      DS{[], acc}
    case DS{Con{DW{ns, ic}, work}, acc}:
      dstep.w(ns, ic, work, acc)

# Every function and method declaration, at any depth.
def decls(fuel: Nat, ds: DS) -> List<&2, Decl>:
  match fuel ds:
    case 0n DS{w, acc}:
      acc
    case 1n+p DS{Nil{}, acc}:
      acc
    case 1n+p d:
      decls(p, dstep(d))

# ---------------------------------------------------------------- summaries

def bind(ps: List<&2, Param>, +idx: U32, +i: U32, +env: Map<&2, U32>, seed: Seed) -> Map<&2, U32>:
  match ps seed:
    case Nil{} s:
      env
    case Con{Param{name, num}, rest} SrcSeed{}:
      bind(rest, idx, U32.add(i, 1), env.set(env, name, b2t(U32.is_eq(i, idx) && Bool.not(num), SRC())), SrcSeed{})
    case Con{Param{name, num}, rest} MarkerSeed{}:
      bind(rest, idx, U32.add(i, 1), env.set(env, name, b2t(U32.is_eq(i, idx) && Bool.not(num), U32.or(SRC(), SUMMARY_MARKER()))), MarkerSeed{})

# Analyze a declaration's body with parameter idx bound to request input or a summary marker.
def run(fuel: Nat, d: Decl, +idx: U32, +cx: Map<&2, Sum>, seed: Seed) -> Res:
  match d:
    case Decl{key, ps, body}:
      an(fuel, Stmts{body, St{bind(ps, idx, 0, MTip{}, seed), [], 0, 0}}, cx)

def res_st(r: Res) -> St:
  match r:
    case Res{t, ts, st}:
      st

def fs.has(fs: List<&2, Finding>, +line: U32, +cls: U32) -> Bool:
  match fs:
    case Nil{}:
      False{}
    case Con{Finding{l, c, s}, rest}:
      (U32.is_eq(l, line) && U32.is_eq(c, cls)) || fs.has(rest, line, cls)

# OR of the classes of findings in fs that are not in base.
def fs.new(fs: List<&2, Finding>, +base: List<&2, Finding>) -> U32:
  match fs:
    case Nil{}:
      0
    case Con{Finding{+l, +c, s}, rest}:
      tor(b2t(Bool.not(fs.has(base, l, c)), c), fs.new(rest, base))

type PS is Data:
  PS{prop: U32, sink: U32, revived: U32}

def sum.one(fuel: Nat, +d: Decl, +i: U32, +cx: Map<&2, Sum>, +base: List<&2, Finding>, p: Param) -> PS:
  match p:
    case Param{name, True{}}:
      PS{0, 0, 0}
    case Param{name, False{}}:
      +st = res_st(run(fuel, d, i, cx, MarkerSeed{}))
      PS{U32.and(st_ret(st), SRC()), fs.new(st.fs(st), base), st.revived(st)}

def sum.params(ps: List<&2, Param>, +fuel: Nat, +d: Decl, +i: U32, +cx: Map<&2, Sum>, +base: List<&2, Finding>) -> List<&2, PS>:
  match ps:
    case Nil{}:
      []
    case Con{p, rest}:
      x xs = sum.one(fuel, d, i, cx, base, p) sum.params(rest, fuel, d, U32.add(i, 1), cx, base)
      Con{x, xs}

def ps.props(xs: List<&2, PS>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      []
    case Con{PS{a, b, c}, rest}:
      Con{a, ps.props(rest)}

def ps.sinks(xs: List<&2, PS>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      []
    case Con{PS{a, b, c}, rest}:
      Con{b, ps.sinks(rest)}

def ps.revived(xs: List<&2, PS>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      []
    case Con{PS{a, b, c}, rest}:
      Con{c, ps.revived(rest)}

type KS is Data:
  KS{key: String, sum: Sum}

def decl_ps(d: Decl) -> List<&2, Param>:
  match d:
    case Decl{key, ps, body}:
      ps

def decl_key(d: Decl) -> String:
  match d:
    case Decl{key, ps, body}:
      key

def sum.decl(+fuel: Nat, +d: Decl, +cx: Map<&2, Sum>) -> KS:
  +st = res_st(run(fuel, d, 65535, cx, SrcSeed{}))
  +xs = sum.params(decl_ps(d), fuel, d, 0, cx, st.fs(st))
  KS{decl_key(d), Sum{st_ret(st), ps.props(xs), ps.sinks(xs), ps.revived(xs)}}

def sum.decls(ds: List<&2, Decl>, +fuel: Nat, +cx: Map<&2, Sum>) -> List<&2, KS>:
  match ds:
    case Nil{}:
      []
    case Con{d, rest}:
      x xs = sum.decl(fuel, d, cx) sum.decls(rest, fuel, cx)
      Con{x, xs}

def zip_or_list(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  match a b:
    case Nil{} b2:
      b2
    case Con{x, xr} Nil{}:
      Con{x, xr}
    case Con{x, xr} Con{y, yr}:
      Con{tor(x, y), zip_or_list(xr, yr)}

# Same-named methods in different classes share one key: OR them.
def sum.merge(a: Sum, b: Sum) -> Sum:
  match a b:
    case NoSum{} b2:
      b2
    case Sum{s, p, k, r} NoSum{}:
      Sum{s, p, k, r}
    case Sum{s, p, k, r} Sum{s2, p2, k2, r2}:
      Sum{tor(s, s2), zip_or_list(p, p2), zip_or_list(k, k2), zip_or_list(r, r2)}

def sum.put(kss: List<&2, KS>, +m: Map<&2, Sum>) -> Map<&2, Sum>:
  match kss:
    case Nil{}:
      m
    case Con{KS{+k, s}, rest}:
      sum.put(rest, Map.set(&2, Sum, m, k, sum.merge(sum.get(m, k), s)))

def round(+ds: List<&2, Decl>, +fuel: Nat, +cx: Map<&2, Sum>) -> Map<&2, Sum>:
  sum.put(sum.decls(ds, fuel, cx), MTip{})

# Baseline findings of every declaration body.
def decl_fs(ds: List<&2, Decl>, +fuel: Nat, +cx: Map<&2, Sum>) -> List<&2, Finding>:
  match ds:
    case Nil{}:
      []
    case Con{d, rest}:
      a b = st.fs(res_st(run(fuel, d, 65535, cx, SrcSeed{}))) decl_fs(rest, fuel, cx)
      List.concat(&2, Finding, [a, b])

# ---------------------------------------------------------------- entry

def toks.code(ts: List<&2, L.Tok>) -> List<&2, L.Tok>:
  match ts:
    case Nil{}:
      []
    case Con{L.Tok{8, s, l}, rest}:
      toks.code(rest)
    case Con{t, rest}:
      Con{t, toks.code(rest)}

# Lines a `phpscan-ignore` comment covers: its own line when it trails code,
# the next line when it stands alone.
def toks.ign(ts: List<&2, L.Tok>, +last: U32) -> List<&2, U32>:
  match ts:
    case Nil{}:
      []
    case Con{L.Tok{8, s, +l}, +rest}:
      L.sel(List<&2, U32>, U32.is_eq(l, last), u => Con{l, toks.ign(rest, last)}, u => Con{U32.add(l, 1), toks.ign(rest, last)})
    case Con{L.Tok{k, s, +l}, rest}:
      toks.ign(rest, l)

def u32.has(xs: List<&2, U32>, +x: U32) -> Bool:
  match xs:
    case Nil{}:
      False{}
    case Con{y, rest}:
      U32.is_eq(x, y) || u32.has(rest, x)

def suppress(fs: List<&2, Finding>, +ign: List<&2, U32>) -> List<&2, Finding>:
  match fs:
    case Nil{}:
      []
    case Con{Finding{+l, c, s}, +rest}:
      L.sel(List<&2, Finding>, u32.has(ign, l), u => suppress(rest, ign), u => Con{Finding{l, c, s}, suppress(rest, ign)})

def f.lt(a: Finding, b: Finding) -> Bool:
  match a b:
    case Finding{+l, c, s} Finding{+l2, c2, s2}:
      U32.is_lt(l, l2) || (U32.is_eq(l, l2) && U32.is_lt(c, c2))

def f.same(a: Finding, b: Finding) -> Bool:
  match a b:
    case Finding{l, c, s} Finding{l2, c2, s2}:
      U32.is_eq(l, l2) && U32.is_eq(c, c2)

# Insert keeping (line, cls) order and dropping duplicates.
def f.ins(xs: List<&2, Finding>, +f: Finding) -> List<&2, Finding>:
  match xs:
    case Nil{}:
      [f]
    case Con{+x, +rest}:
      L.sel(List<&2, Finding>, f.same(f, x), u => Con{x, rest}, u => L.sel(List<&2, Finding>, f.lt(f, x), v => Con{f, Con{x, rest}}, v => Con{x, f.ins(rest, f)}))

def f.sort(xs: List<&2, Finding>, +acc: List<&2, Finding>) -> List<&2, Finding>:
  match xs:
    case Nil{}:
      acc
    case Con{x, rest}:
      f.sort(rest, f.ins(acc, x))

# Scan one PHP source file. A finding with cls 0 means the analysis ran out
# of fuel and is incomplete.
def scan(src: String) -> List<&2, Finding>:
  +ts = L.lex(src)
  +ns = T.tree(toks.code(ts))
  +fuel = Nat.add(Nat.mul(List.length(&2, L.Tok, ts), 16n), 4096n)
  +ds = decls(fuel, DS{[DW{ns, False{}}], []})
  +cx = round(ds, fuel, round(ds, fuel, round(ds, fuel, MTip{})))
  top fs2 = st.fs(res_st(an(fuel, Stmts{ns, St{MTip{}, [], 0, 0}}, cx))) decl_fs(ds, fuel, cx)
  f.sort(suppress(List.concat(&2, Finding, [top, fs2]), toks.ign(ts, 0)), [])
