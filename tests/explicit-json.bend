import Base
import ../src/json.bend as J
import ../src/lex.bend as L

def present(r: Maybe<&2, J.Value>) -> Bool:
  match r:
    case Some{v}:
      True{}
    case None{}:
      False{}

def accepts(s: String) -> Bool:
  present(J.read(s))

def rejects(s: String) -> Bool:
  Bool.not(accepts(s))

def decoded(r: Maybe<&2, J.Value>, +text: String) -> Bool:
  match r:
    case Some{J.Str{line, value}}:
      U32.is_eq(line, 1) && String.eq(value, text)
    case _:
      False{}

def numbers() -> Bool:
  accepts("0") && accepts("-0") && accepts("9") && accepts("10") && accepts("-123") &&
    accepts("0.0") && accepts("-10.25") && accepts("0e0") && accepts("1E+2") && accepts("1.2e-30") &&
    rejects("") && rejects("-") && rejects("01") && rejects("-01") && rejects("+1") && rejects(".1") &&
    rejects("1.") && rejects("1e") && rejects("1e+") && rejects("1e-") && rejects("1.2.3") &&
    rejects("1a") && rejects("1e2e3") && rejects("--1") && rejects("00.1") && rejects("NaN")

def strings() -> Bool:
  decoded(J.read("\"\""), "") && decoded(J.read("\"plain\""), "plain") &&
    decoded(J.read("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\""), "\"\\/" ++ SCon{Char.from_u32(8), SCon{Char.from_u32(12), "\n\r\t"}}) &&
    decoded(J.read("\"\\u0041\\u00e9\""), "Aé") &&
    decoded(J.read("\"\\ud83d\\ude00\""), SCon{Char.from_u32(128512), SNil{}}) &&
    decoded(J.read("\"\\uD800\\uDC00\""), SCon{Char.from_u32(65536), SNil{}}) &&
    decoded(J.read("\"\\uDBFF\\uDFFF\""), SCon{Char.from_u32(1114111), SNil{}}) &&
    rejects("\"\\ud800\"") && rejects("\"\\udc00\"") && rejects("\"\\ud800\\u0041\"") &&
    rejects("\"\\ud800x\"") && rejects("\"\\ud800\\x0000\"") && rejects("\"\\u12\"") &&
    rejects("\"\\u12xz\"") && rejects("\"\\x\"") && rejects("\"line\ntext\"") && rejects("\"unterminated")

def nested(r: Maybe<&2, J.Value>) -> Bool:
  match r:
    case Some{J.Object{Con{J.Field{"first", J.Array{Con{J.Str{2, "x"}, Con{J.Other{}, Nil{}}}}}, Con{J.Field{"last", J.Object{Con{J.Field{"k", J.Str{3, "v"}}, Nil{}}}}, Nil{}}}}}:
      True{}
    case _:
      False{}

def grammar() -> Bool:
  accepts("[]") && accepts("{}") && accepts("[true,false,null]") &&
    nested(J.read("{\n\"first\":[\"x\",2],\n\"last\":{\"k\":\"v\"}}")) &&
    rejects("[1,]") && rejects("[,1]") && rejects("[1 2]") && rejects("[") && rejects("[1}") &&
    rejects("{\"x\":1,}") && rejects("{x:1}") && rejects("{\"x\" 1}") && rejects("{\"x\":}") &&
    rejects("{\"x\":1 \"y\":2}") && rejects("{\"x\":1,\"x\":2}") && rejects("{\"a\":1,\"\\u0061\":2}") &&
    rejects("true false") && rejects("[]x") && rejects("/*x*/null") && rejects("TRUE")

def no_tokens(r: Maybe<&2, List<&2, J.Token>>) -> Bool:
  match r:
    case None{}:
      True{}
    case _:
      False{}

def no_string(r: Maybe<&2, J.StringRest>) -> Bool:
  match r:
    case None{}:
      True{}
    case _:
      False{}

def empty_tokens(r: Maybe<&2, List<&2, J.Token>>) -> Bool:
  match r:
    case Some{Nil{}}:
      True{}
    case _:
      False{}

def quoted_text(r: Maybe<&2, J.StringRest>, +expected: String) -> Bool:
  match r:
    case Some{J.StringRest{actual, "tail"}}:
      String.eq(actual, expected)
    case _:
      False{}

def budgets() -> Bool:
  no_tokens(J.lex(0n, "", 1)) && empty_tokens(J.lex(1n, "", 1)) &&
    no_tokens(J.lex(1n, " ", 1)) && empty_tokens(J.lex(2n, " ", 1)) &&
    no_string(J.quoted(0n, "\"tail", [])) && quoted_text(J.quoted(1n, "\"tail", []), "") &&
    no_string(J.quoted(1n, "a\"tail", [])) && quoted_text(J.quoted(2n, "a\"tail", []), "a") &&
    quoted_text(J.quoted(2n, "\\u0041\"tail", []), "A") &&
    quoted_text(J.quoted(2n, "\\ud83d\\ude00\"tail", []), SCon{Char.from_u32(128512), SNil{}}) &&
    no_string(J.quoted(1n, "\\u0041\"tail", []))

def parsed(r: Maybe<&2, J.Parsed>) -> Bool:
  match r:
    case Some{J.Parsed{v, Nil{}}}:
      True{}
    case _:
      False{}

def parse_budgets() -> Bool:
  +empty = {[J.Punct{"["}, J.Punct{"]"}] : List<&2, J.Token>}
  +one = {[J.Punct{"["}, J.Literal{}, J.Punct{"]"}] : List<&2, J.Token>}
  +pair = {[J.Punct{"["}, J.Literal{}, J.Punct{","}, J.Literal{}, J.Punct{"]"}] : List<&2, J.Token>}
  +object = {[J.Punct{"{"}, J.Quoted{1, "key"}, J.Punct{":"}, J.Literal{}, J.Punct{"}"}] : List<&2, J.Token>}
  Bool.not(parsed(J.parse(0n, J.ParseValue{}, [J.Literal{}]))) &&
    Bool.not(parsed(J.parse(1n, J.ParseValue{}, empty))) && parsed(J.parse(2n, J.ParseValue{}, empty)) &&
    Bool.not(parsed(J.parse(2n, J.ParseValue{}, one))) && parsed(J.parse(3n, J.ParseValue{}, one)) &&
    Bool.not(parsed(J.parse(3n, J.ParseValue{}, pair))) && parsed(J.parse(4n, J.ParseValue{}, pair)) &&
    Bool.not(parsed(J.parse(3n, J.ParseValue{}, object))) && parsed(J.parse(4n, J.ParseValue{}, object))

def main() -> U32:
  L.sel(U32, numbers() && strings() && grammar() && budgets() && parse_budgets(), u => 0, u => 1)
