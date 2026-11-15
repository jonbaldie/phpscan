import Base
import ../src/scan.bend as S
import ../src/lex.bend as L

def render(fs: List<&2, S.Finding>) -> String:
  match fs:
    case Nil{}:
      ""
    case Con{S.Finding{line, cls, sink}, rest}:
      U32.show(line) ++ ":" ++ U32.show(cls) ++ ":" ++ sink ++ ";" ++ render(rest)

def main() -> U32:
  ok = String.eq(render(S.scan("<?php\necho -$_GET[\"x\"];\n echo $_GET[\"x\"] + 1;\n echo $_GET[\"x\"] . \"!\";\n echo 1 < $_GET[\"x\"];\n")), "4:8:echo;") &&
    String.eq(render(S.scan("<?php\n$x=$_GET[\"x\"];\n $y=$x?\"clean\":\"safe\";\n echo $y;\n $y=$x?:\"safe\";\n echo $y;\n echo $x??\"safe\";\n")), "6:8:echo;7:8:echo;") &&
    String.eq(render(S.scan("<?php\n$x=$_GET[\"x\"];\n $x=\"safe\";\n echo $x;\n $x[0]=$_GET[\"x\"];\n $x[0]=\"safe\";\n echo $x;\n")), "7:8:echo;") &&
    String.eq(render(S.scan("<?php\n$a->p=$_GET[\"x\"];\n echo $a->p;\n $a->p=\"safe\";\n echo $a->p;\n $a->p->q=$_GET[\"x\"];\n echo $a->p;\n echo $a->p[0]->q;\n")), "3:8:echo;7:8:echo;8:8:echo;") &&
    String.eq(render(S.scan("<?php\n$x=\"safe\";\n if ($ok) {$x=$_GET[\"x\"];\n} echo $x;\n $x=$_GET[\"x\"];\n if ($ok) {$x=\"safe\";\n} echo $x;\n")), "4:8:echo;7:8:echo;") &&
    String.eq(render(S.scan("<?php\n$x=\"safe\";\n $f=function() {$x=$_GET[\"x\"];\n echo $x;\n};\n echo $x;\n $g=fn()=>($_GET[\"x\"]);\n echo $g;\n")), "4:8:echo;") &&
    String.eq(render(S.scan("<?php\nfunction n(int|float|null $x){echo $x;\n} function s(int|string $x){echo $x;\n} n($_GET[\"x\"]);\n s($_GET[\"x\"]);\n")), "5:8:s();") &&
    String.eq(render(S.scan("<?php\nfunction dec($x){file_get_contents(html_entity_decode($x));\n} function plain($x){file_get_contents($x);\n} dec(basename($_GET[\"x\"]));\n plain(basename($_GET[\"x\"]));\n")), "4:16:dec();") &&
    String.eq(render(S.scan("<?php\nfunction a($x){return b($x);\n} function b($x){return c($x);\n} function c($x){return $x;\n} echo a($_GET[\"x\"]);\n")), "5:8:echo;") &&
    String.eq(render(S.scan("<?php\nclass A{function f($x){echo $x;\n}} class B{function f(int $x){return $x;\n}} $a->f($_GET[\"x\"]);\n")), "4:8:->f();") &&
    String.eq(render(S.scan("<?php\nparse_str($_GET[\"x\"], $out);\n echo $out;\n parse_str($_GET[\"x\"]);\n curl_setopt($c,CURLOPT_URL,$_GET[\"x\"]);\n echo call_user_func(\"htmlspecialchars\",$_GET[\"x\"]);\n")), "3:8:echo;4:512:parse_str;5:64:curl_setopt;") &&
    String.eq(render(S.scan("<?php\necho match($_GET[\"x\"]){1=>\"safe\",default=>\"clean\"};\n foreach($_GET[\"x\"] as $v){echo $v;\n} for($x=$_GET[\"x\"];\n $x;\n $x=\"safe\"){echo $x;\n}")), "2:8:echo;3:8:echo;") &&
    String.eq(render(S.scan("<?php\nfunction outer(){function inner($x){echo $x;\n}} inner($_GET[\"x\"]);\n")), "3:8:inner();") &&
    String.eq(render(S.scan("<?php\necho htmlspecialchars($_GET[\"x\"]);\n echo html_entity_decode(htmlspecialchars($_GET[\"x\"]));\n")), "3:8:echo;") &&
    String.eq(render(S.scan("<?php\n$x=$_GET[\"x\"];\n $x+=1;\n echo $x;\n $x.=\"!\";\n echo $x;\n $x??=\"safe\";\n echo $x;\n")), "4:8:echo;6:8:echo;8:8:echo;") &&
    String.eq(render(S.scan("<?php\necho $_GET[\"x\"] |> htmlspecialchars(...);\necho $_GET[\"x\"] |> unknown(...);\necho $_GET[\"x\"] |> \"safe\";\n")), "3:8:echo;4:8:echo;") &&
    String.eq(render(S.scan("<?php\necho call_user_func([], $_GET[\"x\"]);\necho call_user_func(\"->\", $_GET[\"x\"]);\necho call_user_func([\"A\",\"escape\"], $_GET[\"x\"]);\necho call_user_func(\"->escape\", $_GET[\"x\"]);\n")), "2:8:echo;3:8:echo;4:8:echo;5:8:echo;") &&
    String.eq(render(S.scan("<?php\nclass A { function m(){ function nested($x){echo $x;} } }\nnested($_GET[\"x\"]);\n")), "3:8:nested();") &&
    String.eq(render(S.scan("<?php\nclass A { (function paren($x){echo $x;}); [function bracket($x){echo $x;}]; }\nparen($_GET[\"x\"]);\nbracket($_GET[\"x\"]);\n")), "3:8:paren();4:8:bracket();") &&
    String.eq(render(S.scan("<?php\necho $_ENV[\"x\"];\necho $GLOBALS[\"x\"];\necho $_SERVER[\"REQUEST_METHOD\"];\necho $_SERVER[\"QUERY_STRING\"];\necho $_FILES[\"a\"][\"size\"];\necho $_FILES[\"a\"][\"name\"];\n")), "5:8:echo;7:8:echo;") &&
    String.eq(render(S.scan("<?php\n$x=$_GET[\"x\"];\n$x->unknown();\necho $x->unknown();\necho $x->escape();\necho A::unknown($_GET[\"x\"]);\n$x();\n")), "4:8:echo;6:8:echo;7:4:dynamic call;") &&
    String.eq(render(S.scan("<?php\nfunction a($x){return b($x);}\nfunction b($x){return c($x);}\nfunction c($x){return d($x);}\nfunction d($x){return \"safe\";}\necho a($_GET[\"x\"]);\n")), "6:8:echo;") &&
    String.eq(render(S.scan("<?php\nfunction n(null|int $x){echo $x;}\nfunction mixed(string|int $x){echo $x;}\nfunction untyped($x){echo $x;}\nn($_GET[\"x\"]);\nmixed($_GET[\"x\"]);\nuntyped($_GET[\"x\"]);\n")), "6:8:mixed();7:8:untyped();") &&
    String.eq(render(S.scan("<?php\nfunction a($x){return b($x); }\nfunction b($x){return c($x); }\nfunction c($x){return \"safe\";}\necho a($_GET[\"x\"]);\n")), "")
  L.sel(U32, ok, u => 0, u => 1)
