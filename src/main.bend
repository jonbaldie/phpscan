import Base
import ./scan.bend as S
import ./lex.bend as L
import ./version.bend as V
import ./advisories.bend as A
import ./catalog.bend as C

# phpscan: taint-tracking vulnerability scanner for PHP sources, for CI.
#
#   phpscan [--format=text|github|sarif] <file-or-dir>...
#
# Directories are searched for *.php, *.phtml and *.inc files. Exit status:
# 0 no findings, 1 findings, 2 usage or I/O error or an incomplete analysis.

type Src is Data:
  Src{path: String, text: String}

type Rep is Data:
  Rep{path: String, fs: List<&2, S.Finding>}
  Inventory{path: String, fs: List<&2, A.Finding>}

type Opts is Data:
  Opts{fmt: U32, paths: List<&2, String>, bad: String}

# ---------------------------------------------------------------- classes

def cls_id(c: U32) -> String:
  match c:
    case 1:
      "PHP-SQLI"
    case 2:
      "PHP-CMDI"
    case 4:
      "PHP-CODEI"
    case 8:
      "PHP-XSS"
    case 16:
      "PHP-PATH"
    case 32:
      "PHP-LFI"
    case 64:
      "PHP-SSRF"
    case 128:
      "PHP-DESER"
    case 256:
      "PHP-HEADER"
    case 512:
      "PHP-VAROVR"
    case _:
      "PHP-INCOMPLETE"

def cls_cwe(c: U32) -> String:
  match c:
    case 1:
      "CWE-89"
    case 2:
      "CWE-78"
    case 4:
      "CWE-95"
    case 8:
      "CWE-79"
    case 16:
      "CWE-22"
    case 32:
      "CWE-98"
    case 64:
      "CWE-918"
    case 128:
      "CWE-502"
    case 256:
      "CWE-113"
    case 512:
      "CWE-621"
    case _:
      "none"

def cls_text(c: U32) -> String:
  match c:
    case 1:
      "SQL injection"
    case 2:
      "OS command injection"
    case 4:
      "code injection"
    case 8:
      "cross-site scripting"
    case 16:
      "path traversal"
    case 32:
      "file inclusion"
    case 64:
      "server-side request forgery"
    case 128:
      "unsafe deserialization"
    case 256:
      "header injection"
    case 512:
      "variable overwrite"
    case _:
      "analysis incomplete"

def msg(+c: U32, s: String) -> String:
  L.sel(String, U32.is_eq(c, 0),
    u => "analysis ran out of fuel; this file was not fully checked",
    u => cls_text(c) ++ ": request data reaches " ++ s ++ " (" ++ cls_cwe(c) ++ ")")

# ---------------------------------------------------------------- formats

def text.one(+path: String, f: S.Finding) -> String:
  match f:
    case S.Finding{l, +c, s}:
      path ++ ":" ++ U32.show(l) ++ ": [" ++ cls_id(c) ++ "] " ++ msg(c, s) ++ "\n"

def gh.ch(c: Char) -> String:
  match c:
    case '%':
      "%25"
    case '\r':
      "%0D"
    case '\n':
      "%0A"
    case ':':
      "%3A"
    case ',':
      "%2C"
    case c:
      SCon{c, SNil{}}

def gh.escape(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{c, rest}:
      gh.ch(c) ++ gh.escape(rest)

def gh.one(+path: String, f: S.Finding) -> String:
  match f:
    case S.Finding{l, +c, s}:
      "::error file=" ++ gh.escape(path) ++ ",line=" ++ U32.show(l) ++ ",title=phpscan " ++ cls_id(c) ++ "::" ++ gh.escape(msg(c, s)) ++ "\n"

def json.ch(c: Char) -> String:
  +k = Char.to_u32(c)
  L.sel(String, U32.is_eq(k, 34), u => "\\\"",
    u => L.sel(String, U32.is_eq(k, 92), v => "\\\\",
      v => L.sel(String, U32.is_lt(k, 32), w => " ", w => SCon{Char.from_u32(k), SNil{}})))

def json.go(cs: List<&2, Char>) -> String:
  match cs:
    case Nil{}:
      ""
    case Con{c, rest}:
      json.ch(c) ++ json.go(rest)

def json.str(s: String) -> String:
  "\"" ++ json.go(String.to_list(s)) ++ "\""

def sarif.one(+path: String, f: S.Finding) -> String:
  match f:
    case S.Finding{+l, +c, s}:
      "{\"ruleId\":" ++ json.str(cls_id(c)) ++ ",\"level\":" ++ json.str(L.sel(String, U32.is_eq(c, 0), u => "warning", u => "error")) ++
      ",\"message\":{\"text\":" ++ json.str(msg(c, s)) ++ "},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":" ++
      json.str(path) ++ "},\"region\":{\"startLine\":" ++ U32.show(L.sel(U32, U32.is_eq(l, 0), u => 1, u => l)) ++ "}}}]}"

def fmt.one(fmt: U32, +path: String, f: S.Finding) -> String:
  match fmt:
    case 1:
      gh.one(path, f)
    case 2:
      sarif.one(path, f)
    case _:
      text.one(path, f)

def fmt.fs(fs: List<&2, S.Finding>, +fmt: U32, +path: String) -> List<&2, String>:
  match fs:
    case Nil{}:
      []
    case Con{f, rest}:
      Con{fmt.one(fmt, path, f), fmt.fs(rest, fmt, path)}

def json.strings(xs: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      []
    case Con{x, rest}:
      Con{json.str(x), json.strings(rest)}

def advisory.props(f: A.Finding) -> String:
  match f:
    case A.Match{n, C.Advisory{id, cve, package, +lower, upper, fixed, provenance, sources, functions}, version, group}:
      "{\"evidenceKind\":\"dependency-version\",\"ghsa\":" ++ json.str(id) ++ ",\"cve\":" ++ json.str(cve) ++
      ",\"package\":" ++ json.str(package) ++ ",\"installedVersion\":" ++ json.str(version) ++
      ",\"dependencyGroup\":" ++ json.str(group) ++ ",\"affectedRange\":" ++ json.str(">=" ++ lower ++ ",<" ++ upper) ++
      ",\"fixedVersion\":" ++ json.str(fixed) ++ ",\"affectedCode\":\"unknown\",\"runtimeExposure\":\"unknown\",\"exploitability\":\"unknown\",\"deployment\":\"unknown\",\"vulnerableFunctions\":[" ++
      String.join(json.strings(functions), ",") ++ "],\"sources\":[" ++ String.join(json.strings(sources), ",") ++
      "],\"rangeProvenance\":" ++ json.str(provenance) ++ ",\"catalogDate\":" ++ json.str(C.snapshot_date()) ++ "}"
    case A.Unknown{n, reason}:
      "{\"evidenceKind\":\"unknown\"}"

def advisory.one(fmt: U32, +path: String, +f: A.Finding) -> String:
  match fmt:
    case 1:
      "::error file=" ++ gh.escape(path) ++ ",line=" ++ U32.show(A.line(f)) ++ ",title=phpscan " ++ A.rule(f) ++ "::" ++ gh.escape(A.message(f)) ++ "\n"
    case 2:
      "{\"ruleId\":" ++ json.str(A.rule(f)) ++ ",\"level\":" ++ json.str(L.sel(String, A.incomplete(f), u => "warning", u => "error")) ++
      ",\"message\":{\"text\":" ++ json.str(A.message(f)) ++ "},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":" ++
      json.str(path) ++ "},\"region\":{\"startLine\":" ++ U32.show(A.line(f)) ++ "}}}],\"properties\":" ++ advisory.props(f) ++ "}"
    case _:
      path ++ ":" ++ U32.show(A.line(f)) ++ ": [" ++ A.rule(f) ++ "] " ++ A.message(f) ++ "\n"

def advisory.fs(fs: List<&2, A.Finding>, +fmt: U32, +path: String) -> List<&2, String>:
  match fs:
    case Nil{}:
      []
    case Con{f, rest}:
      Con{advisory.one(fmt, path, f), advisory.fs(rest, fmt, path)}

def advisory.rules(rs: List<&2, C.Advisory>) -> List<&2, String>:
  match rs:
    case Nil{}:
      ["{\"id\":\"PHP-ADVISORY-INCOMPLETE\",\"shortDescription\":{\"text\":\"Dependency advisory analysis unknown\"}}"]
    case Con{C.Advisory{id, cve, package, lower, upper, fixed, provenance, sources, functions}, rest}:
      Con{"{\"id\":" ++ json.str(id) ++ ",\"shortDescription\":{\"text\":" ++ json.str(cve) ++ "}}", advisory.rules(rest)}

def fmt.reps(rs: List<&2, Rep>, +fmt: U32) -> List<&2, String>:
  match rs:
    case Nil{}:
      []
    case Con{Rep{+path, fs}, rest}:
      List.append(&2, String, fmt.fs(fs, fmt, path), fmt.reps(rest, fmt))
    case Con{Inventory{+path, fs}, rest}:
      List.append(&2, String, advisory.fs(fs, fmt, path), fmt.reps(rest, fmt))

def sarif.rule(+c: U32) -> String:
  "{\"id\":" ++ json.str(cls_id(c)) ++ ",\"name\":" ++ json.str(cls_text(c)) ++
  ",\"shortDescription\":{\"text\":" ++ json.str(cls_text(c)) ++ "},\"properties\":{\"tags\":[\"security\"," ++ json.str(cls_cwe(c)) ++ "]}}"

def sarif.doc(results: List<&2, String>) -> String:
  "{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"phpscan\",\"version\":" ++ json.str(V.value()) ++ ",\"rules\":[" ++
  String.join(List.append(&2, String, [sarif.rule(1), sarif.rule(2), sarif.rule(4), sarif.rule(8), sarif.rule(16), sarif.rule(32), sarif.rule(64), sarif.rule(128), sarif.rule(256), sarif.rule(512), sarif.rule(0)], advisory.rules(C.records())), ",") ++
  "]}},\"results\":[" ++ String.join(results, ",") ++ "]}]}\n"

def render(+fmt: U32, rs: List<&2, Rep>) -> String:
  match fmt:
    case 2:
      sarif.doc(fmt.reps(rs, 2))
    case f:
      String.concat(fmt.reps(rs, f))

def b.eq(a: Bool, b: Bool) -> Bool:
  match a:
    case True{}:
      b
    case False{}:
      Bool.not(b)

def count.fs(fs: List<&2, S.Finding>, +want0: Bool) -> U32:
  match fs:
    case Nil{}:
      0
    case Con{S.Finding{l, c, s}, rest}:
      U32.add(L.sel(U32, b.eq(U32.is_eq(c, 0), want0), u => 1, u => 0), count.fs(rest, want0))

# ---------------------------------------------------------------- status

def count.advisories(fs: List<&2, A.Finding>, +want0: Bool) -> U32:
  match fs:
    case Nil{}:
      0
    case Con{f, rest}:
      U32.add(L.sel(U32, b.eq(A.incomplete(f), want0), u => 1, u => 0), count.advisories(rest, want0))

def count(rs: List<&2, Rep>, +want0: Bool) -> U32:
  match rs:
    case Nil{}:
      0
    case Con{Rep{p, fs}, rest}:
      U32.add(count.fs(fs, want0), count(rest, want0))
    case Con{Inventory{p, fs}, rest}:
      U32.add(count.advisories(fs, want0), count(rest, want0))

def status(+n: U32, +inc: U32) -> U32:
  L.sel(U32, U32.is_lt(0, inc), u => 2, u => L.sel(U32, U32.is_lt(0, n), v => 1, v => 0))

def summary(nfiles: U32, +n: U32, +inc: U32) -> String:
  "phpscan: " ++ U32.show(nfiles) ++ " files, " ++ U32.show(n) ++ " findings, " ++ U32.show(inc) ++ " incomplete"

# ---------------------------------------------------------------- scanning

def scan1(x: Src) -> Rep:
  match x:
    case Src{+p, +t}:
      L.sel(Rep, String.eq(p, "composer.lock") || String.ends_with(p, "/composer.lock"),
        u => Inventory{p, A.scan(t)}, u => Rep{p, S.scan(t)})

def scan_seq(xs: List<&2, Src>) -> List<&2, Rep>:
  match xs:
    case Nil{}:
      []
    case Con{x, rest}:
      Con{scan1(x), scan_seq(rest)}

# Files are independent: scan them in parallel, splitting the list in halves
# so the two sides of each fork carry similar work.
def scan_all(n: Nat, xs: List<&2, Src>) -> List<&2, Rep>:
  match n xs:
    case n0 Nil{}:
      []
    case 0n Con{x, rest}:
      scan_seq(Con{x, rest})
    case 1n+p Con{x, Nil{}}:
      [scan1(x)]
    case 1n+(+p) Con{x, Con{y, rest}}:
      +ys = {Con{x, Con{y, rest}} : List<&2, Src>}
      +h = Nat.div(List.length(&2, Src, ys), 2n)
      a b = scan_all(p, List.take(&2, Src, ys, h)) scan_all(p, List.drop(&2, Src, ys, h))
      List.append(&2, Rep, a, b)

def finish(+fmt: U32, +nfiles: U32, +rs: List<&2, Rep>) -> IO(Unit):
  +n = count(rs, False{})
  +inc = count(rs, True{})
  do IO<Unit>:
    IO.write(render(fmt, rs))
    IO.print_err(summary(nfiles, n, inc))
    IO.exit(status(n, inc))

def nonempty(xs: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      []
    case Con{+x, +rest}:
      L.sel(List<&2, String>, String.is_empty(x), u => nonempty(rest), u => Con{x, nonempty(rest)})

def safe_path(+p: String) -> String:
  L.sel(String, String.starts_with(p, "-"), u => "./" ++ p, u => p)

def found(+p: String, r: Result<&1, &1, U32 & String, U32 & (String & String)>) -> IO(List<&2, String>):
  match r:
    case Fail{(code, m)}:
      IO.die(List<&2, String>, 2, "phpscan: cannot list " ++ p ++ ": " ++ m)
    case Done{(st, (out, err))}:
      L.sel(IO(List<&2, String>), U32.is_eq(st, 0),
        u => IO.pure(List<&2, String>, nonempty(String.lines(out))),
        u => IO.die(List<&2, String>, 2, "phpscan: cannot list " ++ p ++ ": " ++ String.trim_end(err)))

def list_one(+p: String) -> IO(List<&2, String>):
  do IO<List<&2, String>>:
    r : Result<&1, &1, U32 & String, U32 & (String & String)> <-
      Process.run("find", [safe_path(p), "-type", "f", "(", "-name", "*.php", "-o", "-name", "*.phtml", "-o", "-name", "*.inc", ")"], "", 268435456, 120000)
    sources : List<&2, String> <- found(p, r)
    locks : Result<&1, &1, U32 & String, U32 & (String & String)> <-
      Process.run("find", [safe_path(p), "-maxdepth", "1", "-type", "f", "-name", "composer.lock"], "", 268435456, 120000)
    inventory : List<&2, String> <- found(p, locks)
    return List.append(&2, String, sources, inventory)

def list_all(ps: List<&2, String>) -> IO(List<&2, String>):
  match ps:
    case Nil{}:
      IO.pure(List<&2, String>, [])
    case Con{+p, rest}:
      do IO<List<&2, String>>:
        a : List<&2, String> <- list_one(p)
        b : List<&2, String> <- list_all(rest)
        return List.append(&2, String, a, b)

def got(+p: String, r: Result<&1, &1, U32 & String, U32 & (String & String)>) -> IO(Src):
  match r:
    case Fail{(code, m)}:
      IO.die(Src, 2, "phpscan: cannot read " ++ p ++ ": " ++ m)
    case Done{(st, (out, err))}:
      L.sel(IO(Src), U32.is_eq(st, 0),
        u => IO.pure(Src, Src{p, out}),
        u => IO.die(Src, 2, "phpscan: cannot read " ++ p ++ ": " ++ String.trim_end(err)))

def read_one(+p: String) -> IO(Src):
  do IO<Src>:
    r : Result<&1, &1, U32 & String, U32 & (String & String)> <-
      Process.run("cat", ["--", p], "", 67108864, 60000)
    got(p, r)

def read_all(ps: List<&2, String>) -> IO(List<&2, Src>):
  match ps:
    case Nil{}:
      IO.pure(List<&2, Src>, [])
    case Con{+p, rest}:
      do IO<List<&2, Src>>:
        a : Src <- read_one(p)
        b : List<&2, Src> <- read_all(rest)
        return Con{a, b}

def str.le(a: String, b: String) -> Bool:
  String.is_le(a, b)

def scanned(+fmt: U32, +srcs: List<&2, Src>) -> IO(Unit):
  finish(fmt, U32.from_nat(List.length(&2, Src, srcs)), scan_all(64n, srcs))

def run(+fmt: U32, ps: List<&2, String>) -> IO(Unit):
  do IO<Unit>:
    files : List<&2, String> <- list_all(ps)
    srcs : List<&2, Src> <- read_all(List.sort(~String, ~str.le, files))
    scanned(fmt, srcs)

# ---------------------------------------------------------------- arguments

def fmt_code(s: String) -> U32:
  match s:
    case "text":
      0
    case "github":
      1
    case "sarif":
      2
    case _:
      99

def opt(+a: String, o: Opts) -> Opts:
  match o:
    case Opts{+f, +ps, +bad}:
      L.sel(Opts, String.starts_with(a, "--format="),
        u => Opts{fmt_code(String.drop(a, 9n)), ps, bad},
        u => L.sel(Opts, String.starts_with(a, "-") && Bool.not(String.eq(a, "-")),
          v => Opts{f, ps, a},
          v => Opts{f, Con{a, ps}, bad}))

def opts(as: List<&2, String>) -> Opts:
  match as:
    case Nil{}:
      Opts{0, [], ""}
    case Con{a, rest}:
      opt(a, opts(rest))

def usage() -> String:
  "usage: phpscan [--format=text|github|sarif] <file-or-dir>..."

def go(o: Opts) -> IO(Unit):
  match o:
    case Opts{+f, +ps, +bad}:
      L.sel(IO(Unit), Bool.not(String.is_empty(bad)), u => IO.die(Unit, 2, "phpscan: unknown option " ++ bad ++ "\n" ++ usage()),
        u => L.sel(IO(Unit), U32.is_eq(f, 99), v => IO.die(Unit, 2, "phpscan: unknown format\n" ++ usage()),
          v => L.sel(IO(Unit), List.is_empty(&2, String, ps), w => IO.die(Unit, 2, usage()),
            w => run(f, ps))))

def args_rest(as: List<&2, String>) -> List<&2, String>:
  match as:
    case Nil{}:
      []
    case Con{a, rest}:
      rest

def to2(xs: List<&1, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      []
    case Con{x, rest}:
      Con{x, to2(rest)}

def help() -> String:
  "phpscan " ++ V.value() ++ " - PHP taint scanner\n\n" ++ usage() ++
  "\n\nOptions:\n  --format=text|github|sarif  Output format (default: text)\n  --help, -h                 Show this help\n  --version                  Show the version\n\n" ++
  "Directories include .php, .phtml, and .inc files.\nProject roots also check composer.lock against the pinned offline catalog.\nFindings go to stdout; the summary goes to stderr.\nExit codes: 0 clean, 1 findings, 2 usage/I/O error or incomplete analysis.\n"

def entry(as: List<&2, String>) -> IO(Unit):
  match as:
    case Con{"--help", Nil{}}:
      IO.write(help())
    case Con{"-h", Nil{}}:
      IO.write(help())
    case Con{"--version", Nil{}}:
      IO.print("phpscan " ++ V.value())
    case other:
      go(opts(other))

def main() -> IO(Unit):
  do IO<Unit>:
    as : List<&1, String> <- IO.args()
    entry(args_rest(to2(as)))
