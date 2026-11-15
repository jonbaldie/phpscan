import Base
import ../src/scan.bend as S
import ../src/lex.bend as L

def findings(xs: List<&2, S.Finding>, ys: List<&2, S.Finding>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{S.Finding{l, c, s}, rest} Con{S.Finding{m, d, t}, tail}:
      U32.is_eq(l, m) && U32.is_eq(c, d) && String.eq(s, t) && findings(rest, tail)
    case _ _:
      False{}

def result(r: S.Res, +taint: U32, +returned: U32, +restored: U32, +stored: U32, +fs: List<&2, S.Finding>) -> Bool:
  match r:
    case S.Res{t, ts, S.St{env, actual, ret, revived}}:
      U32.is_eq(t, taint) && U32.is_eq(ret, returned) && U32.is_eq(revived, restored) &&
        U32.is_eq(S.env.get(env, "x", 0), stored) && findings(actual, fs)

def declarations(ds: List<&2, S.Decl>) -> Bool:
  match ds:
    case Con{S.Decl{key, ps, body}, Nil{}}:
      String.eq(key, "retained")
    case _:
      False{}

def main() -> U32:
  +st = {S.St{S.env.set(MTip{}, "x", 8), [S.Finding{3, 8, "echo"}], 1, 2} : S.St}
  +done = {S.JDone{S.Res{8, [], st}} : S.Job}
  +partial = {S.DS{[S.DW{[], S.InsideClass{}}], [S.Decl{"retained", [], []}]} : S.DS}
  ok = result(S.an(0n, done, MTip{}), 0, 0, 0, 0, [S.Finding{0, 0, "fuel"}]) &&
    result(S.an(1n, done, MTip{}), 8, 1, 2, 8, [S.Finding{3, 8, "echo"}]) &&
    result(S.an(1n, S.Stmts{[], st}, MTip{}), 0, 0, 0, 0, [S.Finding{0, 0, "fuel"}]) &&
    result(S.an(2n, S.Stmts{[], st}, MTip{}), 0, 1, 2, 8, [S.Finding{3, 8, "echo"}]) &&
    result(S.an(2n, S.JThen{done, S.KRet{}}, MTip{}), 0, 9, 2, 8, [S.Finding{3, 8, "echo"}]) &&
    declarations(S.decls(0n, partial)) && declarations(S.decls(1n, partial)) &&
    U32.is_eq(S.env.get(S.bind([S.Param{"x", S.UntypedParam{}}], S.BaselineParameter65535{}, 65535, MTip{}, S.SrcSeed{}), "x", 0), 1023) &&
    U32.is_eq(S.env.get(S.bind([S.Param{"x", S.NumericParam{}}], S.SeedParameter{0}, 0, MTip{}, S.MarkerSeed{}), "x", 1), 0)
  L.sel(U32, ok, u => 0, u => 1)
