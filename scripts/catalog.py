#!/usr/bin/env python3
import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def render():
    snapshot = json.loads((ROOT / 'advisories/composer.json').read_text())
    records = []
    seen = set()
    for item in snapshot['advisories']:
        assert item['ghsa'] not in seen, 'duplicate GHSA'
        seen.add(item['ghsa'])
        assert item['source_profile'] in {
            'none', 'symfony-path-prefix', 'laravel-token-guard', 'laravel-jsonapi'}
        ranges = []
        for affected in item['affected_ranges']:
            assert affected['upper_exclusive'] == affected['fixed']
            assert isinstance(affected['package'], str) and affected['package']
            lower = affected['lower_inclusive']
            assert lower is None or (isinstance(lower, str) and lower)
            fields = [json.dumps(affected['package']),
                      'None{}' if lower is None else 'Some{' + json.dumps(lower) + '}']
            for key in ['upper_exclusive', 'fixed', 'range_provenance']:
                assert isinstance(affected[key], str) and affected[key]
                fields.append(json.dumps(affected[key]))
            ranges.append('AffectedRange{' + ', '.join(fields) + '}')
        assert ranges
        strings = [item[key] for key in ['ghsa', 'cve', 'source_profile']]
        assert all(isinstance(value, str) and value for value in strings)
        assert item['sources'] and all(url.startswith('https://') for url in item['sources'])
        assert isinstance(item['vulnerable_functions'], list)
        assert all(isinstance(name, str) and name for name in item['vulnerable_functions'])
        fields = [json.dumps(value, ensure_ascii=False) for value in strings]
        fields += ['[' + ', '.join(ranges) + ']', json.dumps(item['sources']),
                   json.dumps(item['vulnerable_functions'])]
        records.append('    Advisory{' + ', '.join(fields) + '}')
    return '''import Base

type AffectedRange is Data:
  AffectedRange{package: String, lower: Maybe<&2, String>, upper: String, fixed: String, provenance: String}

type Advisory is Data:
  Advisory{ghsa: String, cve: String, profile: String, ranges: List<&2, AffectedRange>, sources: List<&2, String>, functions: List<&2, String>}

def lower.eq(x: Maybe<&2, String>, y: Maybe<&2, String>) -> Bool:
  match x y:
    case None{} None{}:
      True{}
    case Some{xs} Some{ys}:
      String.eq(xs, ys)
    case a b:
      False{}

def strings.eq(xs: List<&2, String>, ys: List<&2, String>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{x, xr} Con{y, yr}:
      String.eq(x, y) && strings.eq(xr, yr)
    case a b:
      False{}

def range.eq(x: AffectedRange, y: AffectedRange) -> Bool:
  match x y:
    case AffectedRange{pk1, l1, u1, f1, v1} AffectedRange{pk2, l2, u2, f2, v2}:
      String.eq(pk1, pk2) && lower.eq(l1, l2) && String.eq(u1, u2) && String.eq(f1, f2) && String.eq(v1, v2)
    case a b:
      False{}

def ranges.eq(xs: List<&2, AffectedRange>, ys: List<&2, AffectedRange>) -> Bool:
  match xs ys:
    case Nil{} Nil{}:
      True{}
    case Con{x, xr} Con{y, yr}:
      range.eq(x, y) && ranges.eq(xr, yr)
    case a b:
      False{}

def advisory.eq(x: Advisory, y: Advisory) -> Bool:
  match x y:
    case Advisory{g1, c1, p1, r1, s1, f1} Advisory{g2, c2, p2, r2, s2, f2}:
      String.eq(g1, g2) && String.eq(c1, c2) && String.eq(p1, p2) && ranges.eq(r1, r2) && strings.eq(s1, s2) && strings.eq(f1, f2)
    case a b:
      False{}

def snapshot_date() -> String:
  ''' + json.dumps(snapshot['snapshot_date']) + '''

def records() -> List<&2, Advisory>:
  [
''' + ',\n'.join(records) + '\n  ]\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    target = ROOT / 'src/catalog.bend'
    expected = render()
    if args.check:
        if not target.exists() or target.read_text() != expected:
            parser.exit(1, 'Catalog is stale. Run python3 scripts/catalog.py.\n')
    else:
        target.write_text(expected)


if __name__ == '__main__':
    main()
