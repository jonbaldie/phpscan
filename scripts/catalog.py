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
        assert item['source_profile'] in {'none', 'symfony-path-prefix'}
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
