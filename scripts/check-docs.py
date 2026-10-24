#!/usr/bin/env python3
import pathlib
import re
import sys
import urllib.parse

root = pathlib.Path(__file__).resolve().parents[1]
files = list(root.glob('*.md')) + list((root / 'docs').rglob('*.md'))
checked = 0
missing = []
for source in files:
    for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', source.read_text()):
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        checked += 1
        path = source.parent / urllib.parse.unquote(parsed.path)
        if not path.exists():
            missing.append(f'{source.relative_to(root)}: missing {target}')
if missing:
    print('\n'.join(missing), file=sys.stderr)
    sys.exit(1)
print(f'Documentation: {checked} local link targets exist.')
