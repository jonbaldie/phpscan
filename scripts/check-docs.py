#!/usr/bin/env python3
import pathlib
import re
import sys
import urllib.parse

root = pathlib.Path(__file__).resolve().parents[1]
files = sorted(list(root.glob('*.md')) + [path for path in (root / 'docs').rglob('*') if path.is_file()])
machine_path = re.compile(
    r'/(?:Users|home)/|/opt/homebrew(?:/|\b)|/private/var/|/var/folders/|/Volumes/'
    r'|(?:~|\$HOME|\$\{HOME\})/(?:Code(?:-\d+)?|\.agents|\.pi|\.fleet)(?:/|\b)'
    r'|(?<!\w)\.audit/'
)
entry_version = re.compile(
    r'\bv\d+\.\d+(?:\.\d+)*\b'
    r'|\b(?:phpscan|Bend|Bun|PHP|macOS|glibc|SARIF)\s+v?\d+(?:\.\d+)*\b'
)
checked = 0
errors = []
for source in files:
    text = source.read_text(errors='replace')
    for number, line in enumerate(text.splitlines(), 1):
        normalized = urllib.parse.unquote(line).replace('\\/', '/')
        location = f'{source.relative_to(root)}:{number}'
        if machine_path.search(normalized):
            errors.append(f'{location}: machine-specific path; use repository-relative or public references.')
        if source.parent == root and source.name in ('README.md', 'AGENTS.md') and entry_version.search(line):
            errors.append(f'{location}: cached version; use the current release or link to the reference.')
    if source.suffix != '.md':
        continue
    for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        checked += 1
        path = source.parent / urllib.parse.unquote(parsed.path)
        if not path.exists():
            errors.append(f'{source.relative_to(root)}: missing {target}')
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print(f'Documentation: {len(files)} files checked; {checked} local link targets exist.')
