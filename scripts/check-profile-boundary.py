#!/usr/bin/env python3
import pathlib
import re
import sys


PUBLIC = {
    'lex.bend': {'Tok', 'sel', 'strip_ns', 'is_name_start', 'is_name_char'},
    'tree.bend': {'Node', 'Leaf', 'Grp'},
    'profile-input.bend': {'parse', 'Input'},
}
PARSER_OWNERS = {'lex.bend', 'tree.bend', 'scan.bend', 'profile-input.bend'}
LITERALS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|#[^\n]*')
IMPORT = re.compile(r'^\s*import\s+(\S+)\s+as\s+(\w+)\s*$', re.MULTILINE)
NAME = r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*'
REFERENCE = re.compile(r'\b([A-Za-z_]\w*)\.(' + NAME + r')\b')
PATTERN = re.compile(r'\bcase\b[^:]*:')
TOKEN = re.compile(NAME + r'|==|!=|<=|>=|=>|[^\s]')


def pattern_ranges(source):
    ranges = [(match.start(), match.end()) for match in PATTERN.finditer(source)]
    tokens = list(TOKEN.finditer(source))

    def pattern(index):
        if index < len(tokens) and tokens[index][0] == '+':
            index += 1
        if index >= len(tokens):
            return index
        term = tokens[index][0]
        if re.fullmatch(NAME, term):
            index += 1
            if index >= len(tokens) or tokens[index][0] != '{':
                return index
            closer = '}'
        elif term in {'(', '['}:
            closer = ')' if term == '(' else ']'
        else:
            return index
        index += 1
        while index < len(tokens) and tokens[index][0] != closer:
            end = pattern(index)
            if end == index:
                return index
            index = end
            if index < len(tokens) and tokens[index][0] == ',':
                index += 1
            elif index >= len(tokens) or tokens[index][0] != closer:
                return index
        return index + 1

    for index, token in enumerate(tokens):
        prefix = source[source.rfind('\n', 0, token.start()) + 1:token.start()]
        if prefix.strip() and (index == 0 or tokens[index - 1][0] != ':'):
            continue
        end = pattern(index)
        while end < len(tokens) and tokens[end][0] == ',':
            following = pattern(end + 1)
            if following <= end + 1:
                break
            end = following
        if end < len(tokens) and tokens[end][0] == '=':
            ranges.append((token.start(), tokens[end].start()))
    return ranges


def check(root):
    errors = []
    for path in sorted((root / 'src').rglob('*.bend')):
        source = LITERALS.sub(lambda match: re.sub(r'[^\n]', ' ', match[0]), path.read_text())
        aliases = {alias: (path.parent / target).resolve()
                   for target, alias in IMPORT.findall(source)}
        patterns = pattern_ranges(source)
        for match in REFERENCE.finditer(source):
            module = aliases.get(match[1])
            if module is None or module.parent != (root / 'src').resolve():
                continue
            if module.name not in PUBLIC:
                continue
            parser_owner = path.resolve() in {(root / 'src' / owner).resolve()
                                              for owner in PARSER_OWNERS}
            forbidden = not parser_owner and match[2] not in PUBLIC[module.name]
            if module.name == 'profile-input.bend' and path.resolve() != module:
                forbidden = match[2] not in {'parse', 'Input'}
                if match[2] == 'Input':
                    tail = source[match.end():].lstrip()
                    in_pattern = any(start <= match.start() < end for start, end in patterns)
                    forbidden = tail.startswith('{') and not in_pattern
            if forbidden:
                line = source.count('\n', 0, match.start()) + 1
                errors.append(f'{path.relative_to(root)}:{line}: use profile-input.parse(source); '
                              f'{module.name}:{match[2]} belongs to the validated input boundary.')
    return errors


if __name__ == '__main__':
    root = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1]
    errors = check(root)
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        sys.exit(1)
    print('Profile input ownership: checked all src/**/*.bend files.')
