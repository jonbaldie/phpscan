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
NAME = r'[A-Za-z_][A-Za-z0-9_.]*'
IMPORT = re.compile(r'^\s*import\s+(\S+)\s+as\s+(\w+)\s*$', re.MULTILINE)
REFERENCE = re.compile(r'(?<![A-Za-z0-9_.])' + NAME + r'(?![A-Za-z0-9_.])')
TOKEN = re.compile(NAME + r'|[0-9][A-Za-z0-9_.]*|==|!=|<=|>=|=>|<>|[^\s]')
NUMBER = re.compile(r'[0-9][A-Za-z0-9_.]*')


def pattern_ranges(source):
    ranges = []
    tokens = list(TOKEN.finditer(source))

    def pattern(index):
        if index < len(tokens) and tokens[index][0] == '+':
            index += 1
        if index >= len(tokens):
            return None
        term = tokens[index][0]
        if term == '-' and index + 1 < len(tokens) and NUMBER.fullmatch(tokens[index + 1][0]):
            end = index + 2
        elif NUMBER.fullmatch(term):
            end = index + 1
        elif re.fullmatch(NAME, term):
            end = index + 1
            if end < len(tokens) and tokens[end][0] == '{':
                end = fields(end + 1, '}')
        elif term in {'(', '['}:
            end = fields(index + 1, ')' if term == '(' else ']')
        else:
            return None
        if end is not None and end < len(tokens) and tokens[end][0] in {'+', '<>'}:
            return pattern(end + 1)
        return end

    def fields(index, closer):
        if index < len(tokens) and tokens[index][0] == closer:
            return index + 1
        while index < len(tokens):
            index = pattern(index)
            if index is None or index >= len(tokens):
                return None
            if tokens[index][0] == closer:
                return index + 1
            if tokens[index][0] != ',':
                return None
            index += 1
            if index < len(tokens) and tokens[index][0] == closer:
                return index + 1
        return None

    for index, token in enumerate(tokens):
        if token[0] == 'case':
            end = pattern(index + 1)
            while end is not None and end < len(tokens) and tokens[end][0] != ':':
                end = pattern(end)
            if end is not None and end < len(tokens) and tokens[end][0] == ':':
                ranges.append((token.end(), tokens[end].start()))
            continue
        prefix = source[source.rfind('\n', 0, token.start()) + 1:token.start()]
        if prefix.strip() and (index == 0 or tokens[index - 1][0] not in {':', ';', '(', '=>'}):
            continue
        end = pattern(index)
        while end is not None and end < len(tokens) and tokens[end][0] == ',':
            end = pattern(end + 1)
        if end is not None and end < len(tokens) and tokens[end][0] == '=':
            ranges.append((token.start(), tokens[end].start()))
    return ranges


def check(root):
    errors = []
    for path in sorted((root / 'src').rglob('*.bend')):
        raw = path.read_text()
        source = LITERALS.sub(lambda match: re.sub(r'[^\n]', ' ', match[0]), raw)
        patterns_source = LITERALS.sub(
            lambda match: (' ' if match[0].startswith('#') else '0') +
            re.sub(r'[^\n]', ' ', match[0][1:]), raw)
        aliases = {alias: (path.parent / target).resolve()
                   for target, alias in IMPORT.findall(source)}
        patterns = pattern_ranges(patterns_source)
        for match in REFERENCE.finditer(source):
            alias, separator, member = match[0].partition('.')
            if not separator:
                continue
            module = aliases.get(alias)
            if module is None or module.parent != (root / 'src').resolve():
                continue
            if module.name not in PUBLIC:
                continue
            parser_owner = path.resolve() in {(root / 'src' / owner).resolve()
                                              for owner in PARSER_OWNERS}
            forbidden = not parser_owner and member not in PUBLIC[module.name]
            if module.name == 'profile-input.bend' and path.resolve() != module:
                forbidden = member not in {'parse', 'Input'}
                if member == 'Input':
                    tail = source[match.end():].lstrip()
                    in_pattern = any(start <= match.start() < end for start, end in patterns)
                    forbidden = tail.startswith('{') and not in_pattern
            if forbidden:
                line = source.count('\n', 0, match.start()) + 1
                errors.append(f'{path.relative_to(root)}:{line}: use profile-input.parse(source); '
                              f'{module.name}:{member} belongs to the validated input boundary.')
    return errors


if __name__ == '__main__':
    root = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1]
    errors = check(root)
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        sys.exit(1)
    print('Profile input ownership: checked all src/**/*.bend files.')
