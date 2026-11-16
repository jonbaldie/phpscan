#!/usr/bin/env python3
import pathlib
import subprocess
import sys
import tempfile
import unittest

CHECKER = pathlib.Path(__file__).resolve().parents[1] / 'scripts/check-profile-boundary.py'
CONSUMER = pathlib.Path(__file__).with_name('profile-boundary.bend')


class ProfileBoundaryTests(unittest.TestCase):
    def check_source(self, source, name='future-profile.bend'):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / 'src' / name
            path.parent.mkdir(parents=True)
            path.write_text(source)
            return subprocess.run([sys.executable, str(CHECKER), directory],
                                  capture_output=True, text=True, timeout=10)

    def test_direct_parser_calls_name_the_supported_boundary(self):
        for module, member in [('lex', 'lex'), ('lex', 'qualified'),
                               ('lex', 'without_ignores'), ('lex', 'ignored_lines'),
                               ('tree', 'balanced'), ('tree', 'tree'),
                               ('tree', 'build.tolerant'), ('tree', 'close_all'),
                               ('lex', 'step'), ('lex', 'html'), ('lex', 'tok')]:
            with self.subTest(module=module, member=member):
                result = self.check_source(f'import ./{module}.bend as DifferentAlias\n'
                                           f'def bad() -> U32:\n  DifferentAlias.{member}(source)\n')
                self.assertEqual(result.returncode, 1)
                self.assertIn('src/future-profile.bend:3: use profile-input.parse(source)', result.stderr)

    def test_boundary_construction_and_helpers_are_private(self):
        for expression in ['P.Input{nodes, tokens, ignores, allowance}',
                           'P.grouped(tokens)', 'P.halted(nodes)',
                           'P.parse.raw(tokens)', 'P.Input.Raw{nodes}']:
            with self.subTest(expression=expression):
                result = self.check_source('import ./profile-input.bend as P\n'
                                           'def bad() -> U32:\n  ' + expression + '\n')
                self.assertEqual(result.returncode, 1)
                self.assertIn('profile-input.parse(source)', result.stderr)

    def test_consumers_can_parse_and_match_input(self):
        source = CONSUMER.read_text().replace('../src/profile-input.bend', './profile-input.bend')
        result = self.check_source(source)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_case_bodies_cannot_forge_validated_input(self):
        for body, output in [('P.Input{[], [], [], 0n}', 'P.Input'),
                             ('Some{P.Input{[], [], [], 0n}}', 'Maybe<&2, P.Input>'),
                             ('forged: P.Input = P.Input{[], [], [], 0n}\n      forged', 'P.Input')]:
            with self.subTest(body=body):
                result = self.check_source('import Base\nimport ./profile-input.bend as P\n'
                                           'def bad(flag: Bool) -> ' + output + ':\n'
                                           '  match flag:\n    case True{}: ' + body + '\n')
                self.assertEqual(result.returncode, 1)
                self.assertIn('profile-input.parse(source)', result.stderr)

    def test_comments_and_strings_cannot_create_or_hide_a_violation(self):
        allowed = ('import ./lex.bend as L\n# L.qualified(source)\n'
                   'def text() -> String:\n  "L.qualified(\\\"source\\\")"\n')
        self.assertEqual(self.check_source(allowed).returncode, 0)
        result = self.check_source(allowed + 'def bad() -> U32:\n  L.qualified(source) # "\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn('src/future-profile.bend:6:', result.stderr)

    def test_taint_parser_keeps_its_separate_owner(self):
        result = self.check_source('import ./lex.bend as L\nimport ./tree.bend as T\n'
                                   'def scan() -> U32:\n  T.tree(L.without_ignores(L.lex(source)))\n',
                                   name='scan.bend')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nested_sources_are_checked(self):
        result = self.check_source('import ../lex.bend as L\n'
                                   'def bad() -> U32:\n  L.qualified(source)\n',
                                   name='profiles/future.bend')
        self.assertEqual(result.returncode, 1)
        self.assertIn('src/profiles/future.bend:3:', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
