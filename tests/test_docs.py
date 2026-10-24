#!/usr/bin/env python3
import pathlib
import subprocess
import sys
import tempfile
import unittest


CHECKER = pathlib.Path(__file__).resolve().parents[1] / 'scripts/check-docs.py'


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.put('scripts/check-docs.py', CHECKER.read_text())

    def put(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def check_docs(self):
        return subprocess.run(
            [sys.executable, str(self.root / 'scripts/check-docs.py')],
            cwd=self.root, text=True, capture_output=True, check=False,
        )

    def test_portable_paths_and_historical_versions_are_allowed(self):
        self.put('README.md', '''# phpscan
[Reference](docs/reference.md)
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/jonbaldie/phpscan/releases/latest/download/install.sh
export PATH="$HOME/.local/bin:$PATH"
''')
        self.put('AGENTS.md', 'Read [the source](src/version.bend).\n')
        self.put('src/version.bend', 'version = "0.1.0"\n')
        self.put('docs/reference.md', 'SARIF 2.1.0; glibc 2.35; macOS 13.\n')
        self.put('docs/evidence/README.md', 'Historical phpscan v0.1.0.\n')
        self.put('docs/evidence/reads.json', '{"skill": "unslop", "sha256": "recorded"}\n')
        self.put('THIRD_PARTY_NOTICES.md', 'Bend 2.0.38 uses Apache-2.0.\n')
        result = self.check_docs()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('2 local link targets exist', result.stdout)

    def test_missing_relative_link_is_rejected(self):
        self.put('README.md', '[Missing](docs/not-present.md)\n')
        result = self.check_docs()
        self.assertEqual(result.returncode, 1)
        self.assertIn('README.md: missing docs/not-present.md', result.stderr)

    def test_machine_paths_are_rejected_in_markdown(self):
        for text in (
            '/Users/maintainer/Code/phpscan',
            '~/Code/github.com/owner/phpscan',
            '$HOME/Code-2/github.com/owner/phpscan',
            '${HOME}/.agents/skills/example/SKILL.md',
            '/opt/homebrew/bin/bun',
            '/private/var/folders/example/scan.php',
            '/var/folders/example/scan.php',
            '/Volumes/work/phpscan',
        ):
            with self.subTest(path=text):
                self.put('README.md', '# Guide\nRead `' + text + '`.\n')
                result = self.check_docs()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn('README.md:2: machine-specific path', result.stderr)

    def test_machine_paths_are_rejected_in_evidence(self):
        for name, text in (
            ('reads.json', '{"source":"/Users/maintainer/skills/SKILL.md"}'),
            ('escaped.json', r'{"source":"\/Users\/maintainer\/skills\/SKILL.md"}'),
            ('scan.sarif', '{"uri":"file://%2FUsers%2Fmaintainer%2Fscan.php"}'),
            ('run.txt', 'Read /Users/maintainer/project/source.php'),
        ):
            with self.subTest(name=name):
                path = 'docs/evidence/' + name
                self.put(path, text)
                result = self.check_docs()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(path + ':1: machine-specific path', result.stderr)
                (self.root / path).unlink()

    def test_operator_audit_paths_are_rejected(self):
        for text in ('.audit/phpscan-release/results.json', '~/.fleet/events/policy.json', '~/.pi/agent/session.jsonl'):
            with self.subTest(path=text):
                self.put('docs/evidence/review.md', text + '\n')
                result = self.check_docs()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn('docs/evidence/review.md:1: machine-specific path', result.stderr)

    def test_release_literals_are_rejected_in_entry_guides(self):
        for name in ('README.md', 'AGENTS.md'):
            for text in (
                'https://raw.githubusercontent.com/jonbaldie/phpscan/v0.1.0/install.sh',
                'sh install-phpscan.sh v0.1.0',
                'Expected output: phpscan 0.1.0',
            ):
                with self.subTest(name=name, text=text):
                    self.put(name, text + '\n')
                    result = self.check_docs()
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn(name + ':1: cached version', result.stderr)
            (self.root / name).unlink()

    def test_toolchain_and_format_versions_are_rejected_in_entry_guides(self):
        for name in ('README.md', 'AGENTS.md'):
            for text in ('Bend 2.0.38', 'Bun 1.3.14', 'PHP 8.3', 'glibc 2.35', 'macOS 13', 'SARIF 2.1.0'):
                with self.subTest(name=name, text=text):
                    self.put(name, text + '\n')
                    result = self.check_docs()
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn(name + ':1: cached version', result.stderr)
            (self.root / name).unlink()

    def test_other_root_guides_are_checked_for_machine_paths(self):
        self.put('CODING_STANDARDS.md', 'Read /Users/maintainer/private/standards.md\n')
        result = self.check_docs()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('CODING_STANDARDS.md:1: machine-specific path', result.stderr)


if __name__ == '__main__':
    unittest.main()
