#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

BINARY = pathlib.Path(sys.argv.pop(1)).resolve()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.bad = self.root / 'unsafe.php'
        self.bad.write_text("<?php\necho $_GET['name'];\n")
        self.clean = self.root / 'clean.php'
        self.clean.write_text("<?php\necho htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');\n")

    def run_cli(self, *args):
        return subprocess.run([str(BINARY), *map(str, args)], capture_output=True, text=True, timeout=60, cwd=self.root)

    def test_version(self):
        result = self.run_cli('--version')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'phpscan 0.1.0\n')
        self.assertEqual(result.stderr, '')

    def test_help(self):
        for option in ['--help', '-h']:
            with self.subTest(option=option):
                result = self.run_cli(option)
                self.assertEqual(result.returncode, 0)
                self.assertIn('usage: phpscan', result.stdout)
                self.assertIn('--format=text|github|sarif', result.stdout)
                self.assertEqual(result.stderr, '')

    def test_literal_finding_and_summary(self):
        result = self.run_cli(self.bad)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, f'{self.bad}:2: [PHP-XSS] cross-site scripting: request data reaches echo (CWE-79)\n')
        self.assertEqual(result.stderr, 'phpscan: 1 files, 1 findings, 0 incomplete\n')

    def test_text_source_paths_stay_on_one_line(self):
        for name, rendered in [('ordinary.php', 'ordinary.php'), ('odd\rname.php', r'odd\rname.php')]:
            with self.subTest(name=name):
                path = self.root / name
                path.write_text("<?php echo $_GET['x'];")
                result = self.run_cli(path)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr, 'phpscan: 1 files, 1 findings, 0 incomplete\n')
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertEqual(result.stdout,
                                 f'{self.root}/{rendered}:1: [PHP-XSS] '
                                 'cross-site scripting: request data reaches echo (CWE-79)\n')

    def test_sanitized_source(self):
        result = self.run_cli(self.clean)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'phpscan: 1 files, 0 findings, 0 incomplete\n')

    def test_directory_extensions_and_sorting(self):
        (self.root / 'more.phtml').write_text("<?php echo $_POST['x'];")
        (self.root / 'more.inc').write_text("<?php echo 'safe';")
        (self.root / 'ignored.txt').write_text("<?php echo $_GET['x'];")
        result = self.run_cli(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, 'phpscan: 4 files, 2 findings, 0 incomplete\n')
        self.assertIn('more.phtml:1: [PHP-XSS]', result.stdout)
        self.assertNotIn('ignored.txt', result.stdout)
        self.assertLess(result.stdout.index('more.phtml'), result.stdout.index('unsafe.php'))

    def test_sarif_from_actual_scan(self):
        result = self.run_cli('--format=sarif', self.bad)
        self.assertEqual(result.returncode, 1)
        document = json.loads(result.stdout)
        self.assertEqual(document['version'], '2.1.0')
        run = document['runs'][0]
        self.assertEqual(run['tool']['driver']['version'], '0.1.0')
        self.assertEqual(len(run['results']), 1)
        finding = run['results'][0]
        self.assertEqual(finding['ruleId'], 'PHP-XSS')
        location = finding['locations'][0]['physicalLocation']
        self.assertEqual(location['region']['startLine'], 2)
        self.assertEqual(location['artifactLocation']['uri'], str(self.bad))
        clean = self.run_cli('--format=sarif', self.clean)
        self.assertEqual(clean.returncode, 0)
        self.assertEqual(json.loads(clean.stdout)['runs'][0]['results'], [])

    def test_github_escapes_workflow_properties(self):
        path = self.root / 'odd %,name: test.php'
        path.write_text("<?php echo $_GET['x'];")
        result = self.run_cli('--format=github', path)
        self.assertEqual(result.returncode, 1)
        escaped = str(path).replace('%', '%25').replace(',', '%2C').replace(':', '%3A')
        self.assertEqual(result.stdout, f'::error file={escaped},line=1,title=phpscan PHP-XSS::cross-site scripting%3A request data reaches echo (CWE-79)\n')

    def test_json_quotes_and_literal_shell_metacharacters(self):
        path = self.root / 'odd " $(touch marker).php'
        path.write_text("<?php echo $_GET['x'];")
        result = self.run_cli('--format=sarif', path)
        self.assertEqual(result.returncode, 1)
        uri = json.loads(result.stdout)['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
        self.assertEqual(uri, str(path))
        self.assertFalse((self.root / 'marker').exists())

    def test_usage_errors_fail_closed(self):
        for args in [[], ['--unknown'], ['--format=xml', self.bad], [self.root / 'missing']]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertNotEqual(result.stderr, '')

    def test_multiple_input_paths(self):
        result = self.run_cli(self.clean, self.bad)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, 'phpscan: 2 files, 1 findings, 0 incomplete\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
