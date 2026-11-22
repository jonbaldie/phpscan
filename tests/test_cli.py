#!/usr/bin/env python3
import json
import os
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
        self.assertEqual(result.stdout, 'phpscan 0.2.0\n')
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

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlinks required')
    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlinks required')
    def test_symlinked_files_scanned(self):
        os.symlink(self.bad, self.root / 'link.php')
        explicit = self.run_cli(self.root / 'link.php')
        self.assertEqual(explicit.returncode, 1, explicit.stderr)
        self.assertIn('link.php:2: [PHP-XSS]', explicit.stdout)
        in_dir = self.run_cli(self.root)
        self.assertEqual(in_dir.returncode, 1)
        self.assertEqual(in_dir.stderr, 'phpscan: 3 files, 2 findings, 0 incomplete\n')
        self.assertIn('link.php:2: [PHP-XSS]', in_dir.stdout)
        self.assertIn('unsafe.php:2: [PHP-XSS]', in_dir.stdout)

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlinks required')
    def test_symlinked_lockfile_supplies_advisories(self):
        lock = self.root / 'real-lock.json'
        lock.write_text(json.dumps({'packages': [{'name': 'livewire/livewire', 'version': '3.6.3'}]}))
        os.symlink(lock, self.root / 'composer.lock')
        result = self.run_cli(self.root)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('GHSA-29cq-5w36-x7w3', result.stdout)
        explicit = self.run_cli(self.root / 'composer.lock')
        self.assertEqual(explicit.returncode, 1, explicit.stderr)
        self.assertIn('GHSA-29cq-5w36-x7w3', explicit.stdout)

    @unittest.skipUnless(hasattr(os, 'symlink') and hasattr(os, 'mkfifo'), 'symlinks and fifos required')
    def test_unresolvable_inputs_exit_two(self):
        dangling = self.root / 'broken.php'
        os.symlink(self.root / 'nowhere.php', dangling)
        result = self.run_cli(self.root)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('cannot list', result.stderr)
        explicit = self.run_cli(self.root / 'broken.php')
        self.assertEqual(explicit.returncode, 2, explicit.stdout)
        self.assertIn('cannot list', explicit.stderr)
        txt = self.root / 'broken.txt'
        os.symlink(self.root / 'nowhere.txt', txt)
        result = self.run_cli(txt)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('cannot list', result.stderr)
        fifo = self.root / 'p.fifo'
        os.mkfifo(fifo)
        result = self.run_cli(fifo)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn('cannot list', result.stderr)

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlinks required')
    def test_symlink_to_directory_is_not_followed(self):
        target = self.root / 'target'
        target.mkdir()
        (target / 'bad.php').write_text("<?php echo $_GET['x'];")
        link = self.root / 'realdir'
        os.symlink(target, link, target_is_directory=True)
        result = self.run_cli(link)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'phpscan: 0 files, 0 findings, 0 incomplete\n')

    def test_overlapping_spellings_do_not_duplicate_findings(self):
        sub = self.root / 'sub'
        sub.mkdir()
        evil = sub / 'a.php'
        evil.write_text("<?php echo $_GET['x'];")
        result = self.run_cli('--format=sarif', '.', 'sub/a.php')
        self.assertEqual(result.returncode, 1, result.stderr)
        results = json.loads(result.stdout)['runs'][0]['results']
        uris = [r['locations'][0]['physicalLocation']['artifactLocation']['uri'] for r in results
                if r['ruleId'] == 'PHP-XSS' and r['locations'][0]['physicalLocation']['artifactLocation']['uri'].endswith('sub/a.php')]
        self.assertEqual(len(uris), 1, results)

    def test_symfony_lockfile_overlap_prefers_settled_evidence(self):
        fixture = r'''<?php
namespace App\Http\Middleware;
use Closure;
use Illuminate\Http\Request;
class PrefixAccess
{
    public function handle(Request $request, Closure $next)
    {
        if (str_starts_with($request->getPathInfo(), '/admin')) {
            abort_unless(auth()->check(), 403);
        }
        return $next($request);
    }
}
'''
        proj = self.root / 'app'
        proj.mkdir()
        (proj / 'PrefixAccess.php').write_text(fixture)
        lock = proj / 'composer.lock'
        lock.write_text(json.dumps({
            'packages': [{'name': 'symfony/http-foundation', 'version': 'v7.3.6'}],
            'packages-dev': [],
        }))
        for paths in [(proj, lock), (lock, proj)]:
            result = self.run_cli('--format=sarif', *paths)
            self.assertEqual(result.returncode, 1, result.stderr)
            results = json.loads(result.stdout)['runs'][0]['results']
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['properties']['affectedCode'], 'possible')
            self.assertIn('phpscan: 2 files,', result.stderr)

    def test_explicit_files_scanned_regardless_of_extension(self):
        upper = self.root / 'UPPER.PHP'
        upper.write_text("<?php echo $_GET['x'];")
        result = self.run_cli(upper)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('PHP-XSS', result.stdout)
        notes = self.root / 'notes.txt'
        notes.write_text("<?php echo $_GET['x'];")
        result = self.run_cli(notes)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('PHP-XSS', result.stdout)
        lock = self.root / 'composer.lock'
        lock.write_text('{"packages":[{"name":"livewire/livewire","version":"3.6.3","desc":"<?php echo $_GET[q];"}]}')
        result = self.run_cli(lock)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('GHSA-29cq-5w36-x7w3', result.stdout)
        self.assertNotIn('[PHP-', result.stdout)

    def test_overlapping_inputs_do_not_duplicate_findings(self):
        result = self.run_cli(self.root, self.bad)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, 'phpscan: 2 files, 1 findings, 0 incomplete\n')
        self.assertEqual(result.stdout.count('PHP-XSS'), 1)
        result = self.run_cli(self.bad, self.bad)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, 'phpscan: 1 files, 1 findings, 0 incomplete\n')
        self.assertEqual(result.stdout.count('PHP-XSS'), 1)
        proj = self.root / 'lockproj'
        proj.mkdir()
        (proj / 'app.php').write_text('<?php\n')
        lock = proj / 'composer.lock'
        lock.write_text(json.dumps({'packages': [{'name': 'livewire/livewire', 'version': '3.6.3'}]}))
        result = self.run_cli(proj, lock)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, 'phpscan: 2 files, 1 findings, 0 incomplete\n')
        self.assertIn('GHSA-29cq-5w36-x7w3', result.stdout)
        self.assertEqual(len([line for line in result.stdout.splitlines() if line]), 1)

    def test_sarif_from_actual_scan(self):
        result = self.run_cli('--format=sarif', self.bad)
        self.assertEqual(result.returncode, 1)
        document = json.loads(result.stdout)
        self.assertEqual(document['version'], '2.1.0')
        run = document['runs'][0]
        self.assertEqual(run['tool']['driver']['version'], '0.2.0')
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

    @unittest.skipUnless(hasattr(os, 'symlink') and hasattr(os, 'mkfifo'), 'symlinks and fifos required')
    def test_symlink_to_fifo_fails_fast(self):
        fifo = self.root / 'p.fifo'
        os.mkfifo(fifo)
        link = self.root / 'fifo.php'
        os.symlink(fifo, link)
        import time
        started = time.time()
        result = self.run_cli(self.root)
        elapsed = time.time() - started
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertLess(elapsed, 60)
        self.assertIn('not a regular file', result.stderr)

    def test_multiple_input_paths(self):
        result = self.run_cli(self.clean, self.bad)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, 'phpscan: 2 files, 1 findings, 0 incomplete\n')

    def test_first_format_option_wins_even_when_later_format_is_invalid(self):
        result = self.run_cli('--format=github', '--format=xml', self.bad)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(result.stdout.startswith('::error file='), result.stdout)
        invalid = self.run_cli('--format=xml', '--format=github', self.bad)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(invalid.stdout, '')
        self.assertIn('unknown format', invalid.stderr)

    def test_first_unknown_option_wins_over_format_and_path_errors(self):
        result = self.run_cli('--first', '--format=xml', '--second', self.root / 'missing')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertIn('unknown option --first', result.stderr)
        self.assertNotIn('--second', result.stderr)

    def test_help_and_version_are_only_special_as_sole_arguments(self):
        for argument in ['--help', '-h', '--version']:
            with self.subTest(argument=argument):
                result = self.run_cli(argument, self.clean)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertIn('unknown option ' + argument, result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
