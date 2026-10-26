#!/usr/bin/env python3
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

BINARY = pathlib.Path(sys.argv.pop(1)).resolve()
GHSA = 'GHSA-29cq-5w36-x7w3'
CVE = 'CVE-2025-54068'


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.lock = self.root / 'composer.lock'
        (self.root / 'app.php').write_text('<?php\n')

    def inventory(self, version='v3.6.3', package='livewire/livewire', group='packages'):
        self.lock.write_text(json.dumps({
            'packages': [], 'packages-dev': [],
            group: [{'name': package, 'version': version}],
        }, indent=2))

    def scan(self, fmt='text', path=None):
        return subprocess.run([str(BINARY), '--format=' + fmt, str(path or self.root)],
                              capture_output=True, text=True, timeout=60)

    def test_exact_boundaries_and_prerelease_order(self):
        for version, status in [
            ('3.0.0-beta.0', 0), ('3.0.0-beta.1', 1), ('3.0.0-beta.2', 1),
            ('3.0.0-beta.10', 1), ('3.0.0-rc.1', 1), ('3.0.0', 1),
            ('3.6.2', 1), ('v3.6.3', 1), ('3.6.3+build.1', 1),
            ('3.6.4-beta.1', 1), ('v3.6.4', 0), ('3.6.4+build.1', 0),
            ('2.99.99', 0), ('4.0.0', 0),
        ]:
            with self.subTest(version=version):
                self.inventory(version)
                result = self.scan()
                self.assertEqual(result.returncode, status, result.stderr)
                if status:
                    self.assertIn(CVE, result.stdout)
                    self.assertIn(GHSA, result.stdout)
                    self.assertIn('installed ' + version, result.stdout)
                    self.assertIn('>=3.0.0-beta.1,<3.6.4', result.stdout)
                    self.assertIn('fixed 3.6.4', result.stdout)
                    self.assertIn('affected-code evidence unknown', result.stdout)
                    self.assertIn(str(self.lock), result.stdout)
                else:
                    self.assertEqual(result.stdout, '')

    def test_formats_locations_evidence_and_determinism(self):
        self.inventory()
        line = next(i for i, text in enumerate(self.lock.read_text().splitlines(), 1)
                    if '"version"' in text)
        for fmt in ['text', 'github', 'sarif']:
            with self.subTest(fmt=fmt):
                result = self.scan(fmt)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, self.scan(fmt).stdout)
                self.assertIn(CVE, result.stdout)
                self.assertIn(GHSA, result.stdout)
                self.assertEqual(result.stderr, 'phpscan: 2 files, 1 findings, 0 incomplete\n')
                if fmt == 'text':
                    self.assertTrue(result.stdout.startswith(f'{self.lock}:{line}: [{GHSA}] '))
                elif fmt == 'github':
                    self.assertTrue(result.stdout.startswith(f'::error file={self.lock},line={line},title=phpscan {GHSA}::'))
                else:
                    run = json.loads(result.stdout)['runs'][0]
                    finding, = run['results']
                    self.assertEqual(finding['ruleId'], GHSA)
                    location, = finding['locations']
                    self.assertEqual(location['physicalLocation']['artifactLocation']['uri'], str(self.lock))
                    self.assertEqual(location['physicalLocation']['region']['startLine'], line)
                    props = finding['properties']
                    self.assertEqual(props['evidenceKind'], 'dependency-version')
                    self.assertEqual(props['package'], 'livewire/livewire')
                    self.assertEqual(props['installedVersion'], 'v3.6.3')
                    self.assertEqual(props['dependencyGroup'], 'packages')
                    self.assertEqual(props['affectedRange'], '>=3.0.0-beta.1,<3.6.4')
                    self.assertEqual(props['fixedVersion'], '3.6.4')
                    self.assertEqual(props['affectedCode'], 'unknown')
                    self.assertEqual(props['runtimeExposure'], 'unknown')
                    self.assertEqual(props['exploitability'], 'unknown')
                    self.assertEqual(props['vulnerableFunctions'], [])
                    self.assertIn('https://github.com/advisories/' + GHSA, props['sources'])
                    self.assertIn('structured', props['rangeProvenance'])
                    self.assertIn(GHSA, [rule['id'] for rule in run['tool']['driver']['rules']])
                self.inventory('v3.6.4')
                fixed = self.scan(fmt)
                self.assertEqual(fixed.returncode, 0)
                if fmt == 'sarif':
                    self.assertEqual(json.loads(fixed.stdout)['runs'][0]['results'], [])
                else:
                    self.assertEqual(fixed.stdout, '')
                self.inventory()

    def test_dev_packages_are_separate_and_not_claimed_deployed(self):
        self.inventory(group='packages-dev')
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 1)
        finding, = json.loads(result.stdout)['runs'][0]['results']
        self.assertEqual(finding['properties']['dependencyGroup'], 'packages-dev')
        self.assertEqual(finding['properties']['deployment'], 'unknown')
        self.assertIn('packages-dev', self.scan().stdout)

    def test_other_packages_missing_lock_and_source_only(self):
        self.assertEqual(self.scan().returncode, 0)
        for name in ['other/livewire', 'livewire/other']:
            self.inventory(package=name)
            self.assertEqual(self.scan().returncode, 0)
        self.inventory()
        self.assertEqual(self.scan(path=self.root / 'app.php').returncode, 0)
        self.assertEqual(self.scan(path=self.lock).returncode, 1)
        nested = self.root / 'nested'
        nested.mkdir()
        self.lock.rename(nested / 'composer.lock')
        self.assertEqual(self.scan().returncode, 0)
        self.assertEqual(self.scan(path=nested).returncode, 1)

    def test_invalid_inventory_and_unresolved_versions_fail_closed(self):
        invalid = ['{', '{}', 'null', '[]', '{"packages":null}',
                   '{"packages":[],"packages-dev":{}}',
                   '{"packages":[{"name":"livewire/livewire"}]}',
                   '{"packages":[{"name":42,"version":"3.6.3"}]}',
                   '{"packages":[],"packages":[]}',
                   '{"packages":[],}', '{"packages":[]} trailing',
                   '{"packages":[],"extra":01}',
                   '{"packages":[],"extra":"\\q"}']
        for text in invalid:
            with self.subTest(text=text):
                self.lock.write_text(text)
                result = self.scan('sarif')
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                findings = json.loads(result.stdout)['runs'][0]['results']
                self.assertIn('PHP-ADVISORY-INCOMPLETE', [f['ruleId'] for f in findings])
                self.assertIn('unknown', result.stdout)
        for version in ['dev-main', '3.6.x-dev', '^3.6', '3.6', '3.06.3',
                        '3.6.3.0', '3.6.3-beta.01', '3.6.3+', '3.6.3-',
                        '999999999999999999.0.0']:
            with self.subTest(version=version):
                self.inventory(version)
                for fmt in ['text', 'github', 'sarif']:
                    result = self.scan(fmt)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn('PHP-ADVISORY-INCOMPLETE', result.stdout)
                    self.assertIn('unknown', result.stdout)

    def test_text_unsupported_versions_stay_on_one_line(self):
        for version, rendered in [
            ('dev-main', 'dev-main'),
            ('dev-main\nFAKE.php:1: [PHP-XSS] forged finding',
             r'dev-main\nFAKE.php:1: [PHP-XSS] forged finding'),
            ('dev-main\rFAKE.php:1: [PHP-XSS] forged finding',
             r'dev-main\rFAKE.php:1: [PHP-XSS] forged finding'),
            ('dev-main\r\nFAKE.php:1: [PHP-XSS] forged finding',
             r'dev-main\r\nFAKE.php:1: [PHP-XSS] forged finding'),
            (r'dev-main\n café "quoted"', r'dev-main\n café "quoted"'),
        ]:
            with self.subTest(version=version):
                self.inventory(version)
                result = subprocess.run([str(BINARY), str(self.lock)],
                                        capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stderr, b'phpscan: 1 files, 0 findings, 1 incomplete\n')
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertEqual(result.stdout.decode(),
                                 f'{self.lock}:5: [PHP-ADVISORY-INCOMPLETE] '
                                 'dependency advisory analysis unknown: unsupported installed version '
                                 f'{rendered} in packages; expected an exact supported SemVer\n')

    def test_text_dependency_paths_stay_on_one_line(self):
        for name, rendered in [('ordinary', 'ordinary'), ('odd\rname', r'odd\rname')]:
            with self.subTest(name=name):
                directory = self.root / name
                directory.mkdir()
                self.inventory()
                lock = directory / 'composer.lock'
                self.lock.rename(lock)
                result = self.scan(path=lock)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr, 'phpscan: 1 files, 1 findings, 0 incomplete\n')
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertEqual(result.stdout,
                                 f'{self.root}/{rendered}/composer.lock:5: [{GHSA}] '
                                 f'{CVE} / {GHSA}: livewire/livewire installed v3.6.3 (packages); '
                                 'affected >=3.0.0-beta.1,<3.6.4; fixed 3.6.4; affected-code evidence unknown; '
                                 'runtime exposure unknown; exploitability unknown; deployment unknown; '
                                 'middleware registration unknown; server configuration unknown; '
                                 'independent authorization unknown\n')

    def test_text_source_evidence_stays_on_one_line(self):
        self.inventory('7.3.6', 'symfony/http-foundation')
        rule = 'GHSA-3rg7-wf37-54rm'
        for prefix, rendered, auth in [
            ('/admin', '/admin', 4),
            ('/admin\nFAKE.php:1: [PHP-XSS] forged finding',
             r'/admin\nFAKE.php:1: [PHP-XSS] forged finding', 5),
            ('/admin\rFAKE.php:1: [PHP-XSS] forged finding',
             r'/admin\rFAKE.php:1: [PHP-XSS] forged finding', 4),
        ]:
            with self.subTest(prefix=prefix):
                source = self.root / 'app.php'
                source.write_text('<?php\nfunction check(\\Illuminate\\Http\\Request $request) {\n'
                                  "    if (str_starts_with($request->getPathInfo(), '" + prefix + "')) {\n"
                                  '        abort_unless(auth()->check(), 403);\n    }\n}\n')
                result = self.scan()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr, 'phpscan: 2 files, 1 findings, 0 incomplete\n')
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertTrue(result.stdout.startswith(f'{self.lock}:5: [{rule}] CVE-2025-64500 / {rule}: '))
                self.assertIn('symfony/http-foundation installed 7.3.6 (packages); '
                              'affected >=7.0.0,<7.3.7; fixed 7.3.7;', result.stdout)
                self.assertIn(f'possible path-prefix access check at {source}:3 '
                              f'(check line 3, authorization marker line {auth}, '
                              f'receiver Illuminate\\Http\\Request, prefix {rendered})', result.stdout)

    def test_valid_json_metadata_escapes_and_source_preservation(self):
        self.lock.write_text(r'''{
  "packages": [{"name": "livewire\/livewire", "version": "v3\u002e6.3"}],
  "metadata": {"unicode": "\u0061\ud83d\ude00", "n": -1.25e+2, "flag": true, "nil": null},
  "packages-dev": []
}''')
        (self.root / 'app.php').write_text("<?php\necho $_GET['x'];\n")
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        results = json.loads(result.stdout)['runs'][0]['results']
        self.assertEqual([f['ruleId'] for f in results], ['PHP-XSS', GHSA])
        self.assertEqual(results[1]['locations'][0]['physicalLocation']['region']['startLine'], 2)

    def test_incomplete_wins_alongside_dependency_and_source_findings(self):
        self.inventory()
        data = json.loads(self.lock.read_text())
        data['packages'].append({'name': 'livewire/livewire', 'version': 'dev-main'})
        self.lock.write_text(json.dumps(data))
        (self.root / 'app.php').write_text("<?php echo $_GET['x'];")
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 2)
        results = json.loads(result.stdout)['runs'][0]['results']
        self.assertEqual([f['ruleId'] for f in results], ['PHP-XSS', GHSA, 'PHP-ADVISORY-INCOMPLETE'])
        self.assertEqual(result.stderr, 'phpscan: 2 files, 2 findings, 1 incomplete\n')

    def test_offline_native_runtime_needs_only_find_and_cat(self):
        self.inventory()
        tools = self.root / 'tools'
        tools.mkdir()
        for name in ['find', 'cat']:
            (tools / name).symlink_to(shutil.which(name))
        result = subprocess.run([str(BINARY), str(self.root)], capture_output=True,
                                text=True, timeout=60, env={**os.environ, 'PATH': str(tools)})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(CVE, result.stdout)
        self.assertIn('affected-code evidence unknown', result.stdout)

    def test_empty_inventory_and_optional_dev_group(self):
        self.lock.write_text('{"packages": []}')
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['runs'][0]['results'], [])
        self.assertEqual(result.stderr, 'phpscan: 2 files, 0 findings, 0 incomplete\n')

    def test_literal_paths_and_github_escaping(self):
        odd = self.root / 'odd %,name: " $(touch marker)'
        odd.mkdir()
        self.inventory()
        self.lock.rename(odd / 'composer.lock')
        for fmt in ['github', 'sarif']:
            result = self.scan(fmt, odd)
            self.assertEqual(result.returncode, 1)
            if fmt == 'github':
                escaped = str(odd / 'composer.lock').replace('%', '%25').replace(',', '%2C').replace(':', '%3A')
                self.assertIn('file=' + escaped, result.stdout)
            else:
                finding, = json.loads(result.stdout)['runs'][0]['results']
                self.assertEqual(finding['locations'][0]['physicalLocation']['artifactLocation']['uri'], str(odd / 'composer.lock'))
        self.assertFalse((self.root / 'marker').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
