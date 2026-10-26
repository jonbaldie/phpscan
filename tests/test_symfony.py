#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

BINARY = pathlib.Path(sys.argv.pop(1)).resolve()
GHSA = 'GHSA-3rg7-wf37-54rm'
CVE = 'CVE-2025-64500'
SOURCE = r'''<?php
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


class SymfonyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.lock = self.root / 'composer.lock'
        self.source = self.root / 'PrefixAccess.php'
        self.source.write_text(SOURCE)

    def inventory(self, version='v7.3.6', package='symfony/http-foundation', group='packages'):
        self.lock.write_text(json.dumps({
            'packages': [], 'packages-dev': [],
            group: [{'name': package, 'version': version}],
        }, indent=2))

    def scan(self, fmt='text', *paths):
        return subprocess.run([str(BINARY), '--format=' + fmt,
                               *(str(p) for p in (paths or [self.root]))],
                              capture_output=True, text=True, timeout=60)

    def test_version_boundaries_and_package_identity(self):
        for package in ['symfony/http-foundation', 'symfony/symfony']:
            for version, status in [
                ('2.0.0', 1), ('5.4.49', 1), ('5.4.50', 0), ('5.99.0', 0),
                ('6.0.0', 1), ('6.4.28', 1), ('6.4.29', 0), ('6.99.0', 0),
                ('7.0.0', 1), ('v7.3.6', 1), ('7.3.7', 0), ('8.0.0', 0),
            ]:
                with self.subTest(package=package, version=version):
                    self.inventory(version, package)
                    result = self.scan()
                    self.assertEqual(result.returncode, status, result.stderr)
                    if status:
                        self.assertIn(CVE, result.stdout)
                        self.assertIn(GHSA, result.stdout)
                        self.assertIn('installed ' + version, result.stdout)
                        self.assertIn(package, result.stdout)
                    else:
                        self.assertEqual(result.stdout, '')
        for package in ['other/http-foundation', 'symfony/other']:
            self.inventory(package=package)
            self.assertEqual(self.scan().stdout, '')
            self.assertEqual(self.scan().returncode, 0)

    def test_distinct_first_interval_lower_bounds(self):
        for package, status in [('symfony/http-foundation', 1), ('symfony/symfony', 0)]:
            with self.subTest(package=package):
                self.inventory('1.99.0', package)
                result = self.scan('sarif')
                self.assertEqual(result.returncode, status, result.stderr)
                results = json.loads(result.stdout)['runs'][0]['results']
                if status:
                    finding, = results
                    self.assertEqual(finding['properties']['affectedRange'], '<5.4.50')
                else:
                    self.assertEqual(results, [])

    def test_supplied_source_and_fixed_control(self):
        self.inventory()
        for fmt in ['text', 'github', 'sarif']:
            with self.subTest(fmt=fmt):
                result = self.scan(fmt)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(CVE, result.stdout)
                self.assertIn(GHSA, result.stdout)
                self.assertIn('possible', result.stdout)
                self.assertIn(str(self.lock), result.stdout)
                self.assertIn(str(self.source), result.stdout)
                if fmt == 'github':
                    self.assertIn(f'::notice file={self.source},line=9,title=phpscan {GHSA}::', result.stdout)
                self.assertIn('unknown', result.stdout)
                self.assertEqual(result.stdout, self.scan(fmt).stdout)
                self.inventory('7.3.7')
                fixed = self.scan(fmt)
                self.assertEqual(fixed.returncode, 0, fixed.stderr)
                if fmt == 'sarif':
                    self.assertEqual(json.loads(fixed.stdout)['runs'][0]['results'], [])
                else:
                    self.assertEqual(fixed.stdout, '')
                self.inventory()

    def test_sarif_keeps_dependency_and_possible_code_evidence_separate(self):
        self.inventory()
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 1, result.stderr)
        run = json.loads(result.stdout)['runs'][0]
        finding, = run['results']
        self.assertEqual(finding['ruleId'], GHSA)
        location, = finding['locations']
        self.assertEqual(location['physicalLocation']['artifactLocation']['uri'], str(self.lock))
        self.assertEqual(location['physicalLocation']['region']['startLine'], 5)
        props = finding['properties']
        self.assertEqual(props['evidenceKind'], 'dependency-version')
        self.assertEqual(props['cve'], CVE)
        self.assertEqual(props['package'], 'symfony/http-foundation')
        self.assertEqual(props['installedVersion'], 'v7.3.6')
        self.assertEqual(props['affectedRange'], '>=7.0.0,<7.3.7')
        self.assertEqual(props['fixedVersion'], '7.3.7')
        self.assertEqual(props['affectedCode'], 'possible')
        self.assertEqual(props['vulnerableFunctions'], [])
        for key in ['runtimeExposure', 'exploitability', 'deployment',
                    'middlewareRegistration', 'serverConfiguration', 'independentAuthorization']:
            self.assertEqual(props[key], 'unknown')
        self.assertEqual(len(props['sourceEvidence']), 1)
        related = [p['physicalLocation'] for p in finding['relatedLocations']]
        self.assertIn({'artifactLocation': {'uri': str(self.source)},
                       'region': {'startLine': 9}}, related)
        self.assertIn({'artifactLocation': {'uri': str(self.source)},
                       'region': {'startLine': 10}}, related)
        self.assertEqual(result.stderr, 'phpscan: 2 files, 1 findings, 0 incomplete\n')
        self.source.unlink()
        finding, = json.loads(self.scan('sarif').stdout)['runs'][0]['results']
        self.assertEqual(finding['properties']['affectedCode'], 'unknown')
        self.assertEqual(finding['properties'].get('sourceEvidence', []), [])

    def test_development_dependency_does_not_claim_deployment(self):
        self.inventory(group='packages-dev')
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 1, result.stderr)
        finding, = json.loads(result.stdout)['runs'][0]['results']
        self.assertEqual(finding['properties']['dependencyGroup'], 'packages-dev')
        self.assertEqual(finding['properties']['deployment'], 'unknown')
        self.assertEqual(finding['properties']['affectedCode'], 'possible')

    def test_multiple_package_matches_have_one_sarif_rule(self):
        self.lock.write_text(json.dumps({'packages': [
            {'name': 'symfony/http-foundation', 'version': '7.3.6'},
            {'name': 'symfony/symfony', 'version': '7.3.6'},
        ], 'packages-dev': []}))
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 1, result.stderr)
        run = json.loads(result.stdout)['runs'][0]
        self.assertEqual([r['ruleId'] for r in run['results']], [GHSA, GHSA])
        self.assertEqual([r['properties']['package'] for r in run['results']],
                         ['symfony/http-foundation', 'symfony/symfony'])
        self.assertEqual([r['id'] for r in run['tool']['driver']['rules']].count(GHSA), 1)
        self.assertEqual(result.stderr, 'phpscan: 2 files, 2 findings, 0 incomplete\n')

    def test_aliased_request_has_possible_evidence(self):
        self.inventory()
        self.source.write_text(SOURCE.replace('use Illuminate\\Http\\Request;',
                                             'use Illuminate\\Http\\Request as WebRequest;')
                               .replace('handle(Request ', 'handle(WebRequest '))
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(CVE, result.stdout)
        self.assertIn('possible', result.stdout)
        self.assertIn(str(self.source), result.stdout)

    def test_unknown_flows_do_not_gain_positive_source_evidence(self):
        self.inventory()
        variants = {
            'untyped': SOURCE.replace('handle(Request $request', 'handle($request'),
            'unrelated type': SOURCE.replace('Illuminate\\Http\\Request', 'Other\\Http\\Request'),
            'no import': SOURCE.replace('use Illuminate\\Http\\Request;', ''),
            'different receiver': SOURCE.replace('$request->getPathInfo()', '$other->getPathInfo()'),
            'no leading slash': SOURCE.replace("'/admin'", "'admin'"),
            'dynamic prefix': SOURCE.replace("'/admin'", '$prefix'),
            'prefix concatenation': SOURCE.replace("'/admin'", "'/admin' . $suffix"),
            'union receiver': SOURCE.replace('handle(Request $request', 'handle(Request|Other $request'),
            'union ending in Request': SOURCE.replace('handle(Request $request', 'handle(Other|Request $request'),
            'intersection ending in Request': SOURCE.replace('handle(Request $request', 'handle(Other&Request $request'),
            'unreachable marker': SOURCE.replace('abort_unless(auth()->check(), 403);',
                                                'function () { abort_unless(auth()->check(), 403); };'),
            'separate marker': SOURCE.replace('abort_unless(auth()->check(), 403);', "logger('admin');")
                                    .replace('return $next($request);', 'abort_unless(auth()->check(), 403); return $next($request);'),
            'no authorization': SOURCE.replace('abort_unless(auth()->check(), 403);', "logger('admin');"),
            'reassigned receiver': SOURCE.replace("        if (str_starts_with", "        $request = other_request();\n        if (str_starts_with"),
            'comment only': '<?php\n/*\n' + SOURCE + '\n*/\n',
            'string only': '<?php\n$example = <<<' + "'EXAMPLE'\n" + SOURCE + '\nEXAMPLE;\n',
        }
        for label, text in variants.items():
            with self.subTest(label=label):
                self.source.write_text(text)
                result = self.scan()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(CVE, result.stdout)
                self.assertIn('affected-code evidence unknown', result.stdout)
                self.assertNotIn('possible path-prefix', result.stdout)
        self.source.write_text(SOURCE)
        self.assertIn('possible', self.scan().stdout)

    def test_malformed_brackets_do_not_establish_source_evidence(self):
        self.inventory()
        for text in [SOURCE.rsplit('}', 1)[0],
                     SOURCE.replace("getPathInfo(), '/admin'", "getPathInfo(], '/admin'")]:
            with self.subTest(source=text):
                self.source.write_text(text)
                result = self.scan()
                self.assertIn(result.returncode, [1, 2], result.stderr)
                self.assertIn(CVE, result.stdout)
                self.assertIn('affected-code evidence unknown', result.stdout)
                self.assertNotIn('possible path-prefix', result.stdout)
        self.source.write_text(SOURCE)
        self.assertIn('possible', self.scan().stdout)

    def test_source_size_does_not_create_an_arbitrary_small_budget_failure(self):
        self.inventory()
        self.source.write_text(SOURCE.replace('class PrefixAccess', '$unused = 0;\n' * 600 + 'class PrefixAccess'))
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(CVE, result.stdout)
        self.assertIn('possible', result.stdout)
        self.assertIn(str(self.source), result.stdout)

    def test_case_insensitive_php_identifiers_keep_case_sensitive_variables(self):
        self.inventory()
        self.source.write_text(SOURCE.replace('namespace ', 'NAMESPACE ')
                               .replace('use Illuminate', 'USE Illuminate')
                               .replace('function handle', 'FUNCTION handle')
                               .replace('str_starts_with', 'STR_STARTS_WITH')
                               .replace('getPathInfo', 'GETPATHINFO')
                               .replace('abort_unless', 'ABORT_UNLESS'))
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('possible', result.stdout)
        self.source.write_text(SOURCE.replace('$request->getPathInfo()', '$REQUEST->getPathInfo()'))
        self.assertIn('affected-code evidence unknown', self.scan().stdout)

    def test_namespace_imports_do_not_leak(self):
        self.inventory()
        logging = SOURCE.replace('abort_unless(auth()->check(), 403);', "logger('admin');")
        second = SOURCE.replace('<?php', '').replace('namespace App\\Http\\Middleware;', 'namespace Unrelated;')
        second = second.replace('use Illuminate\\Http\\Request;', '').replace('class PrefixAccess', 'class OtherAccess')
        for declaration in [second, second.replace('namespace Unrelated;', 'NAMESPACE Unrelated;')]:
            self.source.write_text(logging + '\n' + declaration)
            result = self.scan()
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn(CVE, result.stdout)
            self.assertIn('affected-code evidence unknown', result.stdout)
            self.assertNotIn('possible path-prefix', result.stdout)
        self.source.write_text(SOURCE)
        self.assertIn('possible', self.scan().stdout)

    def test_symfony_alias_and_fully_qualified_type(self):
        self.inventory()
        for declaration, parameter in [
            ('use Symfony\\Component\\HttpFoundation\\Request;', 'Request'),
            ('use Symfony\\Component\\HttpFoundation\\Request as FoundationRequest;', 'FoundationRequest'),
            ('', '\\Symfony\\Component\\HttpFoundation\\Request'),
            ('', '\\Illuminate\\Http\\Request'),
        ]:
            with self.subTest(parameter=parameter):
                self.source.write_text(SOURCE.replace('use Illuminate\\Http\\Request;', declaration)
                                       .replace('handle(Request ', 'handle(' + parameter + ' '))
                result = self.scan()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('possible', result.stdout)
                self.assertIn(str(self.source), result.stdout)

    def test_unresolved_version_and_source_finding_exit_precedence(self):
        self.inventory('dev-main')
        self.source.write_text("<?php echo $_GET['name'];\n")
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 2, result.stderr)
        rules = [r['ruleId'] for r in json.loads(result.stdout)['runs'][0]['results']]
        self.assertIn('PHP-XSS', rules)
        self.assertIn('PHP-ADVISORY-INCOMPLETE', rules)
        self.inventory()
        result = self.scan('sarif')
        self.assertEqual(result.returncode, 1, result.stderr)
        rules = [r['ruleId'] for r in json.loads(result.stdout)['runs'][0]['results']]
        self.assertIn('PHP-XSS', rules)
        self.assertIn(GHSA, rules)

    def test_nested_projects_do_not_supply_source_evidence(self):
        self.inventory()
        self.source.unlink()
        nested = self.root / 'nested'
        nested.mkdir()
        (nested / 'PrefixAccess.php').write_text(SOURCE)
        for marker in ['composer.json', 'composer.lock']:
            with self.subTest(marker=marker):
                path = nested / marker
                path.write_text('{"packages":[]}')
                result = self.scan()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(CVE, result.stdout)
                self.assertIn('affected-code evidence unknown', result.stdout)
                self.assertNotIn('possible path-prefix', result.stdout)
                path.unlink()
        (nested / 'composer.lock').write_text(self.lock.read_text())
        result = self.scan('sarif', self.root, nested)
        self.assertEqual(result.returncode, 1, result.stderr)
        results = json.loads(result.stdout)['runs'][0]['results']
        self.assertEqual([r['properties']['affectedCode'] for r in results], ['unknown', 'possible'])

    def test_suppression_removes_code_evidence_not_dependency_match(self):
        self.inventory()
        for source in [SOURCE.replace('        if (', '        // phpscan-ignore\n        if ('),
                       SOURCE.replace("'/admin')) {", "'/admin')) { // phpscan-ignore")]:
            with self.subTest(source=source):
                self.source.write_text(source)
                result = self.scan('sarif')
                self.assertEqual(result.returncode, 1, result.stderr)
                finding, = json.loads(result.stdout)['runs'][0]['results']
                self.assertEqual(finding['ruleId'], GHSA)
                self.assertEqual(finding['properties']['affectedCode'], 'unknown')
                self.assertEqual(finding['properties']['sourceEvidence'], [])
        self.source.write_text(SOURCE)
        self.assertEqual(json.loads(self.scan('sarif').stdout)['runs'][0]['results'][0]['properties']['affectedCode'], 'possible')

    def test_other_scan_roots_do_not_supply_source_evidence(self):
        self.inventory()
        self.source.unlink()
        sibling = self.root.parent / (self.root.name + '-other')
        sibling.mkdir()
        self.addCleanup(lambda: sibling.rmdir())
        foreign_source = sibling / 'PrefixAccess.php'
        foreign_source.write_text(SOURCE)
        self.addCleanup(foreign_source.unlink)
        result = self.scan('text', self.root, sibling)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(CVE, result.stdout)
        self.assertIn('affected-code evidence unknown', result.stdout)
        self.assertNotIn('possible path-prefix', result.stdout)
        self.source.write_text(SOURCE)
        self.assertIn(str(self.source), self.scan().stdout)

    def test_logging_is_not_an_access_check(self):
        self.inventory()
        self.source.write_text(SOURCE.replace(
            "if (str_starts_with($request->getPathInfo(), '/admin')) {\n"
            "            abort_unless(auth()->check(), 403);\n        }",
            "logger($request->getPathInfo());"))
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(CVE, result.stdout)
        self.assertIn('affected-code evidence unknown', result.stdout)
        self.assertNotIn('possible path-prefix', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
