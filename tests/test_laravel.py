#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

BINARY = pathlib.Path(sys.argv.pop(1)).resolve()
GHSA = 'GHSA-f9x3-7vq9-cph6'
CVE = 'CVE-2026-114509'
AUTH = r'''<?php
return ['guards' => ['api' => [
    'driver' => 'token', 'provider' => 'users', 'hash' => false,
]], 'providers' => ['users' => ['driver' => 'eloquent', 'model' => App\Models\User::class]]];
'''
DATABASE = "<?php\nreturn ['default' => 'mysql'];\n"
ROUTE = r'''<?php
use Illuminate\Support\Facades\Route;
Route::middleware('auth:api')->get('/account', fn () => ['id' => auth()->id()]);
'''


class LaravelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.lock = self.root / 'composer.lock'
        self.auth = self.root / 'config/auth.php'
        self.database = self.root / 'config/database.php'
        self.route = self.root / 'routes/api.php'
        for path, text in [(self.auth, AUTH), (self.database, DATABASE), (self.route, ROUTE)]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.inventory()

    def inventory(self, version='v12.67.0', package='laravel/framework', group='packages'):
        data = {'packages': [], 'packages-dev': []}
        data[group] = [{'name': package, 'version': version}]
        self.lock.write_text(json.dumps(data, indent=2))

    def scan(self, fmt='sarif', *paths):
        return subprocess.run([str(BINARY), '--format=' + fmt,
                               *(str(p) for p in (paths or [self.root]))],
                              capture_output=True, text=True, timeout=60)

    def finding(self, result=None):
        result = result or self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        matches = [r for r in json.loads(result.stdout)['runs'][0]['results'] if r['ruleId'] == GHSA]
        self.assertEqual(len(matches), 1, result.stdout)
        return matches[0]

    def test_version_intervals_independent_of_source(self):
        for path in [self.auth, self.database, self.route]:
            path.unlink()
        for version, expected in [
                ('0.0.1', 1), ('v12.67.0', 1), ('12.68.0', 0), ('12.70.0', 0),
                ('13.0.0', 1), ('13.28.0', 1), ('13.29.0', 0), ('14.0.0', 0)]:
            with self.subTest(version=version):
                self.inventory(version)
                result = self.scan()
                self.assertEqual(result.returncode, expected, result.stderr)
                results = json.loads(result.stdout)['runs'][0]['results']
                if expected:
                    finding = self.finding(result)
                    props = finding['properties']
                    self.assertEqual(props['cve'], CVE)
                    self.assertEqual(props['installedVersion'], version)
                    self.assertEqual(props['affectedCode'], 'unknown')
                    self.assertEqual(props['sourceEvidence'], [])
                    self.assertEqual(props['affectedRange'],
                                     '>=13.0.0,<13.29.0' if version.startswith('13.') else '<12.68.0')
                else:
                    self.assertEqual(results, [])
        self.inventory(package='laravel/framework-extra')
        self.assertEqual(self.scan().returncode, 0)
        self.assertEqual(json.loads(self.scan().stdout)['runs'][0]['results'], [])

    def test_literal_profile_has_separate_observations_and_locations(self):
        finding = self.finding()
        props = finding['properties']
        self.assertEqual(props['evidenceKind'], 'dependency-version')
        self.assertEqual(props['ghsa'], GHSA)
        self.assertEqual(props['package'], 'laravel/framework')
        self.assertEqual(props['fixedVersion'], '12.68.0')
        self.assertEqual(props['vulnerableFunctions'], [])
        self.assertEqual(props['affectedCode'], 'possible')
        for key in ['runtimeExposure', 'exploitability', 'deployment']:
            self.assertEqual(props[key], 'unknown')
        self.assertEqual(finding['locations'][0]['physicalLocation'], {
            'artifactLocation': {'uri': str(self.lock)}, 'region': {'startLine': 5}})
        observed = {(s['kind'], s['sourcePath'], s['line'], s['status'])
                    for s in props['sourceEvidence']}
        self.assertEqual(observed, {
            ('token-guard', str(self.auth), 3, 'possible'),
            ('guard-route', str(self.route), 3, 'possible'),
            ('database-selection', str(self.database), 2, 'possible'),
        })
        related = {(l['physicalLocation']['artifactLocation']['uri'],
                    l['physicalLocation']['region']['startLine'])
                   for l in finding['relatedLocations']}
        self.assertEqual(related, {(str(self.auth), 3), (str(self.route), 3), (str(self.database), 2)})
        self.assertIn('mysql', json.dumps(props['sourceEvidence']))

    def test_all_formats_are_deterministic_and_fixed_control_is_clean(self):
        for fmt in ['text', 'github', 'sarif']:
            with self.subTest(fmt=fmt):
                result = self.scan(fmt)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(GHSA, result.stdout)
                self.assertIn(CVE, result.stdout)
                self.assertEqual(result.stdout, self.scan(fmt).stdout)
                for path in [self.lock, self.auth, self.database, self.route]:
                    self.assertIn(str(path).replace('\\', '\\\\') if fmt == 'sarif' else str(path), result.stdout)
                for kind in ['token-guard', 'guard-route', 'database-selection']:
                    self.assertIn(kind, result.stdout)
                if fmt == 'github':
                    for path, line in [(self.auth, 3), (self.database, 2), (self.route, 3)]:
                        self.assertIn(f'::notice file={path},line={line},title=phpscan {GHSA}::', result.stdout)
                self.inventory('12.68.0')
                fixed = self.scan(fmt)
                self.assertEqual(fixed.returncode, 0, fixed.stderr)
                self.assertEqual(json.loads(fixed.stdout)['runs'][0]['results'] if fmt == 'sarif' else fixed.stdout,
                                 [] if fmt == 'sarif' else '')
                self.inventory()

    def test_dynamic_database_keeps_explicit_unknown_observation(self):
        self.database.write_text("<?php\nreturn ['default' => env('DB_CONNECTION')];\n")
        finding = self.finding()
        evidence = finding['properties']['sourceEvidence']
        self.assertEqual({s['kind'] for s in evidence if s['status'] == 'possible'},
                         {'token-guard', 'guard-route'})
        database, = [s for s in evidence if s['kind'] == 'database-selection']
        self.assertEqual((database['sourcePath'], database['line'], database['status']),
                         (str(self.database), 2, 'unknown'))
        self.assertEqual(finding['properties']['runtimeExposure'], 'unknown')
        for fmt in ['text', 'github']:
            result = self.scan(fmt)
            self.assertEqual(result.returncode, 1)
            self.assertIn('database-selection', result.stdout)
            self.assertIn('unknown', result.stdout)
            self.assertIn(str(self.database), result.stdout)

    def test_mariadb_is_literal_evidence_but_other_databases_are_not(self):
        for database, status in [('mariadb', 'possible'), ('pgsql', 'unknown'), ('sqlite', 'unknown')]:
            with self.subTest(database=database):
                self.database.write_text(DATABASE.replace('mysql', database))
                item, = [s for s in self.finding()['properties']['sourceEvidence']
                         if s['kind'] == 'database-selection']
                self.assertEqual(item['status'], status)

    def test_unresolved_guard_route_or_provider_has_no_positive_token_profile(self):
        variants = [
            (AUTH.replace("'token'", "'sanctum'"), ROUTE),
            (AUTH.replace("'token'", "'passport'"), ROUTE),
            (AUTH.replace("'eloquent'", "'custom-provider'"), ROUTE),
            (AUTH.replace("'hash' => false", "'hash' => true"), ROUTE),
            (AUTH.replace("'token'", "env('AUTH_DRIVER')"), ROUTE),
            (AUTH, ROUTE.replace('auth:api', 'auth:web')),
            (AUTH, "<?php\nlogger('auth:api');\n"),
            (AUTH, ROUTE.replace('Illuminate\\Support\\Facades\\Route', 'Other\\Route')),
            (AUTH, ROUTE.replace("'auth:api'", '$middleware')),
            (AUTH, '<?php\n/* ' + ROUTE + ' */\n'),
        ]
        for auth, route in variants:
            with self.subTest(auth=auth, route=route):
                self.auth.write_text(auth)
                self.route.write_text(route)
                props = self.finding()['properties']
                self.assertEqual(props['affectedCode'], 'unknown')
                self.assertFalse(any(s['status'] == 'possible' for s in props['sourceEvidence']))
        self.auth.write_text(AUTH)
        self.route.write_text(ROUTE)
        self.assertEqual(self.finding()['properties']['affectedCode'], 'possible')
        self.route.unlink()
        self.assertEqual(self.finding()['properties']['affectedCode'], 'unknown')

    def test_unsupported_string_escapes_do_not_establish_literal_configuration(self):
        self.auth.write_text(AUTH.replace("'token'", r'"t\oken"'))
        props = self.finding()['properties']
        self.assertEqual(props['affectedCode'], 'unknown')
        self.auth.write_text(AUTH)
        self.database.write_text(DATABASE.replace("'mysql'", r'"my\sql"'))
        item, = [s for s in self.finding()['properties']['sourceEvidence']
                 if s['kind'] == 'database-selection']
        self.assertEqual(item['status'], 'unknown')
        self.database.write_text(DATABASE)
        self.assertEqual(self.finding()['properties']['affectedCode'], 'possible')

    def test_unrelated_arrays_and_malformed_config_are_not_guard_evidence(self):
        variants = [
            AUTH.replace("'guards'", "'unrelated'"),
            "<?php\nlogger(['guards' => ['api' => ['driver' => 'token']]]);\n",
            AUTH.replace("'driver' => 'token'", "'driver' => 'token' . $suffix"),
            AUTH.replace("'driver' => 'token'", "'driver' => 'token', 'driver' => 'sanctum'"),
            AUTH.replace("'api' => [", "'api' => array_merge($defaults, [").replace("]], 'providers'", "])], 'providers'"),
            AUTH.rsplit(']', 1)[0],
        ]
        for auth in variants:
            with self.subTest(auth=auth):
                self.auth.write_text(auth)
                props = self.finding()['properties']
                self.assertEqual(props['affectedCode'], 'unknown')
        self.auth.write_text(AUTH)
        self.assertEqual(self.finding()['properties']['affectedCode'], 'possible')

    def test_projects_and_explicit_input_arguments_do_not_share_evidence(self):
        sibling = self.root / 'nested'
        sibling.mkdir()
        (sibling / 'composer.json').write_text('{}')
        for path in [self.auth, self.database, self.route]:
            target = sibling / path.relative_to(self.root)
            target.parent.mkdir(parents=True, exist_ok=True)
            path.rename(target)
        self.assertEqual(self.finding()['properties']['affectedCode'], 'unknown')
        (sibling / 'composer.lock').write_text(self.lock.read_text())
        result = self.scan('sarif', self.root, sibling)
        self.assertEqual(result.returncode, 1, result.stderr)
        results = json.loads(result.stdout)['runs'][0]['results']
        self.assertEqual([r['properties']['affectedCode'] for r in results], ['unknown', 'possible'])
        result = self.scan('sarif', self.lock, sibling / 'config/auth.php',
                           sibling / 'config/database.php', sibling / 'routes/api.php')
        self.assertEqual(self.finding(result)['properties']['affectedCode'], 'unknown')

    def test_mixed_advisories_keep_profile_observations_separate(self):
        self.lock.write_text(json.dumps({'packages': [
            {'name': 'laravel/framework', 'version': '12.67.0'},
            {'name': 'symfony/http-foundation', 'version': '7.3.6'},
        ]}))
        (self.root / 'Prefix.php').write_text(r'''<?php
use Illuminate\Http\Request;
function access(Request $request) {
    if (str_starts_with($request->getPathInfo(), '/admin')) {
        abort_unless(auth()->check(), 403);
    }
}
''')
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        findings = {r['ruleId']: r for r in json.loads(result.stdout)['runs'][0]['results']}
        self.assertEqual(set(findings), {GHSA, 'GHSA-3rg7-wf37-54rm'})
        self.assertEqual({s['kind'] for s in findings[GHSA]['properties']['sourceEvidence']},
                         {'token-guard', 'guard-route', 'database-selection'})
        self.assertEqual({s['kind'] for s in findings['GHSA-3rg7-wf37-54rm']['properties']['sourceEvidence']},
                         {'possible path-prefix access check'})

    def test_development_group_and_incomplete_precedence(self):
        self.inventory(group='packages-dev')
        finding = self.finding()
        self.assertEqual(finding['properties']['dependencyGroup'], 'packages-dev')
        self.assertEqual(finding['properties']['deployment'], 'unknown')
        self.inventory('dev-main')
        (self.root / 'unsafe.php').write_text("<?php echo $_GET['name'];\n")
        result = self.scan()
        self.assertEqual(result.returncode, 2, result.stderr)
        rules = {r['ruleId'] for r in json.loads(result.stdout)['runs'][0]['results']}
        self.assertEqual(rules, {'PHP-XSS', 'PHP-ADVISORY-INCOMPLETE'})
        self.inventory()
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual({r['ruleId'] for r in json.loads(result.stdout)['runs'][0]['results']},
                         {'PHP-XSS', GHSA})

    def test_suppression_drops_source_evidence_not_the_dependency_match(self):
        self.route.write_text(ROUTE.replace("Route::middleware", "// phpscan-ignore\nRoute::middleware"))
        props = self.finding()['properties']
        self.assertEqual(props['affectedCode'], 'unknown')
        self.route.write_text(ROUTE)
        self.assertEqual(self.finding()['properties']['affectedCode'], 'possible')


if __name__ == '__main__':
    unittest.main(verbosity=2)
