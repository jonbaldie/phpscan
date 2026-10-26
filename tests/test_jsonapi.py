#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

BINARY = pathlib.Path(sys.argv.pop(1)).resolve()
GHSA = 'GHSA-5wcm-3v2w-8362'
CVE = 'CVE-2026-114508'
RESOURCE = r'''<?php
namespace App\Http\Resources;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\JsonApi\JsonApiResource;
class UserResource extends JsonApiResource
{
    public function toRelationships(Request $request): array
    {
        return ['comments'];
    }
}
'''
ROUTE = r'''<?php
use App\Models\User;
use App\Http\Resources\UserResource;
use Illuminate\Support\Facades\Route;
Route::get('/users/{user}', fn (User $user) => new UserResource($user));
'''


class JsonApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.lock = self.root / 'composer.lock'
        self.resource = self.root / 'app/Http/Resources/UserResource.php'
        self.route = self.root / 'routes/api.php'
        for path, source in [(self.resource, RESOURCE), (self.route, ROUTE)]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        self.inventory()

    def inventory(self, version='v12.67.0', package='laravel/framework'):
        self.lock.write_text(json.dumps({'packages': [
            {'name': package, 'version': version}], 'packages-dev': []}, indent=2))

    def scan(self, fmt='sarif', *roots):
        return subprocess.run([str(BINARY), '--format=' + fmt,
                               *(str(p) for p in (roots or [self.root]))],
                              capture_output=True, text=True, timeout=60)

    def finding(self, result):
        self.assertEqual(result.returncode, 1, result.stderr)
        matches = [r for r in json.loads(result.stdout)['runs'][0]['results']
                   if r['ruleId'] == GHSA]
        self.assertEqual(len(matches), 1, result.stdout)
        return matches[0]

    def test_reviewed_version_boundaries(self):
        self.resource.unlink()
        self.route.unlink()
        for version, expected, exit_status in [('12.44.9', 0, 1), ('12.45.0', 1, 1),
                                               ('v12.67.0', 1, 1), ('12.68.0', 0, 0),
                                               ('13.0.0', 1, 1), ('13.26.9', 1, 1),
                                               ('13.27.0', 0, 1), ('14.0.0', 0, 0)]:
            with self.subTest(version=version):
                self.inventory(version)
                result = self.scan()
                self.assertEqual(result.returncode, exit_status, result.stderr)
                results = json.loads(result.stdout)['runs'][0]['results']
                self.assertEqual([r['ruleId'] for r in results],
                                 ([GHSA] if expected else []) +
                                 (['GHSA-f9x3-7vq9-cph6'] if exit_status else []))
                matches = [r for r in results if r['ruleId'] == GHSA]
                self.assertEqual(len(matches), expected)
                if expected:
                    finding = self.finding(result)
                    self.assertEqual(finding['properties']['cve'], CVE)
                    self.assertEqual(finding['properties']['affectedCode'], 'unknown')
                    self.assertEqual(finding['properties']['sourceEvidence'], [])
                    self.assertEqual(finding['properties']['installedVersion'], version)
        self.inventory(package='other/framework')
        self.assertEqual(self.scan('text').returncode, 0)
        self.assertEqual(self.scan('text').stdout, '')

    def test_supplied_resource_and_route_in_all_formats(self):
        finding = self.finding(self.scan())
        self.assertEqual(finding['properties']['evidenceKind'], 'dependency-version')
        self.assertEqual(finding['properties']['affectedCode'], 'possible')
        self.assertEqual(finding['properties']['vulnerableFunctions'], [])
        location, = finding['locations']
        self.assertEqual(location['physicalLocation'], {
            'artifactLocation': {'uri': str(self.lock)}, 'region': {'startLine': 5}})
        related = [loc['physicalLocation'] for loc in finding['relatedLocations']]
        self.assertIn({'artifactLocation': {'uri': str(self.resource)},
                       'region': {'startLine': 5}}, related)
        self.assertIn({'artifactLocation': {'uri': str(self.route)},
                       'region': {'startLine': 5}}, related)
        self.assertEqual({(loc['artifactLocation']['uri'], loc['region']['startLine'])
                          for loc in related},
                         {(str(self.resource), 5), (str(self.resource), 9),
                          (str(self.route), 5)})
        self.assertEqual(finding['properties']['sourceEvidence'], [
            {'kind': 'jsonapi-resource', 'sourcePath': str(self.resource), 'line': 5,
             'status': 'possible',
             'detail': r'direct JsonApiResource subclass app\http\resources\userresource; literal declared relationships: [comments]; model resolution unknown; runtime registration unknown; exploitability unknown'},
            {'kind': 'jsonapi-relationships', 'sourcePath': str(self.resource), 'line': 9,
             'status': 'possible',
             'detail': 'literal declared relationships: [comments]; model resolution unknown'},
            {'kind': 'jsonapi-endpoint', 'sourcePath': str(self.route), 'line': 5,
             'status': 'possible',
             'detail': r'literal GET /users/{user} returns app\http\resources\userresource; model resolution unknown; runtime registration unknown; exploitability unknown'},
        ])
        self.assertEqual(finding['properties']['runtimeExposure'], 'unknown')
        self.assertEqual(finding['properties']['exploitability'], 'unknown')
        for fmt in ['text', 'github', 'sarif']:
            with self.subTest(fmt=fmt):
                result = self.scan(fmt)
                self.assertEqual(result.returncode, 1, result.stderr)
                for expected in [CVE, GHSA, str(self.lock), str(self.resource),
                                 str(self.route), 'comments', 'unknown', 'possible']:
                    self.assertIn(expected, result.stdout)
                self.assertEqual(result.stdout, self.scan(fmt).stdout)

    def test_ordinary_json_resource_keeps_only_version_match(self):
        self.resource.write_text(RESOURCE.replace(
            'Resources\\JsonApi\\JsonApiResource', 'Resources\\Json\\JsonResource')
                                 .replace('extends JsonApiResource', 'extends JsonResource'))
        finding = self.finding(self.scan())
        self.assertEqual(finding['properties']['affectedCode'], 'unknown')
        self.assertEqual(finding['properties']['sourceEvidence'], [])
        self.assertEqual(finding.get('relatedLocations', []), [])

    def test_aliased_resource_and_endpoint_imports(self):
        self.resource.write_text(RESOURCE.replace('JsonApiResource;', 'JsonApiResource as ApiBase;')
                                 .replace('extends JsonApiResource', 'extends ApiBase'))
        self.route.write_text(ROUTE.replace('Resources\\UserResource;',
                                           'Resources\\UserResource as ApiUser;')
                              .replace('new UserResource', 'new ApiUser'))
        finding = self.finding(self.scan())
        related = json.dumps(finding['relatedLocations'])
        self.assertIn(str(self.resource), related)
        self.assertIn(str(self.route), related)

    def test_dynamic_relationships_and_unresolved_routes_stay_unknown(self):
        self.resource.write_text(RESOURCE.replace("return ['comments'];", 'return $this->relationships();'))
        finding = self.finding(self.scan())
        self.assertIn('unknown', finding['message']['text'])
        self.assertEqual(finding['properties']['sourceEvidence'], [
            {'kind': 'jsonapi-resource', 'sourcePath': str(self.resource), 'line': 5,
             'status': 'possible',
             'detail': r'direct JsonApiResource subclass app\http\resources\userresource; dynamic relationships; relationships unknown; model resolution unknown; runtime registration unknown; exploitability unknown'},
            {'kind': 'jsonapi-relationships', 'sourcePath': str(self.resource), 'line': 9,
             'status': 'unknown',
             'detail': 'dynamic relationships; relationships unknown; model resolution unknown'},
        ])
        self.assertNotIn(str(self.route), json.dumps(finding.get('relatedLocations', [])))
        self.resource.write_text(RESOURCE)
        self.route.write_text(ROUTE.replace('new UserResource', 'new OtherResource'))
        finding = self.finding(self.scan())
        self.assertNotIn(str(self.route), json.dumps(finding.get('relatedLocations', [])))
        self.assertIn('unknown', finding['message']['text'])

    def test_route_requires_two_explicit_positional_arguments(self):
        for route in [
                ROUTE.replace("'/users/{user}',", "uri: '/users/{user}',"),
                ROUTE.replace('fn (User $user)', 'action: fn (User $user)'),
                ROUTE.replace('new UserResource($user));', 'new UserResource($user), $extra);'),
                ROUTE.replace('fn (User $user) => new UserResource($user)', '...$callbacks')]:
            with self.subTest(route=route):
                self.route.write_text(route)
                finding = self.finding(self.scan())
                self.assertEqual([site['kind'] for site in finding['properties']['sourceEvidence']],
                                 ['jsonapi-resource', 'jsonapi-relationships'])
                self.assertNotIn(str(self.route), json.dumps(finding.get('relatedLocations', [])))
        self.route.write_text(ROUTE)
        self.assertEqual([site['kind'] for site in self.finding(self.scan())['properties']['sourceEvidence']],
                         ['jsonapi-resource', 'jsonapi-relationships', 'jsonapi-endpoint'])

    def test_unsupported_string_forms_do_not_establish_literal_links(self):
        for value in [r'"com\x6dents"', "<<<'NAMES'\ncomments\nNAMES"]:
            with self.subTest(value=value):
                self.resource.write_text(RESOURCE.replace("['comments']", '[' + value + ']'))
                finding = self.finding(self.scan())
                self.assertEqual([(site['kind'], site['status'])
                                  for site in finding['properties']['sourceEvidence']],
                                 [('jsonapi-resource', 'possible'),
                                  ('jsonapi-relationships', 'unknown')])
                self.assertNotIn(str(self.route), json.dumps(finding.get('relatedLocations', [])))
        self.resource.write_text(RESOURCE)
        self.route.write_text(ROUTE.replace("'/users/{user}'", r'"/users/\x61"'))
        finding = self.finding(self.scan())
        self.assertEqual([site['kind'] for site in finding['properties']['sourceEvidence']],
                         ['jsonapi-resource', 'jsonapi-relationships'])
        self.route.write_text(ROUTE)
        self.assertEqual([site['kind'] for site in self.finding(self.scan())['properties']['sourceEvidence']],
                         ['jsonapi-resource', 'jsonapi-relationships', 'jsonapi-endpoint'])

    def test_nested_function_is_not_a_relationship_method(self):
        self.resource.write_text(RESOURCE.replace(
            "    public function toRelationships(Request $request): array\n"
            "    {\n        return ['comments'];\n    }",
            "    public function helper()\n"
            "    {\n        function toRelationships() { return ['comments']; }\n    }"))
        finding = self.finding(self.scan())
        self.assertEqual([site['kind'] for site in finding['properties']['sourceEvidence']],
                         ['jsonapi-resource'])
        self.assertIn('relationship declaration unavailable', finding['message']['text'])
        self.assertNotIn(str(self.route), json.dumps(finding.get('relatedLocations', [])))
        self.resource.write_text(RESOURCE)
        self.assertEqual([site['kind'] for site in self.finding(self.scan())['properties']['sourceEvidence']],
                         ['jsonapi-resource', 'jsonapi-relationships', 'jsonapi-endpoint'])

    def test_comments_and_strings_are_not_source_evidence(self):
        for text in ['<?php\n/*\n' + RESOURCE + '\n*/\n',
                     "<?php\n$example = <<<'PHP_SAMPLE'\n" + RESOURCE + '\nPHP_SAMPLE;\n']:
            with self.subTest(source=text):
                self.resource.write_text(text)
                finding = self.finding(self.scan())
                self.assertEqual(finding['properties']['affectedCode'], 'unknown')
                self.assertEqual(finding['properties']['sourceEvidence'], [])

    def test_nested_composer_project_does_not_supply_evidence(self):
        nested = self.root / 'nested'
        nested.mkdir()
        (nested / 'composer.json').write_text('{}')
        self.resource.rename(nested / 'UserResource.php')
        self.route.rename(nested / 'api.php')
        finding = self.finding(self.scan())
        self.assertEqual(finding['properties']['affectedCode'], 'unknown')
        self.assertEqual(finding['properties']['sourceEvidence'], [])

    def test_suppressed_prerequisites_do_not_reappear_through_endpoints(self):
        self.finding(self.scan())
        self.resource.write_text(RESOURCE.replace(
            'class UserResource extends JsonApiResource',
            'class UserResource extends JsonApiResource // phpscan-ignore'))
        finding = self.finding(self.scan())
        self.assertEqual(finding['properties']['affectedCode'], 'unknown')
        self.assertEqual(finding['properties']['sourceEvidence'], [])
        self.assertEqual(finding.get('relatedLocations', []), [])
        self.resource.write_text(RESOURCE.replace(
            "return ['comments'];", "return ['comments']; // phpscan-ignore"))
        finding = self.finding(self.scan())
        related = [loc['physicalLocation'] for loc in finding.get('relatedLocations', [])]
        self.assertNotIn(str(self.route), json.dumps(related))
        self.assertNotIn({'artifactLocation': {'uri': str(self.resource)},
                          'region': {'startLine': 9}}, related)
        self.assertNotIn('comments', json.dumps(finding['properties']['sourceEvidence']))
        self.assertEqual([(row['kind'], row['line'])
                          for row in finding['properties']['sourceEvidence']],
                         [('jsonapi-resource', 5)])
        self.assertIn('relationship declaration suppressed', finding['message']['text'])
        self.resource.write_text(RESOURCE)
        self.route.write_text(ROUTE.replace('Route::get', '// phpscan-ignore\nRoute::get'))
        finding = self.finding(self.scan())
        self.assertNotIn(str(self.route), json.dumps(finding.get('relatedLocations', [])))
        self.assertIn('comments', json.dumps(finding['properties']['sourceEvidence']))

    def test_duplicate_class_including_suppressed_declaration_blocks_join(self):
        self.finding(self.scan())
        duplicate = self.root / 'duplicate.php'
        for prefix in ['', '// phpscan-ignore\n']:
            with self.subTest(prefix=prefix):
                duplicate.write_text('<?php\nnamespace App\\Http\\Resources;\n' +
                                     prefix + 'class USERRESOURCE {}\n')
                finding = self.finding(self.scan())
                self.assertEqual(finding['properties']['sourceEvidence'], [])
                self.assertEqual(finding.get('relatedLocations', []), [])

    def test_exact_namespace_link_and_explicit_closure_endpoint(self):
        self.route.write_text(r'''<?php
namespace Elsewhere;
use Illuminate\Support\Facades\Route;
Route::get('/wrong', fn () => new UserResource());
''')
        finding = self.finding(self.scan())
        self.assertNotIn(str(self.route), json.dumps(finding.get('relatedLocations', [])))
        self.route.write_text(r'''<?php
\Illuminate\Support\Facades\Route::get('/users', function () {
    return new \App\Http\Resources\UserResource();
});
''')
        finding = self.finding(self.scan())
        self.assertIn({'artifactLocation': {'uri': str(self.route)},
                       'region': {'startLine': 2}},
                      [loc['physicalLocation'] for loc in finding['relatedLocations']])

    def test_ambiguous_imports_and_malformed_brackets_are_unknown(self):
        self.finding(self.scan())
        for source in [RESOURCE.replace('class UserResource',
                                       'use Other\\Base as JsonApiResource;\nclass UserResource'),
                       RESOURCE + '}\n']:
            with self.subTest(source=source):
                self.resource.write_text(source)
                finding = self.finding(self.scan())
                self.assertEqual(finding['properties']['sourceEvidence'], [])
                self.assertEqual(finding.get('relatedLocations', []), [])

    def test_separate_roots_and_lockfile_only_are_version_only(self):
        self.finding(self.scan())
        separate = self.root / 'lock-only'
        separate.mkdir()
        separate_lock = separate / 'composer.lock'
        self.lock.rename(separate_lock)
        for roots in [(separate_lock,), (separate, self.resource.parent, self.route.parent)]:
            with self.subTest(roots=roots):
                finding = self.finding(self.scan('sarif', *roots))
                self.assertEqual(finding['properties']['affectedCode'], 'unknown')
                self.assertEqual(finding['properties']['sourceEvidence'], [])
                self.assertEqual(finding.get('relatedLocations', []), [])

    def test_laravel_advisories_keep_their_own_observations(self):
        config = self.root / 'config'
        config.mkdir()
        (config / 'auth.php').write_text("<?php\nreturn ['guards' => ['api' => [\n"
                                       "'driver' => 'token', 'provider' => 'users', 'hash' => false\n"
                                       "]], 'providers' => ['users' => ['driver' => 'eloquent']]];\n")
        (config / 'database.php').write_text("<?php\nreturn ['default' => 'mysql'];\n")
        (self.root / 'routes/guard.php').write_text(
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\n"
            "Route::middleware('auth:api')->get('/account', fn () => 1);\n")
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        findings = {row['ruleId']: row for row in json.loads(result.stdout)['runs'][0]['results']}
        self.assertEqual(set(findings), {GHSA, 'GHSA-f9x3-7vq9-cph6'})
        self.assertEqual([row['kind'] for row in findings[GHSA]['properties']['sourceEvidence']],
                         ['jsonapi-resource', 'jsonapi-relationships', 'jsonapi-endpoint'])
        self.assertEqual([row['kind'] for row in
                          findings['GHSA-f9x3-7vq9-cph6']['properties']['sourceEvidence']],
                         ['token-guard', 'guard-route', 'database-selection'])
        self.assertNotIn(str(config), json.dumps(findings[GHSA]['relatedLocations']))
        self.assertNotIn(str(self.resource),
                         json.dumps(findings['GHSA-f9x3-7vq9-cph6']['relatedLocations']))
        self.inventory('12.44.9')
        result = self.scan()
        self.assertEqual(result.returncode, 1, result.stderr)
        guard, = json.loads(result.stdout)['runs'][0]['results']
        self.assertEqual(guard['ruleId'], 'GHSA-f9x3-7vq9-cph6')
        self.assertEqual([row['kind'] for row in guard['properties']['sourceEvidence']],
                         ['token-guard', 'guard-route', 'database-selection'])

    def test_source_is_not_executed(self):
        marker = self.root / 'executed'
        self.route.write_text(ROUTE + "file_put_contents('" + str(marker) + "', 'ran');\n")
        finding = self.finding(self.scan())
        self.assertEqual(finding['properties']['affectedCode'], 'possible')
        self.assertFalse(marker.exists())

    def test_taint_findings_and_incomplete_exit_precedence(self):
        (self.root / 'unsafe.php').write_text("<?php echo $_GET['name'];\n")
        result = self.scan()
        self.finding(result)
        self.assertIn('PHP-XSS', [r['ruleId'] for r in json.loads(result.stdout)['runs'][0]['results']])
        self.inventory('dev-main')
        result = self.scan()
        self.assertEqual(result.returncode, 2, result.stderr)
        rules = [r['ruleId'] for r in json.loads(result.stdout)['runs'][0]['results']]
        self.assertIn('PHP-XSS', rules)
        self.assertIn('PHP-ADVISORY-INCOMPLETE', rules)


if __name__ == '__main__':
    unittest.main(verbosity=2)
