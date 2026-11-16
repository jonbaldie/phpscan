#!/usr/bin/env python3
"""Compare two real scanners on deterministic state-transition inputs."""
import argparse
import itertools
import json
from pathlib import Path
import subprocess
import tempfile


def corpus(root):
    php = root / 'php'
    php.mkdir()
    expressions = [
        "$_GET['x']", "htmlspecialchars($_GET['x'])", "intval($_GET['x'])",
        "htmlspecialchars_decode(htmlspecialchars($_GET['x']))",
        '"prefix $x suffix"', '"{$x} ${x} {$obj->x}"', '`echo $x`',
        "(int) $x", "( $x )", "-$x + +$x", "$x ?? 'safe'", "$x . 'tail'",
        "fn () => $x", "(function () use ($x) { return $x; })()",
    ]
    statements = [
        "$x = $_GET['x']; echo EXPR;",
        "$x = $_GET['x']; system(EXPR);",
        "$x = $_GET['x']; if ($x) { $x = 'safe'; } echo EXPR;",
    ]
    for number, (expression, statement) in enumerate(itertools.product(expressions, statements)):
        (php / f'expression-{number:03}.php').write_text('<?php\n' + statement.replace('EXPR', expression))
    fragments = [
        "html <?= $_GET['x'] ?> html <?PHP echo $_POST['x']; ?>",
        "<?php // phpscan-ignore\necho $_GET['x'];\necho $_GET['x'];",
        "<?php echo $_GET['x']; /* phpscan-ignore */\necho $_GET['x'];",
        "<?php // comment ?> <?= $_GET['x'] ?>",
        "<?php /* unterminated\n echo $_GET['x'];",
        "<?php echo 'unterminated",
        '<?php echo "unterminated $x',
        '<?php echo "${unfinished',
        "<?php $x = $_GET['x']; echo <<<TXT\n$x\nTXT;",
        "<?php $x = $_GET['x']; echo <<<'TXT'\n$x\nTXT;",
        "<?php $x = $_GET['x']; echo <<<TXT\n  $x\n  TXT;",
        "<?php echo ($_GET['x']]; echo $_GET['x'];",
        "<?php function f(int $a, string $b) { return $a . $b; } echo f($_GET['x'], $_GET['y']);",
        "<?php function a($x) { return b($x); } function b($x) { return c($x); } function c($x) { return $x; } echo a($_GET['x']);",
        "<?php $a->x = $_GET['x']; $a->x = 'safe'; echo $a->x;",
        "<?php $a['x'] = $_GET['x']; $a['x'] = 'safe'; echo $a['x'];",
        "<?php $x = $_GET['x']; $x .= 'safe'; echo $x;",
        "<?php $x = $_GET['x']; $f = function () use ($x) { $x = 'safe'; return $x; }; echo $x;",
    ]
    for number, text in enumerate(fragments):
        (php / f'fragment-{number:03}.php').write_text(text)
    queries = [[f'--format={fmt}', str(php)] for fmt in ['text', 'github', 'sarif']]
    queries += [[], ['--help'], ['--version'], ['--unknown'], ['--unknown', '--other'],
                ['--format=xml', '--format=text', str(php)],
                ['--format=text', '--format=xml', str(php)],
                ['--format=github', '--format=sarif', str(php)],
                [str(root / 'missing')], [str(php), str(php)]]
    locks = ['{}', '{"packages":[]}', '{"packages":[],"packages":[]}',
             '{"packages":[],"packages-dev":[]}',
             '{"packages":[{"name":"laravel/framework","version":"12.67.0"}]}',
             '{"packages":[{"name":"symfony/http-foundation","version":"7.3.6"}]}',
             '{"packages":[{"name":"livewire/livewire","version":"3.6.3"}]}']
    locks += ['{"x":' + value + ',"packages":[]}' for value in
              ['0', '-0', '1.0', '1e+2', '01', '-', '1.', '1e', '1e-', 'true',
               '"\\uD834\\uDD1E"', '"\\uD834"', '"\\uDD1E"', '"\\x"', '[1,]', '{"a":1,"a":2}']]
    for number, lock in enumerate(locks):
        project = root / f'lock-{number:03}'
        project.mkdir()
        (project / 'composer.lock').write_text(lock)
        (project / 'app.php').write_text("<?php echo $_GET['x'];")
        queries.append(['--format=sarif', str(project)])
    resource = r'''<?php
namespace App;
use Illuminate\Http\Resources\JsonApi\JsonApiResource;
class Resource extends JsonApiResource {
  public function toRelationships() { return ['comments', 'author',]; }
}
'''
    route = r'''<?php
use Illuminate\Support\Facades\Route;
use App\Resource;
Route::get('/users', fn ($user) => new Resource($user));
Route::middleware('auth:api')->get('/account', fn () => 'ok');
'''
    variants = [resource,
                resource + 'class Resource {}',
                resource.replace("return ['comments', 'author',];", "return $dynamic;"),
                resource.replace('class Resource', '// phpscan-ignore\nclass Resource'),
                resource + 'use Other\\Late;',
                resource.replace('namespace App;', 'namespace App; namespace Other;'),
                resource.replace("return ['comments', 'author',];", "return ['comments', 'comments'];"),
                resource.replace('\n}', '\npublic function toRelationships() { return []; }\n}')]
    for number, source in enumerate(variants):
        project = root / f'laravel-{number}'
        for directory in ['app', 'routes', 'config']:
            (project / directory).mkdir(parents=True, exist_ok=True)
        (project / 'composer.lock').write_text(json.dumps({'packages': [
            {'name': 'laravel/framework', 'version': '12.67.0'}]}))
        (project / 'app/Resource.php').write_text(source)
        (project / 'routes/api.php').write_text(route)
        (project / 'config/auth.php').write_text("<?php return ['guards'=>['api'=>["
            "'driver'=>'token','provider'=>'users','hash'=>false]],"
            "'providers'=>['users'=>['driver'=>'eloquent','model'=>App\\User::class]]];")
        (project / 'config/database.php').write_text("<?php return ['default'=>'mysql'];")
        queries.append(['--format=sarif', str(project)])
    symfony = r'''<?php
namespace App;
use Illuminate\Http\Request;
function handle(TYPE $request) {
  if (str_starts_with($request->getPathInfo(), '/admin')) { abort_unless(auth()->check(), 403); }
}
'''
    for number, parameter in enumerate(['Request', 'string|Request', '?Request', 'Request&Other']):
        project = root / f'symfony-{number}'
        project.mkdir()
        (project / 'composer.lock').write_text(json.dumps({'packages': [
            {'name': 'symfony/http-foundation', 'version': '7.3.6'}]}))
        (project / 'app.php').write_text(symfony.replace('TYPE', parameter))
        queries.append(['--format=sarif', str(project)])
    return queries, len(list(root.rglob('*.php')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    args = parser.parse_args()
    binaries = [args.baseline.resolve(), args.candidate.resolve()]
    with tempfile.TemporaryDirectory(prefix='phpscan-states-') as temporary:
        root = Path(temporary)
        queries, files = corpus(root)
        for number, query in enumerate(queries):
            outputs = []
            for binary in binaries:
                result = subprocess.run([str(binary), *query], capture_output=True, timeout=120, cwd=root)
                outputs.append((result.returncode, result.stdout, result.stderr))
            if outputs[0] != outputs[1]:
                print(json.dumps({'query': number, 'args': query, 'baseline': [str(x) for x in outputs[0]],
                                  'candidate': [str(x) for x in outputs[1]]}, indent=2))
                return 1
    print(f'PASS: {len(queries)} CLI comparisons, {files} PHP transition fixtures; identical status, stdout, stderr.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
