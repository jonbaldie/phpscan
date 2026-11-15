#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class FixtureLifecycleTests(unittest.TestCase):
    def run_fixtures(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tests/cve').mkdir(parents=True)
            (root / 'bin').mkdir()
            (root / 'tmp').mkdir()
            shutil.copyfile(ROOT / 'tests/cve.sh', root / 'tests/cve.sh')
            payload = b'<?php\n'
            checksum = hashlib.sha256(payload).hexdigest()
            first_sum = '0' * 64 if failure == 'checksum' else checksum
            (root / 'tests/cve/manifest.tsv').write_text(
                f'CVE-first\t1\tcontrol\t!XSS@*\t{first_sum}\thttps://example.invalid/{failure}.php\n'
                f'CVE-next\t2\tcontrol\t!XSS@*\t{checksum}\thttps://example.invalid/healthy.php\n'
            )
            self.executable(root / 'bin/curl', '''#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
if args[-1].endswith('/download.php'):
    raise SystemExit(22)
pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'<?php\\n')
''')
            self.executable(root / 'scanner', '''#!/usr/bin/env python3
import sys
if sys.argv[1].endswith('/scanner.php'):
    raise SystemExit(2)
if sys.argv[1].endswith('/expectation.php'):
    print(sys.argv[1] + ':1: [XSS] unexpected finding')
    raise SystemExit(1)
''')
            env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                       TMPDIR=str(root / 'tmp'))
            result = subprocess.run(['bash', 'tests/cve.sh', str(root / 'scanner')],
                                    cwd=root, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(list((root / 'tmp').iterdir()), [], result.stdout + result.stderr)
            self.assertIn('PASS CVE-next', result.stdout)
            return result

    def executable(self, path, text):
        path.write_text(text)
        path.chmod(0o755)

    def test_success(self):
        result = self.run_fixtures('healthy')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS CVE-first', result.stdout)

    def test_failure_stays_failed_and_later_fixture_runs(self):
        for failure, message in [('download', 'download failed'), ('checksum', 'sha256'),
                                 ('scanner', 'scanner exited 2'), ('expectation', 'expect !XSS@*')]:
            with self.subTest(failure=failure):
                result = self.run_fixtures(failure)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('FAIL CVE-first', result.stdout)
                self.assertIn(message, result.stdout)


if __name__ == '__main__':
    unittest.main()
