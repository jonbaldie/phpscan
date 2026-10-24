#!/usr/bin/env python3
import hashlib
import io
import os
import pathlib
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest

BINARY = pathlib.Path(sys.argv.pop(1)).resolve()
INSTALLER = pathlib.Path(__file__).resolve().parents[1] / 'install.sh'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.transport = self.root / 'transport'
        self.transport.mkdir()
        self.dest = self.root / 'bin with spaces'
        self.dest.mkdir()
        self.target = self.dest / 'phpscan'
        self.target.write_text('existing installation\n')
        os_name = 'darwin' if platform.system() == 'Darwin' else 'linux'
        arch = 'arm64' if platform.machine() in ('arm64', 'aarch64') else 'x86_64'
        self.asset = f'phpscan-{os_name}-{arch}.tar.gz'
        self.archive = self.transport / self.asset
        with tarfile.open(self.archive, 'w:gz') as archive:
            archive.add(BINARY, arcname='phpscan')
        self.manifest = self.transport / 'SHA256SUMS'
        self.write_manifest()
        tools = self.root / 'tools'
        tools.mkdir()
        curl = tools / 'curl'
        curl.write_text(f'''#!{sys.executable}
import os, pathlib, shutil, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://'))
base = 'https://github.com/jonbaldie/phpscan/releases/'
assert url.startswith(base), url
suffix = url[len(base):]
assert suffix.startswith(('download/v0.1.0/', 'latest/download/')), suffix
assert '--proto' in args and '=https' in args
name = url.rsplit('/', 1)[-1]
shutil.copyfile(pathlib.Path(os.environ['TEST_TRANSPORT']) / name, args[args.index('-o') + 1])
''')
        curl.chmod(0o755)
        self.env = dict(os.environ, PATH=f'{tools}:{os.environ["PATH"]}',
                        PHPSCAN_INSTALL_DIR=str(self.dest), TEST_TRANSPORT=str(self.transport))
        self.tools = tools

    def write_manifest(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.manifest.write_text(f'{digest}  {self.asset}\n')

    def install(self, *args):
        return subprocess.run(['sh', str(INSTALLER), *args], env=self.env,
                              capture_output=True, text=True, timeout=60)

    def assert_preserved(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.target.read_text(), 'existing installation\n')
        self.assertEqual(list(self.dest.glob('.phpscan.*')), [])

    def test_pinned_install_and_actual_scan(self):
        result = self.install('v0.1.0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.access(self.target, os.X_OK))
        version = subprocess.run([self.target, '--version'], capture_output=True, text=True, timeout=30)
        self.assertEqual(version.returncode, 0)
        self.assertEqual(version.stdout, 'phpscan 0.1.0\n')
        php = self.root / 'unsafe.php'
        php.write_text("<?php echo $_GET['x'];")
        scan = subprocess.run([self.target, php], capture_output=True, text=True, timeout=30)
        self.assertEqual(scan.returncode, 1)
        self.assertIn(':1: [PHP-XSS]', scan.stdout)
        again = self.install('v0.1.0')
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(hashlib.sha256(self.target.read_bytes()).digest(), hashlib.sha256(BINARY.read_bytes()).digest())

    def test_latest_install(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), BINARY.read_bytes())

    def test_corruption_preserves_existing_binary(self):
        with self.archive.open('ab') as archive:
            archive.write(b'corrupt')
        result = self.install('v0.1.0')
        self.assert_preserved(result)
        self.assertIn('Checksum mismatch', result.stderr)

    def test_missing_and_duplicate_checksums(self):
        valid = self.manifest.read_text()
        for contents in ['', valid + valid]:
            with self.subTest(contents=contents):
                self.manifest.write_text(contents)
                self.assert_preserved(self.install('v0.1.0'))

    def test_download_failure(self):
        self.archive.unlink()
        self.assert_preserved(self.install('v0.1.0'))

    def test_invalid_version(self):
        for version in ['../main', '--unknown', '0.1.0']:
            with self.subTest(version=version):
                self.assert_preserved(self.install(version))

    def test_unsupported_platform(self):
        uname = self.tools / 'uname'
        uname.write_text('#!/bin/sh\nprintf "FreeBSD\\n"\n')
        uname.chmod(0o755)
        result = self.install('v0.1.0')
        self.assert_preserved(result)
        self.assertIn('Supported operating systems', result.stderr)

    def test_missing_binary_in_archive(self):
        with tarfile.open(self.archive, 'w:gz') as archive:
            item = tarfile.TarInfo('not-phpscan')
            item.size = 1
            archive.addfile(item, io.BytesIO(b'x'))
        self.write_manifest()
        self.assert_preserved(self.install('v0.1.0'))

    def test_wrong_binary_version(self):
        other = self.root / 'other'
        other.write_text('#!/bin/sh\nprintf "phpscan 99.0.0\\n"\n')
        other.chmod(0o755)
        with tarfile.open(self.archive, 'w:gz') as archive:
            archive.add(other, arcname='phpscan')
        self.write_manifest()
        result = self.install('v0.1.0')
        self.assert_preserved(result)
        self.assertIn('does not match', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
