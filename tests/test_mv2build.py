import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import mv2build as builder


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_linux_dev_uses_unstable_package_and_requested_name(self):
        packages = b'Package: google-chrome-unstable\nVersion: 159.0.8130.0-1\nArchitecture: amd64\nFilename: pool/dev.deb\nSHA256: abc\n\n'
        with patch.object(builder, 'metadata', return_value=gzip.compress(packages)):
            release = builder.resolve('chrome-linux-dev')
        self.assertEqual(release.filename, 'chrome-dev-159.0.8130.0.tar.zst')
        self.assertEqual(release.url, builder.GOOGLE_DEB + 'pool/dev.deb')

    def test_cft_names_do_not_collide_with_regular_chrome(self):
        data = {'channels': {'Stable': {'version': '156.0.8078.80', 'downloads': {'chrome': [
            {'platform': 'linux64', 'url': 'https://example/linux.zip'},
            {'platform': 'win64', 'url': 'https://example/windows.zip'}]}}}}
        with patch.object(builder, 'metadata', return_value=json.dumps(data).encode()):
            linux = builder.resolve('chrome-testing-linux-stable')
            windows = builder.resolve('chrome-testing-win64-stable')
        self.assertEqual(windows.filename, 'chrome-win64-156.0.8078.80-stable-testing.tar.zst')
        self.assertEqual(linux.filename, 'chrome-stable-156.0.8078.80-testing.tar.zst')

    def test_omaha_uses_full_x64_installer_and_https(self):
        data = b'''<response><app><updatecheck status="ok"><urls>
          <url codebase="http://dl.google.com/release/"/>
          <url codebase="https://dl.google.com/release/"/></urls>
          <manifest version="158.0.8127.2"><packages><package name="full.exe"
          hash_sha256="abcd"/></packages></manifest></updatecheck></app></response>'''
        with patch.object(builder, 'fetch', return_value=data) as fetch:
            release = builder.resolve('chrome-win64-beta')
        self.assertEqual(release.url, 'https://dl.google.com/release/full.exe')
        self.assertIn(b'ap="x64-beta"', fetch.call_args.args[1])
        self.assertEqual(release.checksum, 'abcd')

    def test_arch_compares_versions_not_dates_and_uses_matching_checksum(self):
        stable = dict(epoch=0, pkgver='156.0.8078.79', pkgrel='9', filename='stable.pkg.tar.zst', repo='extra')
        testing = dict(epoch=0, pkgver='157.0.8100.1', pkgrel='1', filename='testing.pkg.tar.zst', repo='extra-testing')
        database = io.BytesIO()
        desc = ('%FILENAME%\ntesting.pkg.tar.zst\n\n%SHA256SUM%\n' + 'a' * 64 + '\n').encode()
        with tarfile.open(fileobj=database, mode='w:gz') as tar:
            member = tarfile.TarInfo('chromium-157/desc')
            member.size = len(desc)
            tar.addfile(member, io.BytesIO(desc))
        def metadata(url):
            if url.endswith('.db'):
                return database.getvalue()
            return json.dumps(testing if '/extra-testing/' in url else stable).encode()
        with patch.object(builder, 'metadata', side_effect=metadata):
            release = builder.resolve('chromium-arch')
        self.assertIn('/extra-testing/', release.url)
        self.assertEqual(release.checksum, 'a' * 64)

    def test_snapshot_uses_exact_commit_and_unique_revision_name(self):
        import base64
        def metadata(url):
            if url.endswith('LAST_CHANGE'):
                return b'1234567'
            if url.endswith('REVISIONS'):
                return json.dumps({'got_revision': 'a' * 40}).encode()
            self.assertIn('/' + 'a' * 40 + '/', url)
            return base64.b64encode(b'MAJOR=159\nMINOR=0\nBUILD=8139\nPATCH=0\n')
        with patch.object(builder, 'metadata', side_effect=metadata):
            release = builder.resolve('chromium-snapshot-linux')
        self.assertEqual(release.filename, 'chromium-snapshot-159.0.8139.0-r1234567.tar.zst')

    def test_tar_rejects_traversal_and_symlink_escape(self):
        for name, link in [('../escape', ''), ('/absolute', ''), ('browser/link', '../../escape')]:
            with self.subTest(name=name):
                source = self.root / 'bad.tar'
                with tarfile.open(source, 'w') as archive:
                    member = tarfile.TarInfo(name)
                    if link:
                        member.type = tarfile.SYMTYPE
                        member.linkname = link
                    archive.addfile(member)
                with self.assertRaises((builder.BuildError, tarfile.FilterError)):
                    builder.extract_tar(source, self.root / 'extract')
        self.assertFalse((self.root / 'escape').exists())

    def test_zip_traversal_rejected_executable_permissions_preserved(self):
        source = self.root / 'browser.zip'
        with zipfile.ZipFile(source, 'w') as archive:
            member = zipfile.ZipInfo('chrome-linux64/chrome')
            member.external_attr = 0o100755 << 16
            archive.writestr(member, b'executable')
        builder.extract_zip(source, self.root / 'extract')
        self.assertEqual((self.root / 'extract/chrome-linux64/chrome').stat().st_mode & 0o777, 0o755)
        with zipfile.ZipFile(source, 'w') as archive:
            archive.writestr('../escape', 'bad')
        with self.assertRaises(builder.BuildError):
            builder.extract_zip(source, self.root / 'extract')

    def test_deb_excludes_absolute_system_links_and_preserves_sandbox_mode(self):
        source = self.root / 'data.tar.gz'
        with tarfile.open(source, 'w:gz') as archive:
            link = tarfile.TarInfo('./etc/cron.daily/google-chrome')
            link.type = tarfile.SYMTYPE
            link.linkname = '/opt/google/chrome/cron/google-chrome'
            archive.addfile(link)
            sandbox = tarfile.TarInfo('./opt/google/chrome/chrome-sandbox')
            sandbox.mode = 0o4755
            archive.addfile(sandbox)
        builder.extract_tar(source, self.root / 'extract', browser_only=True)
        self.assertFalse((self.root / 'extract/etc').exists())
        self.assertEqual((self.root / 'extract/opt/google/chrome/chrome-sandbox').stat().st_mode & 0o7777, 0o4755)

    def test_windows_extractor_forces_pe_envelope(self):
        source = self.root / 'installer.exe'
        destination = self.root / 'unpacked'
        destination.mkdir()
        (destination / 'chrome.dll').write_bytes(b'test')
        def run(argv, **kwargs):
            if argv[0] == '7z':
                self.assertIn('-tPE', argv)
                return b'Path = installer.exe\nPath = .rsrc/BN/CHROME.7Z\n'
            return b''
        with patch.object(builder, 'run', side_effect=run), patch.object(builder.subprocess, 'run') as extract:
            extract.return_value.returncode = 0
            builder.extract_installer(source, destination, self.root)
            self.assertIn('-tPE', extract.call_args.args[0])

    def test_deb_internal_absolute_links_remain_valid_after_moving_browser(self):
        for channel in ('beta', 'unstable', 'canary'):
            with self.subTest(channel=channel):
                browser = f'opt/google/chrome-{channel}'
                source = self.root / f'{channel}.tar'
                with tarfile.open(source, 'w') as archive:
                    # Match the alias before its target, as in real packages.
                    link = tarfile.TarInfo(f'./{browser}/google-chrome')
                    link.type = tarfile.SYMTYPE
                    link.linkname = f'/{browser}/google-chrome-{channel}'
                    archive.addfile(link)
                    target = tarfile.TarInfo(f'./{browser}/google-chrome-{channel}')
                    target.size = 7
                    archive.addfile(target, io.BytesIO(b'wrapper'))
                destination = self.root / channel
                builder.extract_tar(source, destination, browser_only=True)
                moved = self.root / f'portable-{channel}'
                (destination / browser).rename(moved)
                alias = moved / 'google-chrome'
                self.assertEqual(alias.readlink(), Path(f'google-chrome-{channel}'))
                self.assertEqual(alias.read_bytes(), b'wrapper')

    def test_deb_rejects_links_outside_browser_directory(self):
        for target in ('/etc/passwd', '/opt/google/chrome-beta-other/chrome',
                       '/opt/google/chrome-canary/chrome', '/opt/google/chrome-beta/../../../etc/passwd',
                       '../../../etc/passwd'):
            with self.subTest(target=target):
                source = self.root / 'link.tar'
                with tarfile.open(source, 'w') as archive:
                    link = tarfile.TarInfo('./opt/google/chrome-beta/google-chrome')
                    link.type = tarfile.SYMTYPE
                    link.linkname = target
                    archive.addfile(link)
                with self.assertRaises(builder.BuildError):
                    builder.extract_tar(source, self.root / 'extract', browser_only=True)

    @unittest.skipUnless(shutil.which('zstd') and shutil.which('tar') and shutil.which('bsdtar'), 'archive tools required')
    def test_arch_rebuild_updates_mtree_and_preserves_package_metadata(self):
        root = self.root / 'package'
        (root / 'usr/lib/chromium').mkdir(parents=True)
        binary = root / 'usr/lib/chromium/chromium'
        binary.write_bytes(b'patched browser')
        binary.chmod(0o755)
        (root / '.PKGINFO').write_text('pkgname = chromium\npkgver = 156.0.8078.79-1\n')
        (root / '.BUILDINFO').write_text('format = 2\n')
        (root / '.MTREE').write_bytes(b'old hashes')
        (root / 'usr/bin').mkdir()
        (root / 'usr/bin/chromium').symlink_to('../lib/chromium/chromium')
        builder.refresh_mtree(root)
        mtree = gzip.decompress((root / '.MTREE').read_bytes()).decode()
        self.assertIn(hashlib.sha256(binary.read_bytes()).hexdigest(), mtree)
        self.assertIn('uid=0', mtree)
        self.assertIn('gid=0', mtree)
        self.assertIn('.BUILDINFO', mtree)
        archive = self.root / 'chromium.pkg.tar.zst'
        builder.pack(root, archive, arch=True)
        unpacked = self.root / 'check.tar'
        builder.run(['zstd', '-d', '-q', archive, '-o', unpacked])
        with tarfile.open(unpacked) as tar:
            self.assertEqual(tar.extractfile('./.PKGINFO').read(), (root / '.PKGINFO').read_bytes())
            self.assertEqual(tar.getmember('./usr/lib/chromium/chromium').uid, 0)
            self.assertTrue(tar.getmember('./usr/bin/chromium').issym())

    def test_failed_patch_publishes_nothing_and_success_is_cached(self):
        output = self.root / 'builds'
        (output / 'logs').mkdir(parents=True)
        args = argparse.Namespace(output=output, force=False, work_dir=self.root, keep_work=False)
        release = builder.Release('chrome-testing-linux-stable', '156.0.1.0', 'https://example/build.zip', 'zip', 'chrome.tar.zst')
        def fetch(url, data=None, destination=None):
            with zipfile.ZipFile(destination, 'w') as archive:
                archive.writestr('chrome-linux64/chrome', b'original')
        def pack(root, destination, arch=False):
            destination.write_bytes((root / 'chrome').read_bytes())
        with patch.object(builder, 'fetch', side_effect=fetch), patch.object(builder, 'pack', side_effect=pack), patch.object(builder, 'patch', side_effect=builder.BuildError('unknown profile')):
            with self.assertRaises(builder.BuildError):
                builder.build(release, args)
        self.assertFalse((output / release.filename).exists())
        def apply(binary, logfile):
            binary.write_bytes(b'patched')
        with patch.object(builder, 'fetch', side_effect=fetch) as download, patch.object(builder, 'pack', side_effect=pack), patch.object(builder, 'patch', side_effect=apply):
            self.assertEqual(builder.build(release, args), 'built')
            self.assertEqual(builder.build(release, args), 'skipped')
            self.assertEqual(download.call_count, 1)
            (output / release.filename).write_bytes(b'corrupted')
            self.assertEqual(builder.build(release, args), 'built')
            self.assertEqual(download.call_count, 2)

    def test_batch_failure_does_not_stop_other_targets(self):
        argv = ['--dry-run', '--output', str(self.root), '--target', 'chrome-linux-stable', '--target', 'chrome-linux-beta']
        release = builder.Release('chrome-linux-beta', '1.0', 'https://example/build', 'deb', 'beta.tar.zst')
        with patch.object(builder, 'resolve', side_effect=[builder.BuildError('unavailable'), release]) as resolve:
            self.assertEqual(builder.main(argv), 1)
            self.assertEqual(resolve.call_count, 2)


if __name__ == '__main__':
    unittest.main()
