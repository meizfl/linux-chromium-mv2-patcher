import argparse
import gzip
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

import mv2build as b
import mv2universal as u


class UniversalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = {'version': '156.0.8078.79-1~deb12u1', 'upstream': '156.0.8078.79',
                        'revision': '1.1.deb12u1', 'packages': []}

    def test_debian_version_ordering(self):
        for older, newer in [('1.0~rc1', '1.0'), ('1.0-1~deb12u1', '1.0-1~deb12u2'),
                             ('156.0.9.0-10', '156.0.10.0-1'), ('1.0-9', '1.0-10'),
                             ('9.0', '1:1.0'), ('1.0-1', '1.0-1+b1')]:
            with self.subTest(older=older):
                self.assertLess(u.version_compare(older, newer), 0)
                self.assertGreater(u.version_compare(newer, older), 0)
        self.assertEqual(u.version_compare('1.01-01', '1.1-1'), 0)

    def test_resolver_uses_latest_bookworm_and_matching_companions(self):
        def record(name, version, depends=''):
            return f'Package: {name}\nVersion: {version}\nArchitecture: amd64\nFilename: pool/{name}.deb\nSHA256: ' + 'a' * 64 + f'\nDepends: {depends}\n\n'
        base = ''.join(record(n, '150.0-1') for n in ('chromium', 'chromium-common', 'chromium-sandbox'))
        security = ''.join(record(n, '156.0-1~deb12u1', 'libexample1 (>= 1), libc6 (>= 2.36)')
                           for n in ('chromium', 'chromium-common', 'chromium-sandbox'))
        security += record('libexample1', '1.0-1', 'libhelper1 (= 2.0), libgbm1')
        security += record('libhelper1', '2.0') + record('libc6', '2.36') + record('libgbm1', '22')
        with patch.object(b, 'metadata', side_effect=lambda url: lzma.compress((security if 'security' in url else base).encode())):
            release = u.resolve()
        packages = {p['name']: p for p in release['packages']}
        self.assertEqual(release['version'], '156.0-1~deb12u1')
        self.assertEqual(set(packages), {'chromium', 'chromium-common', 'chromium-sandbox', 'libexample1', 'libhelper1'})
        self.assertTrue(all(p['suite'] == 'bookworm-security' for p in packages.values()))

    def test_native_versions_include_debian_rebuild_revision(self):
        names = u.filenames(self.release)
        self.assertEqual(len(set(names)), 3)
        self.assertIn('1.1.deb12u1', names[0])
        newer = dict(self.release, revision='1.1.deb12u2')
        self.assertNotEqual(u.filenames(newer), names)

    def test_flag_alone_selects_only_universal_without_changing_default_targets(self):
        with patch.object(u, 'resolve', return_value=self.release), patch.object(b, 'resolve') as normal:
            self.assertEqual(b.main(['--chromium-universal', '--dry-run', '--output', str(self.root)]), 0)
            normal.assert_not_called()
        self.assertNotIn('chromium-universal', b.DEFAULT_TARGETS)

    def test_launcher_prefers_host_libraries_and_preserves_browser_arguments(self):
        browser = self.root / 'browser with spaces'
        browser.mkdir()
        u.write_file(browser / 'chromium', '#!/bin/sh\nprintf "%s\\n" "$LD_LIBRARY_PATH" "$CHROME_DEVEL_SANDBOX" "$@"\n', 0o755)
        launcher = self.root / 'launcher'
        u.write_file(launcher, u.launcher_script(browser), 0o755)
        for inherited in ('', '/explicit/override'):
            with self.subTest(inherited=inherited):
                environment = dict(os.environ, LD_LIBRARY_PATH=inherited, XDG_CONFIG_HOME=str(self.root / 'config'))
                result = subprocess.run([launcher, '--ozone-platform=wayland', 'https://example.org/a b'],
                                        env=environment, check=True, capture_output=True, text=True)
                lines = result.stdout.splitlines()
                search = lines[0].split(':')
                self.assertEqual(search[-1], str(browser / 'lib'))
                self.assertNotIn('', search)
                self.assertLess(search.index('/usr/lib'), search.index(str(browser / 'lib')))
                if inherited:
                    self.assertEqual(search[0], inherited)
                self.assertEqual(lines[1], str(browser / 'chrome-sandbox'))
                self.assertEqual(lines[2:], ['--user-data-dir=' + str(self.root / 'config/chromium-universal'),
                                            '--class=chromium-universal', '--ozone-platform=wayland', 'https://example.org/a b'])
                self.assertNotIn('--no-sandbox', lines)
                self.assertNotIn('--disable-gpu', lines)

    def test_desktop_identity_matches_launcher_even_with_inherited_system_identity(self):
        browser = self.root / 'browser'
        browser.mkdir()
        u.write_file(browser / 'chromium', '#!/bin/sh\nprintf "%s\\n" "$CHROME_DESKTOP" "$@"\n', 0o755)
        launcher = self.root / 'launcher'
        u.write_file(launcher, u.launcher_script(browser), 0o755)
        desktop = self.root / 'chromium-universal.desktop'
        u.write_file(desktop, u.desktop_entry())
        result = subprocess.run([launcher], env=dict(os.environ, CHROME_DESKTOP='chromium.desktop'),
                                check=True, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], desktop.name)
        self.assertIn('--class=' + desktop.stem, lines)
        self.assertIn('StartupWMClass=' + desktop.stem + '\n', desktop.read_text())
        self.assertIn('Icon=chromium-universal\n', desktop.read_text())
        if shutil.which('desktop-file-validate'):
            b.run(['desktop-file-validate', desktop])

    def test_failed_format_does_not_publish_partial_package_set(self):
        output = self.root / 'builds'
        (output / 'logs').mkdir(parents=True)
        args = argparse.Namespace(output=output, force=False, work_dir=self.root, keep_work=False)
        def payload(release, work):
            root = work / 'payload'
            root.mkdir()
            binary = root / 'chromium'
            binary.write_bytes(b'verified browser')
            return root, binary
        def arch(root, destination, release, work):
            destination.write_bytes(b'first format')
        with patch.object(u, 'prepare_payload', side_effect=payload), patch.object(b, 'patch'), \
             patch.object(u, 'make_arch', side_effect=arch), patch.object(u, 'make_deb', side_effect=b.BuildError('pack failed')):
            with self.assertRaises(b.BuildError):
                u.build(self.release, args)
        self.assertFalse(any((output / name).exists() for name in u.filenames(self.release)))
        self.assertFalse((output / 'chromium-universal.json').exists())
        self.assertFalse(list(output.glob('.chromium-universal-*')))

    def test_launcher_exports_oauth_defaults_and_preserves_explicit_overrides(self):
        browser = self.root / 'browser'
        browser.mkdir()
        u.write_file(browser / 'chromium', '#!/bin/sh\nprintf "%s\\n" "${GOOGLE_DEFAULT_CLIENT_ID+set}" "$GOOGLE_DEFAULT_CLIENT_ID" "${GOOGLE_DEFAULT_CLIENT_SECRET+set}" "$GOOGLE_DEFAULT_CLIENT_SECRET"\n', 0o755)
        launcher = self.root / 'launcher'
        u.write_file(launcher, u.launcher_script(browser), 0o755)
        cases = [({}, ['77185425430.apps.googleusercontent.com', 'OTJgUOQcT7lO7GsGZq2G4IlT']),
                 ({'GOOGLE_DEFAULT_CLIENT_ID': 'custom-id', 'GOOGLE_DEFAULT_CLIENT_SECRET': 'custom-secret'},
                  ['custom-id', 'custom-secret']),
                 ({'GOOGLE_DEFAULT_CLIENT_ID': '', 'GOOGLE_DEFAULT_CLIENT_SECRET': ''}, ['', ''])]
        for overrides, expected in cases:
            with self.subTest(mode='default' if not overrides else 'override'):
                environment = {k: v for k, v in os.environ.items()
                               if k not in ('GOOGLE_DEFAULT_CLIENT_ID', 'GOOGLE_DEFAULT_CLIENT_SECRET')}
                environment.update(overrides)
                result = subprocess.run([launcher], env=environment, check=True, capture_output=True, text=True)
                self.assertEqual(result.stdout.splitlines(), ['set', expected[0], 'set', expected[1]])

    @unittest.skipUnless(all(shutil.which(n) for n in ('rpmbuild', 'rpm', 'ar', 'tar', 'zstd', 'bsdtar')), 'native packaging tools required')
    def test_three_native_formats_preserve_binary_and_sandbox_permissions(self):
        root = self.root / 'payload'
        browser = root / 'opt/chromium-universal'
        browser.mkdir(parents=True)
        (browser / 'chromium').write_bytes(b'verified binary bytes')
        (browser / 'chromium').chmod(0o755)
        (browser / 'chrome-sandbox').write_bytes(b'sandbox')
        (browser / 'chrome-sandbox').chmod(0o4755)
        for name in ('usr/bin/chromium-universal', 'usr/share/applications/chromium-universal.desktop',
                     'usr/share/licenses/chromium-universal/copyright',
                     'usr/share/doc/chromium-universal/sources.json',
                     'usr/share/icons/hicolor/128x128/apps/chromium-universal.png'):
            u.write_file(root / name, 'test\n')
        for packer, filename in zip((u.make_arch, u.make_deb, u.make_rpm), u.filenames(self.release)):
            with self.subTest(filename=filename):
                work = self.root / filename.replace('.', '_')
                work.mkdir()
                output = self.root / filename
                packer(root, output, self.release, work)
                extracted = work / 'check'
                extracted.mkdir()
                if output.suffix == '.deb':
                    b.extract_deb(output, extracted, work, browser_only=False)
                else:
                    b.run(['bsdtar', '-xpf', output, '-C', extracted])
                result = extracted / 'opt/chromium-universal/chromium'
                self.assertEqual(result.read_bytes(), (browser / 'chromium').read_bytes())
                # Unprivileged libarchive extraction may deliberately clear
                # setuid. Check the installable package metadata itself.
                if output.suffix == '.rpm':
                    modes = b.run(['rpm', '-qp', '--qf', '[%{FILENAMES}\t%{FILEMODES}\n]', output]).decode()
                    entries = dict(line.split('\t') for line in modes.splitlines())
                    self.assertEqual(int(entries['/opt/chromium-universal/chrome-sandbox']) & 0o7777, 0o4755)
                elif output.suffix == '.zst':
                    unpacked = work / 'archive.tar'
                    b.run(['zstd', '-d', '-q', output, '-o', unpacked])
                    with tarfile.open(unpacked) as archive:
                        self.assertEqual(archive.getmember('opt/chromium-universal/chrome-sandbox').mode, 0o4755)
                else:
                    sandbox = extracted / 'opt/chromium-universal/chrome-sandbox'
                    self.assertEqual(sandbox.stat().st_mode & 0o7777, 0o4755)
                self.assertFalse((extracted / '.PKGINFO').is_file() and output.suffix != '.zst')


if __name__ == '__main__':
    unittest.main()
