import argparse
import json
import lzma
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import mv2build as b
import mv2glibc as g
import mv2universal as u


class PrivateRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = [dict(name=n, version='12.2-1' if n != 'libc6' else '2.36-1',
                             url='https://example/' + n, sha256='a' * 64, suite='bookworm') for n in g.CORE_NAMES]
        self.release = dict(name=g.NAME, version='156.0.8078.79-1~deb12u1', upstream='156.0.8078.79',
                            revision='4.1.deb12u1', packages=[], runtime=self.runtime)

    def test_flag_selects_only_private_runtime_target(self):
        for options in (['--chromium-universal-glibc'], ['--target', g.NAME]):
            with self.subTest(options=options):
                with patch.object(g, 'resolve', return_value=self.release), patch.object(u, 'resolve') as regular, patch.object(b, 'resolve') as others:
                    self.assertEqual(b.main([*options, '--dry-run', '--output', str(self.root)]), 0)
                    regular.assert_not_called()
                    others.assert_not_called()
        self.assertNotIn(g.NAME, b.DEFAULT_TARGETS)

    def test_default_run_never_resolves_private_runtime(self):
        release = b.Release('chrome-linux-stable', '1.0', 'https://example/chrome', 'deb', 'chrome.tar.zst')
        with patch.object(b, 'DEFAULT_TARGETS', ('chrome-linux-stable',)), patch.object(b, 'resolve', return_value=release), patch.object(g, 'resolve') as private:
            self.assertEqual(b.main(['--dry-run', '--output', str(self.root)]), 0)
            private.assert_not_called()

    def test_explicit_flags_can_build_both_independent_variants(self):
        regular_release = {k:v for k,v in self.release.items() if k not in ('name', 'runtime')}
        with patch.object(g, 'resolve', return_value=self.release) as private, patch.object(u, 'resolve', return_value=regular_release) as regular:
            self.assertEqual(b.main(['--chromium-universal', '--chromium-universal-glibc', '--dry-run', '--output', str(self.root)]), 0)
            self.assertEqual(private.call_count, 1)
            self.assertEqual(regular.call_count, 1)
        self.assertTrue(set(u.filenames(self.release)).isdisjoint(u.filenames(regular_release)))

    def test_resolver_uses_only_debian_runtime_and_versions_updates(self):
        regular_release = {k:v for k,v in self.release.items() if k not in ('name', 'runtime')}
        mesa = dict(name='libegl-mesa0', version='22.3.6-1', url='https://example/mesa', sha256='b' * 64, suite='bookworm')
        regular_release['packages'] = [*self.runtime, mesa]
        with patch.object(u, 'resolve', return_value=dict(regular_release)) as resolver:
            release = g.resolve()
        resolver.assert_called_once_with(bundled_host_packages=g.RUNTIME_ROOTS, bundle_hardware=True, extra_repos=g.BACKPORT_REPOS)
        self.assertEqual(release['runtime'], self.runtime)
        self.assertTrue(release['bundled_mesa'])
        self.assertEqual(release['name'], g.NAME)
        self.assertTrue(release['revision'].startswith('5.'))
        self.assertIn('.glibc2.36.1.gcc12.2.1.mesa22.3.6.1', release['revision'])
        self.assertNotIn('desktop_runtime', release)
        newer = dict(regular_release, packages=[dict(self.runtime[0], version='2.36-2'), *self.runtime[1:], mesa])
        with patch.object(u, 'resolve', return_value=newer):
            self.assertNotEqual(u.filenames(g.resolve()), u.filenames(release))
        mismatched = [*self.runtime[:2], dict(self.runtime[2], version='13.0-1'), mesa]
        with patch.object(u, 'resolve', return_value=dict(regular_release, packages=mismatched)):
            with self.assertRaisesRegex(b.BuildError, 'same GCC build'):
                g.resolve()

    def test_graphics_closure_is_private_only_in_opt_in_variant(self):
        dependencies = {'chromium': 'libgl1, libudev1, libgbm1',
                        'libgl1': 'libglx0, libglvnd0', 'libegl1': 'libglvnd0',
                        'libglx0': 'libx11-6', 'libudev1': 'libcap2, libc6',
                        'libcap2': 'libc6', 'libgbm1': 'libdrm2'}
        names = {'chromium', 'chromium-common', 'chromium-sandbox', 'libc6',
                 'libgbm1', 'libdrm2', 'libcap2', 'libx11-6', *g.BUNDLED_GRAPHICS}
        index = ''.join(f'Package: {name}\nVersion: 1.0-1\nArchitecture: amd64\n'
                        f'Filename: pool/{name}.deb\nSHA256: ' + 'a' * 64 +
                        f'\nDepends: {dependencies.get(name, "")}\n\n' for name in names)
        with patch.object(b, 'metadata', return_value=lzma.compress(index.encode())):
            regular = {p['name'] for p in u.resolve()['packages']}
            private = {p['name'] for p in u.resolve(bundled_host_packages=g.BUNDLED_GRAPHICS)['packages']}
        self.assertTrue(set(g.BUNDLED_GRAPHICS).isdisjoint(regular))
        self.assertTrue(set(g.BUNDLED_GRAPHICS) <= private)
        self.assertTrue({'libcap2', 'libx11-6'} <= private)
        self.assertTrue({'libc6', 'libgbm1', 'libdrm2'}.isdisjoint(private))

    def test_debian_payload_separates_core_gconv_and_dri_aliases(self):
        archive = self.root / 'source.deb'
        archive.write_bytes(b'test archive')
        names = ('chromium', 'libc6', 'mesa-libgallium', 'libgl1-mesa-dri')
        packages = [dict(name=name, version='1', url='https://example/' + name,
                         sha256=b.sha256(archive), suite='bookworm') for name in names]
        release = dict(self.release, packages=packages, runtime=[packages[1]])
        def extract(source, destination, work, **kwargs):
            name = work.name
            lib = destination / 'usr/lib/x86_64-linux-gnu'
            lib.mkdir(parents=True)
            if name == 'chromium':
                browser = destination / 'usr/lib/chromium'
                browser.mkdir()
                for file in ('chromium', 'chrome-sandbox', 'resources.pak'):
                    (browser / file).write_bytes(b'browser')
            elif name == 'libc6':
                for file in ('libc.so.6', 'ld-linux-x86-64.so.2'):
                    (lib / file).write_bytes(b'core')
                (lib / 'gconv').mkdir()
                (lib / 'gconv/UTF-8.so').write_bytes(b'module')
                (lib / 'gconv/gconv-modules').write_text('module configuration')
            elif name == 'mesa-libgallium':
                (lib / 'libgallium.so').write_bytes(b'gallium')
            else:
                (lib / 'dri').mkdir()
                (lib / 'dri/crocus_dri.so').write_bytes(b'megadriver')
                os.link(lib / 'dri/crocus_dri.so', lib / 'dri/i915_dri.so')
                (lib / 'dri/radeonsi_dri.so').symlink_to('../libgallium.so')
        work = self.root / 'build'
        work.mkdir()
        with patch.object(b, 'fetch', side_effect=lambda url, destination: shutil.copy2(archive, destination)), \
             patch.object(b, 'extract_deb', side_effect=extract), \
             patch.object(u, 'copy_library', side_effect=lambda source, destination: shutil.copy2(source, destination / source.name)):
            _, binary = u.prepare_payload(release, work)
        home = binary.parent
        self.assertTrue((home / 'runtime/libc.so.6').is_file())
        self.assertFalse((home / 'lib/libc.so.6').exists())
        self.assertEqual((home / 'runtime/gconv/gconv-modules').read_text(), 'module configuration')
        self.assertTrue((home / 'runtime/gconv/UTF-8.so').is_file())
        self.assertFalse((home / 'runtime/UTF-8.so').exists())
        self.assertEqual((home / 'lib/dri/i915_dri.so').readlink(), Path('crocus_dri.so'))
        self.assertEqual((home / 'lib/dri/radeonsi_dri.so').readlink(), Path('../libgallium.so'))
        self.assertEqual((home / 'lib/dri/radeonsi_dri.so').read_bytes(), b'gallium')

    def test_launcher_uses_own_identity_without_leaking_private_loader_path(self):
        home = self.root / 'private browser'
        home.mkdir()
        u.write_file(home / 'chromium', '#!/bin/sh\nprintf "%s\\n" "${LD_LIBRARY_PATH-unset}" "$CHROME_DESKTOP" "$CHROME_WRAPPER" "$CHROME_DEVEL_SANDBOX" "$@"\n', 0o755)
        launcher = self.root / 'launcher'
        u.write_file(launcher, u.launcher_script(home, g.NAME, True), 0o755)
        result = subprocess.run([launcher, '--ozone-platform=wayland'],
                                env=dict(os.environ, LD_LIBRARY_PATH='/old/private/lib'),
                                capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[:4], ['unset', g.NAME + '.desktop', '/usr/bin/' + g.NAME, str(home / 'chrome-sandbox')])
        self.assertTrue(lines[4].endswith('/' + g.NAME))
        self.assertEqual(lines[5:], ['--class=' + g.NAME, '--ozone-platform=wayland'])
        self.assertIn('StartupWMClass=' + g.NAME + '\n', u.desktop_entry(g.NAME))
        self.assertNotIn('--no-sandbox', result.stdout)

    def test_elf_interpreter_detection(self):
        elf = bytearray(120)
        elf[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', elf, 32, 64)
        struct.pack_into('<HH', elf, 54, 56, 1)
        struct.pack_into('<I', elf, 64, 3)
        path = self.root / 'elf'
        path.write_bytes(elf)
        self.assertTrue(g.has_interpreter(path))
        struct.pack_into('<I', elf, 64, 1)
        path.write_bytes(elf)
        self.assertFalse(g.has_interpreter(path))
        path.write_bytes(b'#!/bin/sh\n')
        self.assertFalse(g.has_interpreter(path))

    @unittest.skipUnless(shutil.which('patchelf') and shutil.which('cc'), 'ELF tools required')
    def test_old_host_nss_cannot_override_private_symbol_versions(self):
        home = self.root / 'browser'
        libraries = home / 'lib'
        system = self.root / 'old-system'
        libraries.mkdir(parents=True)
        system.mkdir()
        for name in g.COMPAT_FILES:
            (libraries / name).write_bytes(b'fixture')
        source = self.root / 'nss.c'
        source.write_text('int nss_fixture(void) { return 0; }\n')
        for directory, version in ((system, 'NSS_3.17'), (libraries, 'NSS_3.30')):
            script = directory / 'versions.map'
            script.write_text(version + ' { global: nss_fixture; local: *; };\n')
            b.run(['cc', '-shared', '-fPIC', source, '-Wl,-soname,libnss3.so',
                   '-Wl,--version-script=' + str(script), '-o', directory / 'libnss3.so'])
        main = self.root / 'main.c'
        main.write_text('extern int nss_fixture(void); int main(void) { return nss_fixture(); }\n')
        binary = home / 'client'
        b.run(['cc', main, '-L' + str(libraries), '-lnss3', '-o', binary])
        # Reproduce the reported failure with the old host library ahead of lib/.
        b.run(['patchelf', '--force-rpath', '--set-rpath', f'{system}:{libraries}', binary])
        failed = subprocess.run([binary], capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('NSS_3.30', failed.stderr)
        dependencies = g.library_dependencies
        with patch.object(g, 'library_dependencies', side_effect=lambda p: dependencies(p) if p.name == 'libnss3.so' else []):
            g.prepare_compat(home)
        with patch.object(g, 'SYSTEM_DIRS', (str(system),)):
            _, rpath = g.runtime_paths()
        # runtime_paths normally uses /opt; transplant that exact path order.
        rpath = rpath.replace('/opt/' + g.NAME, str(home))
        self.assertLess(rpath.index(str(home / 'compat')), rpath.index(str(system)))
        b.run(['patchelf', '--force-rpath', '--set-rpath', rpath, binary])
        b.run([binary])
        self.assertEqual((home / 'compat/libz.so.1').readlink(), Path('../lib/libz.so.1'))
        (libraries / 'libdbus-1.so.3').unlink()
        with self.assertRaisesRegex(b.BuildError, 'libdbus-1.so.3'):
            g.prepare_compat(home)

    @unittest.skipUnless(shutil.which('patchelf') and shutil.which('cc'), 'ELF tools required')
    def test_private_interpreter_rpath_and_postrewrite_validation(self):
        root = self.root / 'payload'
        home = root / 'opt' / g.NAME
        (home / 'runtime').mkdir(parents=True)
        (home / 'lib').mkdir()
        for name in g.COMPAT_FILES:
            (home / 'lib' / name).write_bytes(b'fixture')
        for name in g.CORE_FILES:
            (home / 'runtime' / name).write_bytes(b'core stays unchanged')
        source = self.root / 'main.c'
        source.write_text('int main(void) { return 0; }\n')
        binary = home / 'chromium'
        b.run(['cc', source, '-o', binary])
        shutil.copy2(binary, home / 'chrome-sandbox')
        (home / 'chrome-sandbox').chmod(0o4755)
        before = {n:b.sha256(home / 'runtime' / n) for n in g.CORE_FILES}
        with patch.object(g, 'library_dependencies', return_value=[]), patch('mv2ctl.analyze', return_value=([], 'patched', None)) as analyze:
            g.finalize_payload(root, binary, self.release)
            analyze.assert_called_once_with(binary, verbose=False, with_discovery=False)
        interpreter, rpath = g.runtime_paths()
        for path in (binary, home / 'chrome-sandbox'):
            self.assertEqual(b.run(['patchelf', '--print-interpreter', path]).decode().strip(), interpreter)
            self.assertEqual(b.run(['patchelf', '--print-rpath', path]).decode().strip(), rpath)
        self.assertEqual((home / 'chrome-sandbox').stat().st_mode & 0o7777, 0o4755)
        self.assertEqual(before, {n:b.sha256(home / 'runtime' / n) for n in g.CORE_FILES})
        with patch.object(g, 'library_dependencies', return_value=[]), patch('mv2ctl.analyze', return_value=(None, 'fail', None)):
            with self.assertRaisesRegex(b.BuildError, 'MV2 verification failed'):
                g.finalize_payload(root, binary, self.release)
        with self.assertRaises(b.BuildError):
            g.finalize_payload(root, binary, {'version':'1'})

    @unittest.skipUnless(shutil.which('patchelf') and shutil.which('cc'), 'ELF tools required')
    def test_compat_closure_prevents_old_transitive_gpg_error(self):
        home = self.root / 'browser'
        libraries = home / 'lib'
        system = self.root / 'old-system'
        libraries.mkdir(parents=True)
        system.mkdir()
        source = self.root / 'library.c'
        source.write_text('int fixture(void) { return 0; }\n')
        empty = self.root / 'empty.so'
        b.run(['cc', '-shared', '-fPIC', source, '-o', empty])
        for name in g.COMPAT_FILES:
            shutil.copy2(empty, libraries / name)
        for directory, symbol in ((system, 'old_function'), (libraries, 'gpgrt_lock_lock')):
            source.write_text(f'int {symbol}(void) {{ return 0; }}\n')
            script = directory / 'versions.map'
            script.write_text('GPG_ERROR_1.0 { global: ' + symbol + '; local: *; };\n')
            b.run(['cc', '-shared', '-fPIC', source, '-Wl,-soname,libgpg-error.so.0',
                   '-Wl,--version-script=' + str(script), '-o', directory / 'libgpg-error.so.0'])
        source.write_text('extern int gpgrt_lock_lock(void); int crypt_fixture(void) { return gpgrt_lock_lock(); }\n')
        b.run(['cc', '-shared', '-fPIC', source, '-L' + str(libraries), '-l:libgpg-error.so.0',
               '-Wl,-soname,libgcrypt.so.20', '-o', libraries / 'libgcrypt.so.20'])
        source.write_text('extern int crypt_fixture(void); int bus_fixture(void) { return crypt_fixture(); }\n')
        b.run(['cc', '-shared', '-fPIC', source, '-L' + str(libraries), '-l:libgcrypt.so.20',
               '-Wl,-soname,libdbus-1.so.3', '-o', libraries / 'libdbus-1.so.3'])
        main = self.root / 'main.c'
        main.write_text('extern int bus_fixture(void); int main(void) { return bus_fixture(); }\n')
        binary = home / 'client'
        b.run(['cc', main, '-L' + str(libraries), '-l:libdbus-1.so.3',
               '-Wl,-rpath-link,' + str(libraries), '-o', binary])
        # Old policy pinned the direct roots only; gpg-error was still intercepted.
        compat = home / 'compat'
        compat.mkdir()
        for name in g.COMPAT_FILES:
            (compat / name).symlink_to(Path('../lib') / name)
        rpath = f'{home}/runtime:{compat}:{system}:{libraries}:{home}'
        b.run(['patchelf', '--force-rpath', '--set-rpath', rpath, binary])
        failed = subprocess.run([binary], env=dict(os.environ, LD_BIND_NOW='1'), capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('gpgrt_lock_lock', failed.stderr)
        selected = g.prepare_compat(home)
        self.assertIn('libgcrypt.so.20', selected)
        self.assertIn('libgpg-error.so.0', selected)
        b.run([binary])
        self.assertEqual(len(selected), len(set(selected)))

    @unittest.skipUnless(shutil.which('patchelf') and shutil.which('cc'), 'ELF tools required')
    def test_bundled_harfbuzz_cannot_load_old_host_freetype(self):
        home = self.root / 'browser'
        libraries = home / 'lib'
        system = self.root / 'old-system'
        libraries.mkdir(parents=True)
        system.mkdir()
        source = self.root / 'library.c'
        source.write_text('int fixture(void) { return 0; }\n')
        empty = self.root / 'empty.so'
        b.run(['cc', '-shared', '-fPIC', source, '-o', empty])
        for name in g.COMPAT_FILES:
            shutil.copy2(empty, libraries / name)
        for directory, symbol in ((system, 'old_function'), (libraries, 'FT_Get_Transform')):
            source.write_text(f'int {symbol}(void) {{ return 0; }}\n')
            b.run(['cc', '-shared', '-fPIC', source, '-Wl,-soname,libfreetype.so.6',
                   '-o', directory / 'libfreetype.so.6'])
        source.write_text('extern int FT_Get_Transform(void); int hb_fixture(void) { return FT_Get_Transform(); }\n')
        b.run(['cc', '-shared', '-fPIC', source, '-L' + str(libraries), '-l:libfreetype.so.6',
               '-Wl,-soname,libharfbuzz.so.0', '-o', libraries / 'libharfbuzz.so.0'])
        main = self.root / 'main.c'
        main.write_text('extern int hb_fixture(void); int main(void) { return hb_fixture(); }\n')
        binary = home / 'client'
        b.run(['cc', main, '-L' + str(libraries), '-l:libharfbuzz.so.0',
               '-Wl,-rpath-link,' + str(libraries), '-o', binary])
        g.prepare_compat(home)
        b.run(['patchelf', '--force-rpath', '--set-rpath', f'{home}/compat:{system}:{libraries}', binary])
        failed = subprocess.run([binary], capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('FT_Get_Transform', failed.stderr)
        with patch.object(g, 'SYSTEM_DIRS', (str(system),)):
            _, rpath = g.runtime_paths()
        rpath = rpath.replace('/opt/' + g.NAME, str(home))
        self.assertLess(rpath.index(str(libraries)), rpath.index(str(system)))
        b.run(['patchelf', '--force-rpath', '--set-rpath', rpath, binary])
        b.run([binary])

    @unittest.skipUnless(all(shutil.which(n) for n in ('rpmbuild', 'rpm', 'ar', 'tar', 'zstd', 'bsdtar')), 'native packaging tools required')
    def test_packages_do_not_require_or_replace_system_core_runtime(self):
        self.release['bundled_graphics'] = list(g.BUNDLED_GRAPHICS)
        self.release['bundled_mesa'] = True
        root = self.root / 'payload'
        home = root / 'opt' / g.NAME
        home.mkdir(parents=True)
        (home / 'chromium').write_bytes(b'test browser')
        (home / 'chrome-sandbox').write_bytes(b'test sandbox')
        (home / 'chrome-sandbox').chmod(0o4755)
        for path in ('usr/bin/' + g.NAME, 'usr/share/applications/' + g.NAME + '.desktop',
                     'usr/share/licenses/' + g.NAME + '/copyright', 'usr/share/doc/' + g.NAME + '/sources.json',
                     'usr/share/icons/hicolor/128x128/apps/' + g.NAME + '.png'):
            u.write_file(root / path, 'test')
        for packer, filename in zip((u.make_arch,u.make_deb,u.make_rpm), u.filenames(self.release)):
            with self.subTest(filename=filename):
                work = self.root / filename.replace('.', '_')
                work.mkdir()
                output = self.root / filename
                packer(root,output,self.release,work)
                if filename.endswith('.deb'):
                    control = b.run(['ar','p',output,'control.tar.gz'])
                    import io,tarfile
                    with tarfile.open(fileobj=io.BytesIO(control),mode='r:gz') as archive:
                        text=archive.extractfile('./control').read().decode()
                    self.assertIn('Package: '+g.NAME+'\n',text)
                    deps=next(line for line in text.splitlines() if line.startswith('Depends:'))
                    self.assertNotIn('libc6',deps)
                    self.assertNotIn('libstdc++',deps)
                    for dependency in ('libudev1', 'libgl1', 'libegl1', 'libgbm1'):
                        self.assertNotIn(dependency, deps)
                elif filename.endswith('.rpm'):
                    deps=b.run(['rpm','-qp','--requires',output]).decode()
                    self.assertNotIn('glibc',deps)
                    self.assertNotIn('libgcc',deps)
                    self.assertNotIn('libstdc++',deps)
                    self.assertNotIn('systemd-libs', deps)
                    self.assertNotIn('mesa-libgbm', deps)
                    self.assertNotIn('libglvnd', deps)
                else:
                    text=b.run(['bsdtar','-xOf',output,'.PKGINFO']).decode()
                    self.assertIn('pkgname = '+g.NAME+'\n',text)
                    self.assertNotIn('depend = glibc',text)
                    self.assertNotIn('depend = libgcc',text)
                    self.assertNotIn('depend = libglvnd', text)
                    self.assertNotIn('depend = mesa', text)
                    self.assertNotIn('depend = systemd-libs', text)
                names=b.run(['bsdtar','-tf',output]).decode() if not filename.endswith('.deb') else ''
                self.assertNotIn('usr/lib/libc.so',names)


if __name__ == '__main__':
    unittest.main()
