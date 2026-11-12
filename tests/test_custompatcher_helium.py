import contextlib
import gzip
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

import custompatcher as c


def pack(script, *, alias=True):
    # The last payload and an alias exercise index relocation and table retention.
    payloads = [b'unchanged-first', gzip.compress(script, mtime=0), b'unchanged-last']
    result = bytearray(struct.pack('<IBxxxHH', 5, 1, 3, int(alias)))
    offset = 12 + 4 * 6 + int(alias) * 4
    for rid, data in zip((10, c.SETTINGS_ID, 30000), payloads):
        result.extend(struct.pack('<HI', rid, offset))
        offset += len(data)
    result.extend(struct.pack('<HI', 0, offset))
    if alias:
        result.extend(struct.pack('<HH', 30001, 1))
    return bytes(result) + b''.join(payloads)


def resources(data):
    entries = c.read_pack(data)
    return {rid: data[start:end] for (rid, start), (_, end) in zip(entries, entries[1:])}


class HeliumTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.gaia_profile = c.GAIA_EDITS
        self.binary = self.root / 'helium'
        self.binary.write_bytes(b'ELF-test' + b'\0' * 120 + c.NATIVE_WINDOW + b'fixture')
        self.binary.chmod(0o755)
        self.script = '\n'.join(old for old, _ in c.JS_EDITS).encode()
        self.resource = self.root / 'resources.pak'
        self.resource.write_bytes(pack(self.script))
        for name, value in [('NATIVE_OFFSET', 128), ('NATIVE_SHA256', c.file_hash(self.binary)),
                            ('SYNC_EDITS', ()),
                            ('GAIA_EDITS', ()),
                            ('SETTINGS_SHA256', c.digest(self.script))]:
            self.addCleanup(patch.stopall)
            patch.object(c, name, value).start()
        self.backend = Mock()
        self.backend.atomic_install.side_effect = lambda src, dst: Path(src).replace(dst)

    def apply(self, features=('password-manager', 'autofill')):
        with contextlib.redirect_stdout(io.StringIO()):
            c.install_custom(str(self.binary), features, self.backend)

    def with_sync(self):
        data = self.binary.read_bytes()
        changes = []
        for old, new in [(b'https://clients4.9oo91e.qjz9zk/chrome-sync\0',
                          b'https://clients4.google.com/chrome-sync\0\0\0\0'),
                         (struct.pack('<I', 42), struct.pack('<I', 39))]:
            changes.append((len(data), old, new))
            data += old
        self.binary.write_bytes(data)
        patch.object(c, 'SYNC_EDITS', tuple(changes)).start()
        patch.object(c, 'NATIVE_SHA256', c.digest(data)).start()
        return data

    def with_gaia(self):
        data = self.binary.read_bytes()
        changes = []
        for _, old, new in self.gaia_profile:
            changes.append((len(data), old, new))
            data += old
        self.binary.write_bytes(data)
        patch.object(c, 'GAIA_EDITS', tuple(changes)).start()
        patch.object(c, 'NATIVE_SHA256', c.digest(data)).start()
        return data

    def test_gaia_urls_lengths_and_prior_patches_survive_upgrade(self):
        self.with_sync()
        original = self.with_gaia()
        self.apply(('password-manager', 'sync-url'))
        self.apply(('gaia-url',))
        self.assertEqual(c.binary_states(self.binary), {
            'password-manager': 'patched', 'sync-url': 'patched', 'gaia-url': 'patched'})
        result = self.binary.read_bytes()
        self.assertEqual(len(result), len(original))
        for offset, old, new in c.GAIA_EDITS:
            self.assertEqual(result[offset:offset + len(old)], new)
        with contextlib.redirect_stdout(io.StringIO()):
            c.restore_custom(str(self.binary), self.backend)
        self.assertEqual(self.binary.read_bytes(), original)

    def test_partial_gaia_patch_is_refused(self):
        data = bytearray(self.with_gaia())
        offset, old, new = c.GAIA_EDITS[0]
        data[offset:offset + len(old)] = new
        self.binary.write_bytes(data)
        self.assertEqual(c.binary_states(self.binary)['gaia-url'], 'mixed')
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            self.apply(('gaia-url',))
        self.backend.atomic_install.assert_not_called()

    def test_sync_upgrade_keeps_password_patch_and_original_backup(self):
        original = self.with_sync()
        self.apply(('password-manager',))
        previous = self.binary.read_bytes()
        self.apply(('sync-url',))
        self.assertEqual(c.binary_states(self.binary),
                         {'password-manager': 'patched', 'sync-url': 'patched'})
        data = self.binary.read_bytes()
        self.assertEqual(len(data), len(original))
        for offset, old, new in c.SYNC_EDITS:
            self.assertEqual(data[offset:offset + len(new)], new)
        manifest = c.load_backup(self.root / c.BACKUP_DIR)
        self.assertIn(c.digest(previous), manifest['files']['helium']['previous'])
        self.assertEqual((self.root / c.BACKUP_DIR / 'helium').read_bytes(), original)
        self.apply(('password-manager', 'sync-url'))
        self.assertEqual(self.binary.read_bytes(), data)
        with contextlib.redirect_stdout(io.StringIO()):
            c.restore_custom(str(self.binary), self.backend)
        self.assertEqual(self.binary.read_bytes(), original)

    def test_partial_sync_patch_refused(self):
        data = bytearray(self.with_sync())
        offset, old, new = c.SYNC_EDITS[0]
        data[offset:offset + len(old)] = new
        self.binary.write_bytes(data)
        self.assertEqual(c.binary_states(self.binary)['sync-url'], 'mixed')
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            self.apply(('sync-url',))
        self.assertFalse((self.root / c.BACKUP_DIR).exists())

    def test_sync_failure_rolls_back_to_previous_patch_not_pristine_binary(self):
        self.with_sync()
        self.apply(('password-manager',))
        previous = self.binary.read_bytes()

        def fail_once(src, dst):
            self.backend.atomic_install.side_effect = lambda a, b: Path(a).replace(b)
            Path(src).replace(dst)
            raise OSError('injected upgrade failure')

        self.backend.atomic_install.side_effect = fail_once
        with self.assertRaisesRegex(OSError, 'upgrade failure'):
            self.apply(('sync-url',))
        self.assertEqual(self.binary.read_bytes(), previous)
        # A transaction interrupted before replacement also remains restorable.
        with contextlib.redirect_stdout(io.StringIO()):
            c.restore_custom(str(self.binary), self.backend)
        self.assertEqual(c.binary_states(self.binary)['password-manager'], 'original')

    def test_native_exact_fingerprint_and_one_byte_change(self):
        before = self.binary.read_bytes()
        self.assertEqual(c.native_state(self.binary), 'original')
        self.apply(('password-manager',))
        after = self.binary.read_bytes()
        self.assertEqual(after, before[:128] + b'\xc3' + before[129:])
        self.assertEqual(c.native_state(self.binary), 'patched')
        self.binary.write_bytes(after + b'unknown modification')
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            c.native_state(self.binary)

    def test_pack_relocation_aliases_and_other_payloads_preserved(self):
        original = self.resource.read_bytes()
        state, changed = c.patch_resources(original)
        self.assertEqual(state, 'original')
        before, after = resources(original), resources(changed)
        self.assertEqual(before[10], after[10])
        self.assertEqual(before[30000], after[30000])
        self.assertEqual(original[36:40], changed[36:40])  # alias table
        text = gzip.decompress(after[c.SETTINGS_ID]).decode()
        for _, new in c.JS_EDITS:
            self.assertEqual(text.count(new), 1)
        self.assertEqual(c.patch_resources(changed), ('patched', changed))

    def test_partial_or_foreign_javascript_rejected(self):
        text = self.script.decode().replace(*c.JS_EDITS[0])
        with self.assertRaises(ValueError):
            c.patch_resources(pack(text.encode()))
        with self.assertRaises(ValueError):
            c.patch_resources(pack(self.script + b'unknown'))

    def test_corrupt_pack_bounds_and_alias_rejected(self):
        for position, value, fmt in [(14, 1, '<I'), (32, 999999, '<I'), (38, 5, '<H')]:
            with self.subTest(position=position):
                data = bytearray(self.resource.read_bytes())
                struct.pack_into(fmt, data, position, value)
                with self.assertRaises(ValueError):
                    c.patch_resources(data)

    def test_restore_and_reapply_preserve_original_backups(self):
        original = {p.name: p.read_bytes() for p in (self.binary, self.resource)}
        self.apply()
        root = self.root / c.BACKUP_DIR
        first_manifest = (root / 'manifest.json').read_bytes()
        self.apply()
        with contextlib.redirect_stdout(io.StringIO()):
            c.restore_custom(str(self.binary), self.backend)
        for name, data in original.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        self.apply()
        self.assertEqual((root / 'manifest.json').read_bytes(), first_manifest)
        for name, data in original.items():
            self.assertEqual((root / name).read_bytes(), data)

    def test_independent_feature_application(self):
        self.apply(('autofill',))
        self.assertEqual(c.native_state(self.binary), 'original')
        self.apply(('password-manager',))
        self.assertEqual(c.native_state(self.binary), 'patched')
        self.assertEqual(set(c.load_backup(self.root / c.BACKUP_DIR)['files']),
                         {'helium', 'resources.pak'})

    def test_failure_after_first_replace_rolls_back_both(self):
        original = {p.name: p.read_bytes() for p in (self.binary, self.resource)}
        calls = 0

        def install(src, dst):
            nonlocal calls
            calls += 1
            Path(src).replace(dst)
            if calls == 2:
                raise OSError('injected post-replace fsync error')

        self.backend.atomic_install.side_effect = install
        with self.assertRaisesRegex(OSError, 'injected'):
            self.apply()
        for name, data in original.items():
            self.assertEqual((self.root / name).read_bytes(), data)

    def test_changed_backup_or_installed_file_blocks_restore(self):
        self.apply()
        self.binary.write_bytes(self.binary.read_bytes() + b'upgrade')
        with self.assertRaisesRegex(ValueError, 'no longer matches'):
            c.restore_custom(str(self.binary), self.backend)
        self.backend.atomic_install.reset_mock()
        (self.root / c.BACKUP_DIR / 'resources.pak').write_bytes(b'corruption')
        with self.assertRaisesRegex(ValueError, 'backup has changed'):
            c.restore_custom(str(self.binary), self.backend)
        self.backend.atomic_install.assert_not_called()

    def test_refuses_running_browser_before_writing(self):
        self.backend.ensure_chromium_stopped.side_effect = SystemExit('running')
        with self.assertRaisesRegex(SystemExit, 'running'):
            self.apply()
        self.assertFalse((self.root / c.BACKUP_DIR).exists())

    def test_copy_is_self_contained_and_source_unchanged(self):
        output = self.root.parent / (self.root.name + '-copy')
        self.addCleanup(lambda: __import__('shutil').rmtree(output, ignore_errors=True))
        self.binary.with_name('chrome').symlink_to('helium')
        original = c.file_hash(self.binary), c.file_hash(self.resource)
        with contextlib.redirect_stdout(io.StringIO()):
            c.test_custom(str(self.binary), str(output), ['password-manager', 'autofill'], self.backend)
        self.assertEqual((c.file_hash(self.binary), c.file_hash(self.resource)), original)
        self.assertEqual(c.native_state(output / 'helium'), 'patched')
        self.assertEqual((output / 'chrome').readlink(), Path('helium'))
        with self.assertRaisesRegex(ValueError, 'already exists'):
            c.test_custom(str(self.binary), str(output), ['autofill'], self.backend)
        with self.assertRaisesRegex(ValueError, 'inside'):
            c.test_custom(str(self.binary), str(self.root / 'recursive'), ['autofill'], self.backend)

    def test_symlink_backup_is_rejected(self):
        root = self.root / c.BACKUP_DIR
        root.mkdir()
        # Existing malformed backup is refused before any target replacement.
        (root / 'manifest.json').symlink_to(self.root / 'absent')
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            self.apply()
        self.backend.atomic_install.assert_not_called()


if __name__ == '__main__':
    unittest.main()
