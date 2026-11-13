"""Manifest error resources follow message content across linker/resource churn."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

import mv2ctl as ctl
import mv2flow as flow
import test_mv2flow as block_tests


def pack_message(rid, message=flow.UNSUPPORTED_MANIFEST_MESSAGE, alias=None, encoding=1):
    text = message.encode('utf-8' if encoding == 1 else 'utf-16-le')
    start = 24 + (4 if alias is not None else 0)
    header = struct.pack('<IB3xHH', 5, encoding, 1, int(alias is not None))
    index = struct.pack('<HIHI', rid, start, 0, start + len(text))
    return header + index + (struct.pack('<HH', alias, 0) if alias is not None else b'') + text


class ResourceIdentityTests(unittest.TestCase):
    def install_case(self):
        meta, data = block_tests.MultipleBlockTests().case()
        old = next(w for w in meta['windows'] if w['kind'] == 'N5')
        off = int(old['test_offset'], 16)
        real = json.loads((Path(__file__).parent / 'fixtures' /
                           'chrome-linux-canary-160.0.8158.0-install.json').read_text())
        data[off:off + len(bytes.fromhex(old['hex']))] = b'\xcc' * len(bytes.fromhex(old['hex']))
        code = bytes.fromhex(real['window']['hex'])
        data[off:off + len(code)] = code
        return data, real['resource_id']

    def test_8158_copy_patch_uses_source_assets_for_detached_output(self):
        data, rid = self.install_case()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'distribution' / 'chrome'
            source.parent.mkdir()
            source.write_bytes(data)
            locales = source.parent / 'locales'
            locales.mkdir()
            (locales / 'en-US.pak').write_bytes(pack_message(rid))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ctl.analyze(source, with_discovery=False)[1], 'original')
                # check_size is only a CLI minimum-size guard; use writer directly.
                sites, _, _ = ctl.analyze(source, with_discovery=False)
                ctl.write_patched_copy(source, root / 'detached', ctl.pending_patch_sites(sites))
                self.assertEqual(ctl.analyze(root / 'detached', with_discovery=False,
                                            resource_path=locales / 'en-US.pak')[1], 'patched')
            self.assertEqual(source.read_bytes(), data)

    def test_windows_capital_locales_in_version_directory_and_parent(self):
        _, data = block_tests.MultipleBlockTests().case('PE')
        detail = next(r for r in ctl.R159_INSTALL if r[0] == 'PE')[2].search(data)
        rid = 0x14bd
        struct.pack_into('<I', data, detail.start('resource'), rid)
        for parent_assets in (False, True):
            with self.subTest(parent_assets=parent_assets), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'Chrome-bin' / '160.0.8158.0' / 'chrome.dll'
                source.parent.mkdir(parents=True)
                source.write_bytes(data)
                asset_root = source.parent.parent if parent_assets else source.parent
                locale = asset_root / 'Locales'
                locale.mkdir()
                pak = locale / 'en-US.pak'
                pak.write_bytes(pack_message(rid))
                self.assertEqual(flow.locale_pack_for(source), pak)
                with contextlib.redirect_stdout(io.StringIO()):
                    sites, state, _ = ctl.analyze(source, with_discovery=False)
                    self.assertEqual(state, 'original')
                    ctl.write_patched_copy(source, root / 'detached.dll', ctl.pending_patch_sites(sites))
                    self.assertEqual(ctl.analyze(root / 'detached.dll', with_discovery=False,
                                                resource_path=pak)[1], 'patched')

    def test_arbitrary_renumbering_requires_the_exact_message(self):
        for fmt in ('ELF', 'PE'):
            meta, data = block_tests.MultipleBlockTests().case(fmt)
            rule = next(r for r in ctl.R159_INSTALL if r[0] == fmt)
            detail = rule[2].search(data)
            rid = 60000
            struct.pack_into('<I', data, detail.start('resource'), rid)
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'chrome'
                source.write_bytes(data)
                locale = source.parent / 'locales'
                locale.mkdir()
                pak = locale / 'en-US.pak'
                for message, expected in ((flow.UNSUPPORTED_MANIFEST_MESSAGE, 'original'),
                                           ('Some other extension error.', 'fail')):
                    with self.subTest(fmt=fmt, message=message):
                        pak.write_bytes(pack_message(rid, message))
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.assertEqual(ctl.analyze(source, with_discovery=False)[1], expected)

    def test_present_pack_overrides_historical_numeric_allowlist(self):
        _, data = block_tests.MultipleBlockTests().case()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'chrome'
            source.write_bytes(data)
            (source.parent / 'locales').mkdir()
            pak = source.parent / 'locales' / 'en-US.pak'
            pak.write_bytes(pack_message(42, 'An unrelated message.'))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ctl.analyze(source, with_discovery=False)[1], 'fail')
            pak.write_bytes(b'broken')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ctl.analyze(source, with_discovery=False)[1], 'fail')

    def test_unknown_error_emission_cannot_hide_behind_profile_minima(self):
        data, rid = self.install_case()
        detail = next(r for r in ctl.R159_INSTALL if r[0] == 'ELF')[2].search(data)
        call = detail.start('resource') + 4
        struct.pack_into('<i', data, call + 1, 0x1000 - call - 5)
        off = 0x2000
        data[off:off + 10] = b'\xbe' + struct.pack('<I', rid) + b'\xe8' + struct.pack('<i', 0x1000 - off - 10)
        sites, rejects = ctl.find_sites(data, ctl.parse_exec_segments(data), frozenset((rid,)))
        self.assertEqual(len([s for s in sites if s.kind == 'N5']), 1)
        self.assertTrue(any(kind == 'coverage' and address == off for kind, address, _ in rejects))

    def test_resource_number_used_as_length_or_other_argument_is_not_an_error(self):
        data, rid = self.install_case()
        detail = next(r for r in ctl.R159_INSTALL if r[0] == 'ELF')[2].search(data)
        call = detail.start('resource') + 4
        struct.pack_into('<i', data, call + 1, 0x1000 - call - 5)
        for opcode, destination in ((0xba, 0x1000), (0xbe, 0x1100), (0xba, 0x1100)):
            with self.subTest(opcode=opcode, destination=destination):
                off = 0x2000
                data[off:off + 10] = bytes((opcode,)) + struct.pack('<I', rid) + b'\xe8' + struct.pack('<i', destination - off - 10)
                _, rejects = ctl.find_sites(data, ctl.parse_exec_segments(data), frozenset((rid,)))
                self.assertFalse(any(kind == 'coverage' for kind, _, _ in rejects))

    def test_changed_install_body_still_reports_unclassified_error_call(self):
        data, rid = self.install_case()
        detail = next(r for r in ctl.R159_INSTALL if r[0] == 'ELF')[2].search(data)
        data[detail.start()] ^= 1
        call = detail.start('resource') + 4
        struct.pack_into('<i', data, call + 1, 0x1000 - call - 5)
        _, rejects = ctl.find_sites(data, ctl.parse_exec_segments(data), frozenset((rid,)))
        self.assertTrue(any(kind == 'coverage' and 'error call' in reason
                            for kind, _, reason in rejects))

    def test_aliases_and_utf16_resource_text(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'en-US.pak'
            for encoding in (1, 2):
                p.write_bytes(pack_message(100, alias=60000, encoding=encoding))
                self.assertEqual(flow.manifest_resource_ids(p), frozenset((100, 60000)))

    def test_malformed_indexes_and_aliases_are_rejected(self):
        valid = pack_message(100, alias=60000)
        samples = [valid[:10], valid[:24]]
        for offset, value, fmt in ((14, 0, '<I'), (20, len(valid) + 1, '<I'),
                                   (26, 1, '<H'), (24, 100, '<H')):
            broken = bytearray(valid)
            struct.pack_into(fmt, broken, offset, value)
            samples.append(broken)
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'en-US.pak'
            for sample in samples:
                p.write_bytes(sample)
                with self.assertRaises(ValueError):
                    flow.manifest_resource_ids(p)


if __name__ == '__main__':
    unittest.main()
