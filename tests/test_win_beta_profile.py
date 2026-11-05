"""Exercise the real Beta instruction windows in a small, non-executable PE fixture."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

import mv2ctl as ctl


class WindowsBetaProfileTests(unittest.TestCase):
    fixture_name = 'chrome-beta-158.0.8127.2-win64.json'
    install_offset = 0xa00
    install_kind = 'W5_158_8127'
    startup_pattern = ctl.WIN_STARTUP_V13

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture = json.loads((Path(__file__).parent / 'fixtures' / self.fixture_name).read_text())
        data = bytearray(0x200) + bytearray(b'\xcc' * 0x1200)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 0x3c, 0x80)
        data[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<HH', data, 0x84, 0x8664, 1)
        struct.pack_into('<H', data, 0x94, 0xf0)
        struct.pack_into('<H', data, 0x98, 0x20b)
        struct.pack_into('<Q', data, 0x98 + 24, 0x180000000)
        section = 0x98 + 0xf0
        struct.pack_into('<IIII', data, section + 8, 0x1200, 0x1000, 0x1200, 0x200)
        struct.pack_into('<I', data, section + 36, 0x60000020)
        for window in fixture['windows']:
            offset = int(window['test_offset'], 16)
            code = bytes.fromhex(window['hex'])
            data[offset:offset + len(code)] = code
        self.original = bytes(data)
        self.binary = self.root / 'chrome.dll'
        self.binary.write_bytes(data)

    def analyze(self):
        return ctl.analyze(self.binary, verbose=False, with_discovery=False)

    def test_recognizes_complete_profile_and_verifies_eight_edits(self):
        sites, status, _ = self.analyze()
        self.assertEqual(status, 'original')
        self.assertEqual(len(sites), 8)
        self.assertEqual({s.kind for s in sites}, {'A', 'W1', 'W2', 'W3', 'W4', self.install_kind, 'W6'})
        pending = ctl.pending_patch_sites(sites)
        output = self.root / 'patched.dll'
        ctl.write_patched_copy(self.binary, output, pending)
        _, status, _ = ctl.analyze(output, verbose=False, with_discovery=False)
        self.assertEqual(status, 'patched')
        self.assertEqual(self.binary.read_bytes(), self.original)
        expected = bytearray(self.original)
        for site in pending:
            expected[site.jpos:site.jpos + len(site.new)] = site.new
        self.assertEqual(output.read_bytes(), expected)

    def test_rejects_unknown_install_error_resource(self):
        data = bytearray(self.original)
        error = ctl._win_rel32_target(data, self.install_offset + 48, 6)
        data[error + 11] ^= 1
        self.binary.write_bytes(data)
        self.assertEqual(self.analyze()[1], 'fail')

    def test_rejects_changed_install_policy_and_cleanup_destinations(self):
        start = self.install_offset
        error = ctl._win_rel32_target(self.original, start + 48, 6)
        types = ctl._win_rel32_target(self.original, start + 34, 6)
        for offset in (start + 5, start + 44, start + 35,
                       types + 5, types + 14, types + 19, error + 36):
            with self.subTest(offset=hex(offset)):
                data = bytearray(self.original)
                data[offset] ^= 1
                self.binary.write_bytes(data)
                self.assertEqual(self.analyze()[1], 'fail')

    def test_rejects_changed_startup_destination(self):
        data = bytearray(self.original)
        startup = self.startup_pattern.search(data).start()
        data[startup + 10] ^= 1
        self.binary.write_bytes(data)
        self.assertEqual(self.analyze()[1], 'fail')

    def test_patched_startup_still_requires_valid_disable_reason_loop(self):
        sites, _, _ = self.analyze()
        output = self.root / 'patched.dll'
        ctl.write_patched_copy(self.binary, output, ctl.pending_patch_sites(sites))
        data = bytearray(output.read_bytes())
        reason = data.index(bytes.fromhex('c7 00 00 00 80 00'), 0x300)
        data[reason + 4] = 0x40
        self.binary.write_bytes(data)
        self.assertEqual(self.analyze()[1], 'fail')


if __name__ == '__main__':
    unittest.main()
