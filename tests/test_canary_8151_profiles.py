"""Real Canary code windows: complete profiles, safe exits and negative cases."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

import mv2ctl as ctl


class Canary8151ProfileTests(unittest.TestCase):
    def cases(self):
        for path in sorted((Path(__file__).parent / 'fixtures').glob('*159.0.8151.0.json')):
            fixture = json.loads(path.read_text())
            data = bytearray(b'\xcc' * 0x1400)
            data[:0x200] = bytes(0x200)
            if fixture['format'] == 'PE':
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
            else:
                data[:6] = b'\x7fELF\x02\x01'
                struct.pack_into('<Q', data, 32, 64)
                struct.pack_into('<HH', data, 54, 56, 1)
                struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0x200, 0x1000, 0,
                                 0x1200, 0x1200, 0x1000)
            for window in fixture['windows']:
                off = int(window['test_offset'], 16)
                code = bytes.fromhex(window['hex'])
                data[off:off + len(code)] = code
            yield fixture, data

    def analyze(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            path.write_bytes(data)
            return ctl.analyze(path, verbose=False, with_discovery=False)

    def test_complete_profiles_and_verified_copy(self):
        cases = list(self.cases())
        self.assertEqual(len(cases), 3)
        for fixture, data in cases:
            with self.subTest(build=fixture['source']), tempfile.TemporaryDirectory() as directory:
                sites, status, _ = self.analyze(data)
                self.assertEqual(status, 'original')
                pending = ctl.pending_patch_sites(sites)
                self.assertEqual(len(pending), 6 if fixture['format'] == 'PE' else 5)
                source, output = Path(directory) / 'source', Path(directory) / 'patched'
                source.write_bytes(data)
                ctl.write_patched_copy(source, output, pending)
                self.assertEqual(self.analyze(output.read_bytes())[1], 'patched')
                self.assertEqual(source.read_bytes(), data)
                expected = bytearray(data)
                for site in pending:
                    expected[site.jpos:site.jpos + len(site.new)] = site.new
                self.assertEqual(output.read_bytes(), expected)
                for window in fixture['windows']:
                    if window['kind'] in ('CSP', 'H'):
                        off = int(window['test_offset'], 16)
                        code = bytes.fromhex(window['hex'])
                        self.assertEqual(output.read_bytes()[off:off + len(code)], code)

    def test_rejects_changed_safe_exits_and_detail_checks(self):
        for fixture, data in self.cases():
            for window in fixture['windows']:
                if not window['kind'].startswith('N'):
                    continue
                rule = next(r for r in ctl.R159_POLICY
                            if r[0] == fixture['format'] and r[1] == window['kind'])
                off = int(window['test_offset'], 16)
                for field in (5, 6):  # Detailed policy block and safe return.
                    with self.subTest(build=fixture['source'], kind=rule[1], field=field):
                        broken = bytearray(data)
                        broken[off + rule[field]] ^= 1
                        self.assertEqual(self.analyze(broken)[1], 'fail')

    def test_rejects_changed_disable_reason(self):
        for fixture, data in self.cases():
            window = next(w for w in fixture['windows'] if w['kind'] == 'N4')
            off = int(window['test_offset'], 16)
            code = bytes.fromhex(window['hex'])
            reason = code.index(bytes.fromhex('00008000'))
            with self.subTest(build=fixture['source']):
                data[off + reason] ^= 1
                self.assertEqual(self.analyze(data)[1], 'fail')

    def test_rejects_missing_checker_copy(self):
        for fixture, data in self.cases():
            window = next(w for w in fixture['windows'] if w['kind'] == 'N1')
            off = int(window['test_offset'], 16)
            data[off] = 0xcc
            with self.subTest(build=fixture['source']):
                self.assertEqual(self.analyze(data)[1], 'fail')


if __name__ == '__main__':
    unittest.main()
