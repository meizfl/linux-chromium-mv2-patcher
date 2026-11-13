"""Real alternate-toolchain windows, including independent shared-block entries."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

import mv2ctl as ctl
import mv2profiles as profiles
import test_mv2flow as blocks
from test_mv2resources import pack_message


class WindowsInline160Tests(unittest.TestCase):
    def case(self):
        _, data = blocks.MultipleBlockTests().case('PE')
        data.extend(b'\xcc' * (0x10000 - len(data)))
        data[0x200:] = b'\xcc' * (len(data) - 0x200)
        struct.pack_into('<II', data, 0x188 + 8, 0xfe00, 0x1000)
        struct.pack_into('<I', data, 0x188 + 16, 0xfe00)
        meta = json.loads((Path(__file__).parent / 'fixtures' /
                           'chrome-win64-canary-160.0.8158.2-inline.json').read_text())
        for window in meta['windows']:
            off = int(window['test_offset'], 16)
            code = bytes.fromhex(window['hex'])
            data[off:off + len(code)] = code
        # Relocate the formatter call for the synthetic executable segment.
        error = profiles.R160_INLINE_WIN_ERROR.search(data)
        call = error.start('call')
        struct.pack_into('<i', data, call + 1, 0x200 - call - 5)
        data[0x200] = 0xc3
        return meta, data

    def analyze(self, data, message=None):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'chrome.dll'
            p.write_bytes(data)
            locales = p.parent / 'Locales'
            locales.mkdir()
            (locales / 'en-US.pak').write_bytes(pack_message(0x14bd) if message is None else pack_message(0x14bd, message))
            with contextlib.redirect_stdout(io.StringIO()):
                return ctl.analyze(p, with_discovery=False)

    def test_complete_original_copy_and_patched_shared_entries(self):
        meta, data = self.case()
        sites, state, _ = self.analyze(data)
        self.assertEqual(state, 'original')
        self.assertEqual(len([s for s in sites if s.kind == 'N1']), 3)
        self.assertEqual(len([s for s in sites if s.kind == 'A']), 4)
        pending = ctl.pending_patch_sites(sites)
        self.assertEqual(len(pending), 11)
        install = next(s for s in sites if s.kind == 'N5')
        self.assertTrue(any(s.kind == 'A' and s.jpos == install.jpos for s in sites))
        for site in pending:
            data[site.jpos:site.jpos + len(site.new)] = site.new
        self.assertEqual(self.analyze(data)[1], 'patched')
        csp = next(w for w in meta['windows'] if w['purpose'] == 'CSP-preserved')
        off = int(csp['test_offset'], 16)
        code = bytes.fromhex(csp['hex'])
        self.assertEqual(bytes(data[off:off + len(code)]), code)

    def test_additional_entry_to_the_same_block_is_independently_patched(self):
        _, data = self.case()
        sites, _, _ = self.analyze(data)
        source = next(s for s in sites if s.kind == 'N1')
        detail = ctl.decode_jump(data, source.jpos)[0]
        safe = ctl.decode_jump(data, source.jpos + 6)[0]
        off = 0x8100
        compare = bytes(data[source.start:source.jpos])
        branch = off + len(compare)
        code = (compare + b'\x0f\x8e' + struct.pack('<i', detail - branch - 6) +
                b'\xe9' + struct.pack('<i', safe - branch - 11))
        data[off:off + len(code)] = code
        sites, state, _ = self.analyze(data)
        self.assertEqual(state, 'original')
        self.assertEqual(len([s for s in sites if s.kind == 'N1']), 4)
        for site in ctl.pending_patch_sites(sites):
            data[site.jpos:site.jpos + len(site.new)] = site.new
        self.assertEqual(self.analyze(data)[1], 'patched')

    def test_crosswired_shared_detail_or_unaffected_exit_is_refused(self):
        _, data = self.case()
        sites, _, _ = self.analyze(data)
        for site in (s for s in sites if s.kind == 'N1'):
            for offset in (site.jpos + 2, site.jpos + 7):
                with self.subTest(branch=site.jpos, offset=offset):
                    broken = bytearray(data)
                    broken[offset] ^= 1
                    self.assertEqual(self.analyze(broken)[1], 'fail')

    def test_changed_policy_reason_and_operands_are_refused(self):
        _, data = self.case()
        sites, _, _ = self.analyze(data)
        for site in sites:
            if site.kind not in ('A', 'C', 'N2', 'N3', 'N6'):
                continue
            if site.kind == 'A':
                # Both type exclusions becoming 10 still matches the old
                # generic byte anchor; operand validation must reject it.
                match = ctl.RA.match(data, site.start)
                position = match.start('je') - 1
            else:
                reason = bytes(data[site.start:site.end]).find(bytes.fromhex('00008000'))
                position = site.start + reason if reason >= 0 else site.start + 1
            broken = bytearray(data)
            broken[position] ^= 1
            with self.subTest(kind=site.kind, branch=site.jpos):
                self.assertEqual(self.analyze(broken)[1], 'fail')

    def test_unclassified_r8_resource_call_still_stops_patching(self):
        _, data = self.case()
        off = 0x8000
        data[off:off + 11] = bytes.fromhex('41b8bd140000e8') + struct.pack('<i', 0x200 - off - 11)
        self.assertEqual(self.analyze(data)[1], 'fail')

    def test_install_message_must_be_verified(self):
        _, data = self.case()
        self.assertEqual(self.analyze(data, 'Unrelated localization string.')[1], 'fail')


if __name__ == '__main__':
    unittest.main()
