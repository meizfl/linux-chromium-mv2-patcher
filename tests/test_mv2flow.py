"""Independent gates, overlapping proof windows, and coverage failures."""
import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import mv2ctl as ctl
import mv2flow as flow
import test_canary_8151_profiles as fixtures


class MultipleBlockTests(unittest.TestCase):
    def case(self, fmt='ELF'):
        suffix = ('chrome-testing-linux-canary-159.0.8151.0' if fmt == 'ELF' else
                  'chrome-testing-win64-canary-159.0.8151.0')
        meta, data = next((meta, data) for meta, data in fixtures.Canary8151ProfileTests().cases()
                          if meta['source'] == suffix)
        data.extend(b'\xcc' * (0x6000 - len(data)))
        if fmt == 'ELF':
            struct.pack_into('<QQ', data, 96, 0x5e00, 0x5e00)
        else:
            struct.pack_into('<I', data, 0x188 + 8, 0x5e00)
            struct.pack_into('<I', data, 0x188 + 16, 0x5e00)
        # Move the startup proof away to leave room for independent blocks in
        # the same code region. Internal relative branches remain unchanged.
        startup = next(w for w in meta['windows'] if w['kind'] == 'N6')
        off = int(startup['test_offset'], 16)
        code = bytes.fromhex(startup['hex'])
        data[off:off + len(code)] = b'\xcc' * len(code)
        data[0x4000:0x4000 + len(code)] = code
        return meta, data

    def analyze(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'browser'
            path.write_bytes(data)
            return ctl.analyze(path, verbose=False, with_discovery=False)

    def duplicate_install(self, fmt='ELF'):
        meta, data = self.case(fmt)
        install = next(w for w in meta['windows'] if w['kind'] == 'N5')
        code = bytes.fromhex(install['hex'])
        data[0x1900:0x1900 + len(code)] = code
        return meta, data

    def test_two_install_blocks_in_one_code_region_are_both_patched(self):
        for fmt in ('ELF', 'PE'):
            meta, data = self.duplicate_install(fmt)
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as directory:
                sites, state, _ = self.analyze(data)
                self.assertEqual(state, 'original')
                gates = [s for s in sites if s.kind == 'N5']
                self.assertEqual(len(gates), 2)
                self.assertTrue(all(len(s.evidence) == 2 for s in gates))
                source, output = Path(directory) / 'source', Path(directory) / 'copy'
                source.write_bytes(data)
                ctl.write_patched_copy(source, output, ctl.pending_patch_sites(sites))
                patched, state, _ = self.analyze(output.read_bytes())
                self.assertEqual(state, 'patched')
                self.assertEqual(len([s for s in patched if s.kind == 'N5']), 2)
                self.assertEqual(source.read_bytes(), data)

    def test_a_second_role_inside_another_proof_window_is_not_hidden(self):
        for fmt in ('ELF', 'PE'):
            meta, data = self.case(fmt)
            checker = next(w for w in meta['windows'] if w['kind'] == 'N1')
            code = bytes.fromhex(checker['hex'])
            data[0x1540:0x1540 + len(code)] = code
            with self.subTest(fmt=fmt):
                sites, state, _ = self.analyze(data)
                self.assertEqual(state, 'original')
                extra = next(s for s in sites if s.kind == 'N1' and s.jpos == 0x1544)
                install = next(s for s in sites if s.kind == 'N5')
                self.assertTrue(install.start < extra.jpos < install.end)
                self.assertFalse(any(lo <= extra.jpos < hi for lo, hi in install.evidence))

    def test_unclassified_gate_inside_known_span_blocks_writes(self):
        for fmt in ('ELF', 'PE'):
            meta, data = self.case(fmt)
            checker = next(w for w in meta['windows'] if w['kind'] == 'N1')
            code = bytearray.fromhex(checker['hex'])
            # An unproved SUB implementation still has MV2 landmarks, but
            # neither a signature nor the decoded XOR proof authorizes it.
            self.assertEqual(code[6:8], b'\x31\xc0')
            code[6] = 0x29
            data[0x1540:0x1540 + len(code)] = code
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as directory:
                segments = ctl.parse_exec_segments(data)
                sites, rejects = ctl.find_sites(data, segments)
                self.assertFalse(rejects)
                self.assertEqual(len([s for s in sites if s.kind == 'N5']), 1)
                alarms = flow.audit_unclassified(data, segments, sites)
                self.assertTrue(any(kind == 'coverage' and off == 0x1544 for kind, off, _ in alarms))
                self.assertEqual(self.analyze(data)[1], 'fail')
                source, output = Path(directory) / 'source', Path(directory) / 'copy'
                source.write_bytes(data)
                with patch.object(ctl, 'check_size'), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, 'TEST ABORTED'):
                        ctl.cmd_test_apply(source, str(output))
                self.assertFalse(output.exists())
                self.assertEqual(source.read_bytes(), data)

    def test_cross_wiring_two_gates_to_one_detail_is_rejected(self):
        meta, data = self.duplicate_install()
        sites, _, _ = self.analyze(data)
        gates = [s for s in sites if s.kind == 'N5']
        first, second = gates
        second_detail = second.evidence[1][0]
        struct.pack_into('<i', data, first.jpos + 2, second_detail - first.jpos - 6)
        self.assertEqual(self.analyze(data)[1], 'fail')

    def test_loaded_version_register_still_exposes_an_unclassified_block(self):
        meta, data = self.case()
        checker = next(w for w in meta['windows'] if w['kind'] == 'N1')
        code = bytes.fromhex(checker['hex'])
        self.assertEqual(code[:4], bytes.fromhex('83 7e 50 02'))
        # The entire body moves two bytes, preserving its relative branches.
        code = bytes.fromhex('8b 46 50 83 f8 02') + code[4:]
        data[0x1540:0x1540 + len(code)] = code
        segments = ctl.parse_exec_segments(data)
        sites, rejects = ctl.find_sites(data, segments)
        self.assertFalse(rejects)
        alarms = flow.audit_unclassified(data, segments, sites)
        self.assertTrue(any(kind == 'coverage' and off == 0x1546 for kind, off, _ in alarms))
        self.assertEqual(self.analyze(data)[1], 'fail')

    def test_orphan_install_error_block_cannot_hide_behind_profile_minima(self):
        meta, data = self.case()
        rule = next(r for r in ctl.R159_INSTALL if r[0] == 'ELF')
        detail = rule[2].search(data)
        code = bytes(data[detail.start():detail.end()])
        data[0x5000:0x5000 + len(code)] = code
        self.assertEqual(self.analyze(data)[1], 'fail')

    def test_patched_gate_with_two_possible_detail_edges_is_rejected(self):
        meta, data = self.case()
        sites, _, _ = self.analyze(data)
        gate = next(s for s in sites if s.kind == 'N5')
        rule = next(r for r in ctl.R159_INSTALL if r[0] == 'ELF')
        detail = rule[2].search(data)
        safe = gate.jpos + 6
        code = bytearray(data[detail.start():detail.end()])
        for name in ('ja', 'jae', 'je1', 'je2'):
            off = detail.start(name) - detail.start()
            struct.pack_into('<i', code, off + 2, safe - (0x5000 + off + 6))
        data[0x5000:0x5000 + len(code)] = code
        data[gate.jpos:gate.jpos + 6] = b'\x90' * 6
        self.assertEqual(self.analyze(data)[1], 'fail')

    def test_partial_trial_finishes_each_independently_validated_block(self):
        meta, data = self.duplicate_install()
        sites, _, _ = self.analyze(data)
        gate = next(s for s in sites if s.kind == 'N5')
        data[gate.jpos:gate.jpos + len(gate.new)] = gate.new
        self.assertEqual(self.analyze(data)[1], 'mixed')
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'source', Path(directory) / 'copy'
            source.write_bytes(data)
            with patch.object(ctl, 'check_size'), contextlib.redirect_stdout(io.StringIO()):
                ctl.cmd_test_apply(source, str(output))
            self.assertEqual(self.analyze(output.read_bytes())[1], 'patched')
            self.assertEqual(source.read_bytes(), data)

    def test_duplicate_proofs_do_not_inflate_counts(self):
        meta, data = self.case()
        repeated = next(r for r in ctl.R159_POLICY if r[0] == 'ELF' and r[1] == 'N1')
        with patch.object(ctl, 'R159_POLICY', [*ctl.R159_POLICY, repeated]):
            sites, state, _ = self.analyze(data)
        self.assertEqual(state, 'original')
        self.assertEqual(len([s for s in sites if s.kind == 'N1']), 1)

    def test_plain_manifest_comparison_is_not_an_mv2_coverage_alarm(self):
        meta, data = self.case()
        data[0x1000:0x1009] = bytes.fromhex('83 7e 50 02 75 03 31 c0 c3')
        self.assertEqual(self.analyze(data)[1], 'original')

    def test_modern_profiles_require_the_coverage_decoder(self):
        meta, data = self.case()
        with patch.object(flow, 'capstone', None):
            self.assertEqual(self.analyze(data)[1], 'fail')

    def test_overlapping_edits_at_different_addresses_are_rejected(self):
        sites = [ctl.Site('N1', 0, 30, 10, b'abcdef', b'ghijkl', 'original', ''),
                 ctl.Site('N2', 0, 30, 12, b'cd', b'ij', 'original', '')]
        with self.assertRaisesRegex(SystemExit, 'overlap'):
            ctl.pending_patch_sites(sites)


if __name__ == '__main__':
    unittest.main()
