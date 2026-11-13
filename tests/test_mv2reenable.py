"""Operand/control-flow proofs for extra inlined Chrome 160 re-enable gates."""
import json
from pathlib import Path
import struct
import unittest

import mv2ctl as ctl
import test_mv2flow as block_tests


class InlinedReenableTests(unittest.TestCase):
    def case(self, copies=1):
        _, data = block_tests.MultipleBlockTests().case()
        fixture = json.loads((Path(__file__).parent / 'fixtures' /
                              'chrome-linux-160-inlined-reenable.json').read_text())
        entry, detail = bytes.fromhex(fixture['entry_hex']), bytes.fromhex(fixture['detail_hex'])
        delta = int(fixture['detail_offset'], 16) - int(fixture['entry_offset'], 16)
        for off in (0x2800, 0x3200)[:copies]:
            data[off:off + len(entry)] = entry
            data[off + delta:off + delta + len(detail)] = detail
            # Relocate the direct insertion call to executable fixture code.
            call = off + len(entry) - 5
            struct.pack_into('<i', data, call + 1, 0x1000 - call - 5)
        return data, 0x2800, delta

    def test_multiple_independent_inlined_gates_and_patched_recognition(self):
        data, _, _ = self.case(copies=2)
        sites, state, _ = block_tests.MultipleBlockTests().analyze(data)
        self.assertEqual(state, 'original')
        self.assertEqual(len([s for s in sites if s.kind == 'N4']), 3)
        for site in ctl.pending_patch_sites(sites):
            data[site.jpos:site.jpos + len(site.new)] = site.new
        sites, state, _ = block_tests.MultipleBlockTests().analyze(data)
        self.assertEqual(state, 'patched')
        self.assertEqual(len([s for s in sites if s.kind == 'N4']), 3)

    def test_register_allocation_changes_preserve_the_same_proof(self):
        data, off, delta = self.case()
        # RCX object -> RBX, EAX type -> ESI, ECX location -> EDI.
        data[off + 1] = 0x7b
        start = off + delta
        block = bytes(data[start:start + 71])
        for old, new in (('488b9128020000', '488b9328020000'),
                         ('8b4250', '8b7250'), ('80b90802000000', '80bb0802000000'),
                         ('8b8a88000000', '8bba88000000'), ('83f908', '83ff08'),
                         ('0fa3ca', '0fa3fa'), ('83f80a', '83fe0a'), ('83f805', '83fe05')):
            block = block.replace(bytes.fromhex(old), bytes.fromhex(new))
        data[start:start + len(block)] = block
        sites, state, _ = block_tests.MultipleBlockTests().analyze(data)
        self.assertEqual(state, 'original')
        self.assertIn(off + 4, [s.jpos for s in sites if s.kind == 'N4'])

    def test_changed_fields_masks_reason_or_edges_are_rejected(self):
        data, off, delta = self.case()
        detail = bytes(data[off + delta:off + delta + 71])
        positions = [off + 6, off + 16, off + delta + 3,
                     off + delta + detail.index(bytes.fromhex('0a010000')),
                     off + delta + detail.index(bytes.fromhex('0f87')) + 2,
                     off + delta + len(detail) - 4]
        for position in positions:
            with self.subTest(position=position):
                broken = bytearray(data)
                broken[position] ^= 1
                sites, _ = ctl.find_sites(broken, ctl.parse_exec_segments(broken))
                # A damaged proof must never authorize this extra edit, even
                # if the coverage alarm cannot classify the mutated policy.
                self.assertNotIn(off + 4, [s.jpos for s in sites])


if __name__ == '__main__':
    unittest.main()
