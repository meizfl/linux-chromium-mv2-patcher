"""Register-independent predicates, collection edges, and Windows re-enable ABI."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

import capstone
import mv2ctl as ctl
import test_mv2flow as blocks
from test_mv2resources import pack_message


class WindowsDecoded160Tests(unittest.TestCase):
    def case(self):
        _, data = blocks.MultipleBlockTests().case('PE')
        data[0x200:] = b'\xcc' * (len(data) - 0x200)
        meta = json.loads((Path(__file__).parent / 'fixtures' /
                           'chrome-win64-canary-160.0.8159.0-decoded.json').read_text())
        for window in meta['windows']:
            off = int(window['test_offset'], 16)
            code = bytes.fromhex(window['hex'])
            data[off:off + len(code)] = code
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        for window in meta['windows']:
            off = int(window['test_offset'], 16)
            if window['kind'] == 'N6-new':
                head = list(decoder.disasm(bytes(data[off:off + 32]), off, count=3))
                branch = head[-1].address + head[-1].size
                detail = ctl.decode_jump(data, branch)[0]
                call = list(decoder.disasm(bytes(data[detail:detail + 200]), detail, count=23))[18]
                self.assertEqual(call.mnemonic, 'call')
                struct.pack_into('<i', data, call.address + 1, 0x200 - call.address - 5)
            if window['kind'] == 'N4-new':
                call = list(decoder.disasm(bytes(data[off + 10:off + 90]), off + 10, count=6))[-1]
                self.assertEqual(call.mnemonic, 'call')
                struct.pack_into('<i', data, call.address + 1, 0x200 - call.address - 5)
        data[0x200] = 0xc3
        return meta, data

    def analyze(self, data):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'chrome.dll'
            p.write_bytes(data)
            (p.parent / 'Locales').mkdir()
            (p.parent / 'Locales' / 'en-US.pak').write_bytes(pack_message(0x14a0))
            with contextlib.redirect_stdout(io.StringIO()):
                return ctl.analyze(p, with_discovery=False)

    def test_all_nine_edits_and_patched_recognition(self):
        _, data = self.case()
        sites, state, _ = self.analyze(data)
        self.assertEqual(state, 'original')
        self.assertEqual(len([s for s in sites if s.kind == 'N1']), 2)
        self.assertEqual(len([s for s in sites if s.kind == 'N4']), 2)
        pending = ctl.pending_patch_sites(sites)
        self.assertEqual(len(pending), 9)
        for site in pending:
            data[site.jpos:site.jpos + len(site.new)] = site.new
        self.assertEqual(self.analyze(data)[1], 'patched')

    def test_equivalent_xor_encoding_is_proved_but_unknown_sub_is_refused(self):
        _, data = self.case()
        data[0x906] = 0x33
        self.assertEqual(self.analyze(data)[1], 'original')
        data[0x906] = 0x29
        self.assertEqual(self.analyze(data)[1], 'fail')

    def test_return_register_cannot_also_hold_the_type_value(self):
        _, data = self.case()
        off = 0x900
        code = bytes(data[off:off + 69])
        code = code.replace(bytes.fromhex('8b5050'), bytes.fromhex('8b4050'))
        code = code.replace(bytes.fromhex('83fa05'), bytes.fromhex('83f805'))
        code = code.replace(bytes.fromhex('83fa0a'), bytes.fromhex('83f80a'))
        data[off:off + len(code)] = code
        self.assertEqual(self.analyze(data)[1], 'fail')

    def test_collection_reason_and_iterator_edges_are_mandatory(self):
        _, data = self.case()
        sites, _, _ = self.analyze(data)
        site = next(s for s in sites if s.kind == 'N6')
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        safe = site.jpos + 6
        loop = list(decoder.disasm(bytes(data[safe:safe + 80]), safe, count=9))
        detail = ctl.decode_jump(data, site.jpos)[0]
        policy = list(decoder.disasm(bytes(data[detail:detail + 200]), detail, count=23))
        reason = data.find(bytes.fromhex('c70000008000'), safe, detail)
        positions = [reason + 2, loop[-1].address + loop[-1].imm_offset,
                     policy[6].address + policy[6].imm_offset,
                     policy[-2].address + policy[-2].size - 1]
        for position in positions:
            broken = bytearray(data)
            broken[position] ^= 1
            with self.subTest(position=position):
                self.assertEqual(self.analyze(broken)[1], 'fail')

    def test_extra_reenable_gate_cannot_hide_behind_required_minimum(self):
        _, data = self.case()
        # Disagreeing last Windows argument invalidates the insertion proof.
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        instructions = list(decoder.disasm(bytes(data[0x300a:0x3050]), 0x300a, count=6))
        last_argument = instructions[-2]
        data[last_argument.address + last_argument.size - 1] ^= 1
        self.assertEqual(self.analyze(data)[1], 'fail')


if __name__ == '__main__':
    unittest.main()
