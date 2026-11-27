"""The startup helper survives boolean instruction width changes."""
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

import capstone
import mv2flow as flow


class StartupHelperTests(unittest.TestCase):
    def case(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures' /
                              'chrome-linux-canary-160.0.8186.0-helper.json').read_text())
        code = bytes.fromhex(fixture['hex'])
        data = bytearray(b'\xcc' * 0x1000)
        data[0x100:0x100 + len(code)] = code
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for ins in cs.disasm(code, 0x100):
            if ins.mnemonic == 'call':
                struct.pack_into('<i', data, ins.address + 1, 0x800 - ins.address - 5)
        return data

    def proofs(self, data):
        return flow.startup_helper_blocks(data, [SimpleNamespace(off=0, filesz=len(data))], set())

    def test_real_helper_and_patched_round_trip(self):
        data = self.case()
        proof, = self.proofs(data)
        self.assertEqual(proof.branch, 0x10f)
        self.assertEqual(proof.original, b'\x74\x57')
        data[proof.branch:proof.branch + 2] = proof.replacement
        patched, = self.proofs(data)
        self.assertEqual(patched.state, 'patched')
        self.assertEqual(patched.original, proof.original)

    def test_older_byte_test_with_shorter_instruction_is_also_proven(self):
        data = self.case()
        offset = data.index(bytes.fromhex('41 f6 c6 01'))
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        instructions = list(cs.disasm(bytes(data[0x100:0x264]), 0x100))
        data[offset:offset + 4] = bytes.fromhex('45 84 f6')
        def relocated(address):
            return address - (address >= offset + 4)
        for ins in instructions:
            if (ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)) and ins.imm_size:
                target = ins.operands[0].imm
                displacement = relocated(target) - relocated(ins.address) - ins.size
                start = relocated(ins.address) + ins.imm_offset
                data[start:start + ins.imm_size] = displacement.to_bytes(ins.imm_size, 'little', signed=True)
        proof, = self.proofs(data)
        self.assertEqual(proof.original, bytes.fromhex('74 56'))

    def test_near_gate_does_not_depend_on_fixed_displacements(self):
        data = self.case()
        branch = 0x10f
        data[branch:branch + 2] = bytes.fromhex('0f 84 57 00 00 00')
        proof, = self.proofs(data)
        self.assertEqual(proof.original, bytes.fromhex('0f 84 57 00 00 00'))
        data[branch:branch + 6] = proof.replacement
        patched, = self.proofs(data)
        self.assertEqual(patched.state, 'patched')
        self.assertEqual(patched.original, proof.original)

    def test_policy_edges_and_reason_must_match(self):
        original = self.case()
        for needle in (bytes.fromhex('75 a0'), bytes.fromhex('75 86'),
                       bytes.fromhex('74 05'), bytes.fromhex('74 09'),
                       bytes.fromhex('0f 85 78 ff ff ff'),
                       bytes.fromhex('ba 00 00 80 00')):
            with self.subTest(needle=needle.hex()):
                data = bytearray(original)
                offset = data.index(needle)
                data[offset + 1] ^= 1
                self.assertFalse(self.proofs(data))

    def test_other_bit_masks_and_mismatched_extension_are_rejected(self):
        for needle, offset in ((bytes.fromhex('41 f6 c6 01'), 3),
                               (bytes.fromhex('48 89 75 e8'), 3),
                               (bytes.fromhex('48 8b 7d e8'), 3)):
            with self.subTest(needle=needle.hex()):
                data = self.case()
                data[data.index(needle) + offset] ^= 2
                self.assertFalse(self.proofs(data))
