"""Shared Linux/Windows collection proofs and backup-preserving upgrades."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import capstone
import mv2ctl as ctl
import test_mv2flow as blocks
from test_mv2resources import pack_message


class LinuxCollectionMigrationTests(unittest.TestCase):
    def case(self):
        _, data = blocks.MultipleBlockTests().case('ELF')
        data[0x4000:] = b'\xcc' * (len(data) - 0x4000)
        fixture = json.loads((Path(__file__).parent / 'fixtures' /
                              'chrome-linux-canary-160.0.8159.0-collection.json').read_text())
        code = bytes.fromhex(fixture['hex'])
        data[0x4000:0x4000 + len(code)] = code
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        head = list(decoder.disasm(bytes(data[0x4000:0x4030]), 0x4000, count=3))
        branch = head[-1].address + head[-1].size
        detail = ctl.decode_jump(data, branch)[0]
        instructions = list(decoder.disasm(bytes(data[detail:detail + 160]), detail, count=19))
        call = instructions[-3]
        self.assertEqual(call.mnemonic, 'call')
        struct.pack_into('<i', data, call.address + 1, 0x1000 - call.address - 5)
        return data, branch, detail, instructions

    def write_case(self, directory, data):
        root = Path(directory)
        source = root / 'chrome'
        source.write_bytes(data)
        locale = root / 'locales'
        locale.mkdir()
        # The surrounding family windows are the existing validated fixture;
        # only collection code comes from the exact 8159 Linux binary.
        rule = next(r for r in ctl.R159_INSTALL if r[0] == 'ELF')
        detail = rule[2].search(data)
        rid = struct.unpack_from('<I', data, detail.start('resource'))[0]
        (locale / 'en-US.pak').write_bytes(pack_message(rid))
        return source

    def analyze(self, data, verbose=False):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_case(directory, data)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = ctl.analyze(source, verbose=verbose, with_discovery=False)
            return result, output.getvalue()

    def test_linux_collection_original_and_patched_recognition(self):
        data, branch, _, _ = self.case()
        (sites, state, _), _ = self.analyze(data)
        self.assertEqual(state, 'original')
        collection = next(s for s in sites if s.kind == 'N6')
        self.assertEqual(collection.jpos, branch)
        self.assertEqual(len(ctl.pending_patch_sites(sites)), 7)
        for site in ctl.pending_patch_sites(sites):
            data[site.jpos:site.jpos + len(site.new)] = site.new
        (sites, state, _), _ = self.analyze(data)
        self.assertEqual(state, 'patched')

    def test_missing_proof_reports_role_and_unknown_branch(self):
        data, branch, _, _ = self.case()
        data[0x4002] ^= 1  # 0x10A mask becomes a different value.
        (_, state, _), output = self.analyze(data, verbose=True)
        self.assertEqual(state, 'fail')
        self.assertIn('Missing roles: N6 0/1', output)
        self.assertIn(f'file_off=0x{branch:X}', output)
        self.assertNotIn('expected site counts: {', output)

    def test_restore_slot_and_policy_edges_are_mandatory(self):
        data, _, detail, instructions = self.case()
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        block = list(decoder.disasm(bytes(data[detail:detail + 160]), detail, count=19))
        positions = [block[-2].address + block[-2].size - 1,
                     block[6].address + block[6].imm_offset,
                     block[-1].address + block[-1].imm_offset]
        for position in positions:
            with self.subTest(position=position):
                broken = bytearray(data)
                broken[position] ^= 1
                self.assertEqual(self.analyze(broken)[0][1], 'fail')

    def partial_case(self, directory):
        data, _, _, _ = self.case()
        (sites, _, _), _ = self.analyze(data)
        original = bytes(data)
        for site in ctl.pending_patch_sites(sites):
            if site.kind != 'N6':
                data[site.jpos:site.jpos + len(site.new)] = site.new
        source = self.write_case(directory, data)
        backup = Path(str(source) + ctl.BACKUP_SUFFIX)
        backup.write_bytes(original)
        return source, backup, original

    def test_apply_completes_partial_patch_without_replacing_original_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            source, backup, original = self.partial_case(directory)
            output = io.StringIO()
            with patch.object(ctl, 'check_size'), patch.object(ctl, 'ensure_chromium_stopped'), contextlib.redirect_stdout(output):
                ctl.cmd_apply(str(source), True)
                self.assertEqual(ctl.analyze(source, with_discovery=False)[1], 'patched')
            self.assertIn('Validated migration plan: 1 pending edits; 6 already patched', output.getvalue())
            self.assertEqual(backup.read_bytes(), original)

    def test_foreign_backup_is_still_refused_without_changing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source, backup, original = self.partial_case(directory)
            before = source.read_bytes()
            foreign = bytearray(original)
            foreign[0x180] ^= 1  # Outside the ELF header and all patch ranges.
            backup.write_bytes(foreign)
            with patch.object(ctl, 'check_size'), patch.object(ctl, 'ensure_chromium_stopped'), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(SystemExit, 'not a verified original'):
                    ctl.cmd_apply(str(source), True)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(backup.read_bytes(), foreign)


if __name__ == '__main__':
    unittest.main()
