#!/usr/bin/env python3
"""
mv2patch.py — patch Chromium (Linux x86-64) on disk to restore Manifest V2 support.

  python3 mv2ctl.py analyze [BIN]             read-only; show detected sites
  sudo python3 mv2ctl.py apply [BIN]          back up and patch (atomic file replacement)
  sudo python3 mv2ctl.py restore [BIN]        restore the original from backup
  python3 mv2ctl.py status [BIN]              show binary status
  python3 mv2ctl.py repair-profile [PROFILE]  clear the MV2-disabled reason from extensions
  python3 mv2ctl.py launch [BIN] [-- ARGS]   launch a verified patched browser
  python3 mv2ctl.py install-shortcut [BIN]    create an application shortcut

BIN is auto-detected by default (/usr/lib/chromium/chromium).

How it works: the compiler inlined IsExtensionAffected() at several locations.
Each copy first checks "manifest_version > 2 -> unaffected." We make this branch
always take that path (as in the Windows version: jg -> jmp). Each copy is validated
against its full byte sequence and checked to ensure ALL "safe exits" lead to one target.
Any mismatch in the number or structure of sites aborts without writing (fail-closed).

Changes are written to a temporary copy, which atomically replaces the original (a running Chromium is left untouched).
"""
import hashlib
import mmap
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import shlex

from mv2profiles import (
    EXPECT,
    EXPECT_PROFILES,
    F,
    HDR,
    FLAGCHK,
    LOAD228,
    LOADLOC,
    LOADTYP,
    MASK_BT,
    RA,
    RB,
    RC,
    RC155,
    S_NEEDLE,
    S_LEAD,
    RS,
    RD,
    RD_ALT,
    RU,
    RU_ALT,
    R155_M,
    R155_M_ALT,
    R155_A1,
    R155_A2,
    R155_I,
    R155_D,
    R155_D_ALT,
    R155_U,
    RHASH,
    R158_V1,
    R158_V2,
    RWIN_V1,
    RWIN_V2,
    R155_S,
    WIN_SPLIT_V5,
    WIN_SPLIT_V5_ALT,
    WIN_SPLIT_V7,
    WIN_INTEGER_SPLIT,
    WIN_MUST_DISABLE_V5,
    WIN_MUST_DISABLE_V7,
    WIN_REENABLE_V5,
    WIN_REENABLE_V7,
    WIN_INSTALL_V5,
    WIN_INSTALL_V7,
    WIN_INSTALL_V8,
    WIN_INSTALL_V8_ERROR,
    WIN_INSTALL_V10_ERROR,
    WIN_INSTALL_V9_ERROR,
    WIN_INSTALL_V11_ERROR,
    WIN_INSTALL_V12_ERROR,
    WIN_INSTALL_V13_ERROR,
    WIN_INSTALL_V8_TYPES,
    WIN_EXTENSION_FILTER_V11,
    WIN_STARTUP_V5,
    WIN_STARTUP_V6,
    WIN_STARTUP_V11,
    WIN_STARTUP_TARGET_V5,
    WIN_STARTUP_TARGET_V6,
    WIN_STARTUP_TARGET_V11,
)

try:
    import capstone
    CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
except Exception:
    CS = None

AUTO_PATHS = [
    "/usr/lib/chromium/chromium",
    "/usr/lib/chromium-browser/chromium-browser",
    "/usr/lib64/chromium-browser/chromium-browser",
    "/opt/google/chrome/chrome",
]
if sys.platform == "win32":
    AUTO_PATHS = [
        os.path.join(os.environ.get("PROGRAMFILES", r"C:\\Program Files"), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("PROGRAMFILES(X86)", r"C:\\Program Files (x86)"), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Chromium", "Application", "chrome.exe"),
    ]
elif sys.platform == "darwin":
    AUTO_PATHS = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        os.path.expanduser("~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        os.path.expanduser("~/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ]
BACKUP_SUFFIX = ".mv2orig"

# ------------------------------------------------------------------ ELF
class Seg:
    def __init__(self, off, vaddr, filesz):
        self.off, self.vaddr, self.filesz = off, vaddr, filesz


def parse_exec_segments(mm):
    # Linux x86-64 Chromium is ELF. Chromium 158 Intel macOS uses the same
    # verified x86-64 instruction windows in executable Mach-O sections.
    if mm[:4] == b"\xcf\xfa\xed\xfe":  # MH_MAGIC_64, little-endian
        ncmds = struct.unpack_from("<I", mm, 16)[0]
        offset = 32
        segs = []
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", mm, offset)
            if cmdsize < 8 or offset + cmdsize > len(mm):
                raise SystemExit("Malformed Mach-O load command; refusing to inspect this file.")
            if cmd == 0x19 and cmdsize >= 72:  # LC_SEGMENT_64
                _cmd, _size, _name, vmaddr, _vmsize, fileoff, filesize, _maxprot, initprot, _nsects, _flags = struct.unpack_from(
                    "<II16sQQQQiiII", mm, offset)
                if initprot & 0x4 and filesize:
                    segs.append(Seg(fileoff, vmaddr, filesize))
            offset += cmdsize
        if not segs:
            raise SystemExit("Mach-O file has no executable segment; refusing to patch it.")
        return segs

    if mm[:2] == b"MZ":  # PE32+ x86-64
        peoff = struct.unpack_from("<I", mm, 0x3c)[0]
        if peoff + 24 > len(mm) or mm[peoff:peoff + 4] != b"PE\0\0":
            raise SystemExit("Malformed PE header; refusing to inspect this file.")
        machine, section_count = struct.unpack_from("<HH", mm, peoff + 4)
        optional_size = struct.unpack_from("<H", mm, peoff + 20)[0]
        optional = peoff + 24
        if machine != 0x8664 or optional_size < 112 or struct.unpack_from("<H", mm, optional)[0] != 0x20b:
            raise SystemExit("Only PE32+ x86-64 Chromium images have a supported binary profile.")
        image_base = struct.unpack_from("<Q", mm, optional + 24)[0]
        section = optional + optional_size
        segs = []
        for index in range(section_count):
            pos = section + index * 40
            if pos + 40 > len(mm):
                raise SystemExit("Truncated PE section table; refusing to inspect this file.")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", mm, pos + 8)
            characteristics = struct.unpack_from("<I", mm, pos + 36)[0]
            if characteristics & 0x20000000 and raw_size:
                if raw_offset + raw_size > len(mm):
                    raise SystemExit("PE section extends past end of file; refusing to inspect this file.")
                segs.append(Seg(raw_offset, image_base + virtual_address, raw_size))
        if not segs:
            raise SystemExit("PE file has no executable section; refusing to inspect it.")
        return segs

    # Keep unsupported formats fail-closed until their instruction layouts
    # have been independently validated.
    if mm[:4] != b"\x7fELF" or mm[4] != 2 or mm[5] != 1:
        if mm[:2] == b"MZ":
            fmt = "Windows PE"
        elif mm[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            fmt = "macOS Mach-O"
        else:
            fmt = "unknown"
        raise SystemExit(f"Detected {fmt} executable. This format/architecture has no validated patch profile; no changes were made.")
    e_phoff = struct.unpack_from("<Q", mm, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", mm, 54)
    segs = []
    for i in range(e_phnum):
        p_type, p_flags, p_off, p_vaddr, _pa, p_filesz, _ms, _al = struct.unpack_from(
            "<IIQQQQQQ", mm, e_phoff + i * e_phentsize)
        if p_type == 1 and (p_flags & 1) and p_filesz:
            segs.append(Seg(p_off, p_vaddr, p_filesz))
    return segs


def vaddr_of(segs, off):
    for s in segs:
        if s.off <= off < s.off + s.filesz:
            return s.vaddr + off - s.off
    return None


def decode_jump(mm, off):
    """Return (absolute file offset of target, length) for jmp/jcc; also handles nop+jmp."""
    b0 = mm[off]
    if 0x70 <= b0 <= 0x7f or b0 == 0xeb:
        rel = mm[off + 1]
        rel -= 256 if rel > 127 else 0
        return off + 2 + rel, 2
    if b0 == 0x0f and 0x80 <= mm[off + 1] <= 0x8f:
        rel = struct.unpack_from("<i", mm, off + 2)[0]
        return off + 6 + rel, 6
    if b0 == 0x90 and mm[off + 1] == 0xe9:
        rel = struct.unpack_from("<i", mm, off + 2)[0]
        return off + 6 + rel, 6
    return None


# ------------------------------------------------------------------ site discovery
class Site:
    def __init__(self, kind, start, end, jpos, orig, new, state, info):
        self.kind, self.start, self.end = kind, start, end
        self.jpos, self.orig, self.new, self.state, self.info = jpos, orig, new, state, info


def make_site(kind, mm, m, jname, orig, new, info):
    jpos = m.start(jname)
    cur = bytes(mm[jpos:jpos + len(orig)])
    state = "original" if cur == orig else "patched" if cur == new else "unknown"
    return Site(kind, m.start(), m.end(), jpos, orig, new, state, info)


def _win_short_target(mm, pos):
    return pos + 2 + struct.unpack_from("b", mm, pos + 1)[0]


def _win_rel32_target(mm, pos, length):
    return pos + length + struct.unpack_from("<i", mm, pos + length - 4)[0]


def _win_install_policy_valid(mm, seg, start, error_rx):
    end = seg.off + seg.filesz
    inside = lambda pos, size=1: seg.off <= pos and pos + size <= end
    normal = start + 54
    if (not inside(start, 90) or
            _win_short_target(mm, start + 4) != normal or
            _win_short_target(mm, start + 43) != normal or
            _win_short_target(mm, start + 23) != start + 40):
        return False
    types = _win_rel32_target(mm, start + 34, 6)
    if (not inside(types, 21) or
            not WIN_INSTALL_V8_TYPES.match(mm, types) or
            _win_rel32_target(mm, types + 3, 6) != start + 40 or
            _win_rel32_target(mm, types + 12, 6) != normal or
            _win_rel32_target(mm, types + 18, 5) != start + 40):
        return False
    error = _win_rel32_target(mm, start + 48, 6)
    if not inside(error, 46) or not error_rx.match(mm, error):
        return False
    shared = _win_rel32_target(mm, error + 35, 5)
    return (shared == start + 89 and inside(shared, 5) and
            bytes(mm[shared:shared + 5]) == b"\x41\x80\x7e\x17\x00")


def find_sites(mm, segs):
    sites, rejects = [], []
    for kind, rx, names in (("A", RA, ["j", "ja", "jae", "je"]),
                            ("B", RB, ["j", "ja", "jae", "je1", "je2"]),
                            ("C", RC, [])):
        for s in segs:
            for m in rx.finditer(mm, s.off, s.off + s.filesz):
                targets = {}
                bad = None
                for n in names:
                    d = decode_jump(mm, m.start(n))
                    if d is None:
                        bad = f"could not decode branch {n}"
                        break
                    targets[n] = d[0]
                if bad is None and len(set(targets.values())) > 1:
                    bad = "safe exits lead to different destinations: " + \
                          ", ".join(f"{k}->0x{v:X}" for k, v in targets.items())
                if bad:
                    rejects.append((kind, m.start(), bad))
                    continue
                info = ""
                if targets:
                    info = f"unaffected->vaddr 0x{vaddr_of(segs, targets['j']) or 0:X}"
                if kind == "A":
                    sites.append(make_site("A", mm, m, "j", b"\x7f", b"\xeb", info))
                elif kind == "B":
                    sites.append(make_site("B", mm, m, "j", b"\x0f\x8f", b"\x90\xe9", info))
                else:
                    sites.append(make_site("C", mm, m, "j", b"\x7e\x04", b"\x90\x90", "xor eax,eax path"))
    # Chromium 155 distro layout: same clear-result gate with two stack reloads.
    for s in segs:
        for m in RC155.finditer(mm, s.off, s.off + s.filesz):
            jpos = m.start("j")
            cur = bytes(mm[jpos:jpos + 2])
            target = jpos + 6
            safe_jump = decode_jump(mm, jpos + 4)
            if (bytes(mm[jpos + 2:jpos + 4]) != b"\x31\xc0" or
                    bytes(mm[jpos + 4:jpos + 6]) != b"\xeb\x40" or
                    not (s.off <= target < s.off + s.filesz) or
                    safe_jump is None or safe_jump[0] < s.off or safe_jump[0] + 6 > s.off + s.filesz or
                    bytes(mm[safe_jump[0]:safe_jump[0] + 6]) != b"\x88\x86\x93\x03\x00\x00"):
                rejects.append(("C", m.start(), "Chromium 155 clear-result path did not validate"))
                continue
            if cur == b"\x7e\x04":
                state = "original"
            elif cur == b"\x90\x90":
                state = "patched"
            else:
                rejects.append(("C", m.start(), "unknown Chromium 155 JLE bytes"))
                continue
            sites.append(Site("C", m.start(), m.end(), jpos, b"\x7e\x04", b"\x90\x90", state,
                              f"manifest gate -> verified zero-result path vaddr 0x{vaddr_of(segs, safe_jump[0]) or 0:X}"))
    # MV2-specific disable-reason helper, validated by its control-flow target
    # and by the 0x800000 reason-setting call on the fall-through path.
    for s in segs:
        for rx in (RD, RD_ALT):
            for m in rx.finditer(mm, s.off, s.off + s.filesz):
                jpos = m.start("j")
                decoded = decode_jump(mm, jpos)
                if decoded is None:
                    rejects.append(("D", m.start(), "could not decode manifest-version branch"))
                    continue
                target = decoded[0]
                fallthrough = jpos + 6
                call_limit = min(target, s.off + s.filesz)
                reason = b"\xba\x00\x00\x80\x00"
                reason_pos = mm.find(reason, fallthrough, call_limit)
                if reason_pos < 0 or mm[reason_pos + len(reason):reason_pos + len(reason) + 2] != b"\x67\xe8":
                    rejects.append(("D", m.start(), "no call with disable reason 0x800000 found in the bypassed branch"))
                    continue
                if not (s.off <= target < s.off + s.filesz):
                    rejects.append(("D", m.start(), "safe target is outside the executable segment"))
                    continue
                epilogue = bytes(mm[target:min(target + 48, s.off + s.filesz)])
                if b"\x48\x83\xc4" not in epilogue or b"\xc3" not in epilogue:
                    rejects.append(("D", m.start(), "branch target does not look like a function return"))
                    continue
                info = (f"skip MV2 disable reason 0x800000 -> vaddr "
                        f"0x{vaddr_of(segs, target) or 0:X}")
                sites.append(make_site("D", mm, m, "j", b"\x0f\x85", b"\x90\xe9", info))
    # MV2 availability gate: remove JLE so both manifest versions fall through
    # to the already-validated allowed path (xor r14d,r14d; jmp common return).
    for s in segs:
        for m in RU.finditer(mm, s.off, s.off + s.filesz):
            jpos = m.start("j")
            cur = bytes(mm[jpos:jpos + 2])
            detail = b"\x49\x8b\x8e\x28\x02\x00\x00\x8b\x41\x50"
            detail_pos = mm.find(detail, jpos + 2, min(jpos + 192, s.off + s.filesz))
            if detail_pos < 0:
                rejects.append(("U", m.start(), "detailed extension-location check not found"))
                continue
            allowed_jump = decode_jump(mm, jpos + 5)
            allowed_target = allowed_jump[0] if allowed_jump else None
            expected_allowed = b"\x80\x7d\xd7\x00"
            if (allowed_jump is None or allowed_target < s.off or
                    allowed_target >= s.off + s.filesz or
                    bytes(mm[allowed_target:allowed_target + len(expected_allowed)]) != expected_allowed):
                rejects.append(("U", m.start(), "allow path does not lead to the expected shared exit"))
                continue
            if cur[0] == 0x7e:
                disp = mm[jpos + 1]
                disp -= 256 if disp > 127 else 0
                target = jpos + 2 + disp
                if target != detail_pos:
                    rejects.append(("U", m.start(), "JLE does not branch directly to the detailed-check block"))
                    continue
                state = "original"
            elif cur == b"\x90\x90":
                state = "patched"
            else:
                rejects.append(("U", m.start(), "unrecognized bytes at JLE"))
                continue
            info = f"bypass UserMayLoad detail -> allowed vaddr 0x{vaddr_of(segs, allowed_target) or 0:X}"
            sites.append(Site("U", m.start(), m.end(), jpos,
                              b"\x7e" + bytes([mm[jpos + 1]]) if state == "original" else b"\x90\x90",
                              b"\x90\x90", state, info))
        for m in RU_ALT.finditer(mm, s.off, s.off + s.filesz):
            jpos = m.start("j")
            allowed_jump = decode_jump(mm, jpos + 5)
            allowed_target = allowed_jump[0] if allowed_jump else None
            detail = jpos + 2 + 0x51
            if (not (s.off <= detail and detail + 24 <= s.off + s.filesz) or
                    bytes(mm[detail:detail + 14]) !=
                    b"\x49\x8b\x8e\x28\x02\x00\x00\x8b\x41\x50\x41\x80\xbe\x08" or
                    allowed_target is None or not (s.off <= allowed_target < s.off + s.filesz) or
                    bytes(mm[allowed_target:allowed_target + 4]) != b"\xf6\x45\xc0\x01" or
                    mm.find(b"\xb8\x00\x00\x80\x00", detail,
                            min(detail + 0x80, s.off + s.filesz)) < 0):
                rejects.append(("U", m.start(), "alternate UserMayLoad detail/allowed paths did not validate"))
                continue
            cur = bytes(mm[jpos:jpos + 2])
            state = "original" if cur == b"\x7e\x51" else "patched" if cur == b"\x90\x90" else "unknown"
            sites.append(Site("U", m.start(), m.end(), jpos,
                              b"\x7e\x51" if state == "original" else b"\x90\x90", b"\x90\x90", state,
                              f"bypass MV2 UserMayLoad detail -> vaddr 0x{vaddr_of(segs, allowed_target) or 0:X}"))
    # Google Chrome 155+ ELF layout. The function shapes differ from Arch
    # Chromium 154, so recognize each role independently and validate its
    # branch destination and the companion MV2 logic before accepting it.
    def in_segment(seg, pos, length=1):
        return seg.off <= pos and pos + length <= seg.off + seg.filesz

    def target_for(seg, jpos):
        decoded = decode_jump(mm, jpos)
        if decoded is None or not in_segment(seg, decoded[0]):
            return None
        return decoded[0]

    def short_branch_site(kind, seg, match, expected_target, label):
        jpos = match.start("j")
        target = target_for(seg, jpos)
        target_options = expected_target if isinstance(expected_target, tuple) else (expected_target,)
        if target is None or not any(bytes(mm[target:target + len(option)]) == option
                                     for option in target_options):
            rejects.append((kind, match.start(), f"branch target does not match the expected path: {label}"))
            return
        cur = bytes(mm[jpos:jpos + 2])
        if cur[0] not in (0x7f, 0xeb):
            rejects.append((kind, match.start(), "unexpected short-branch opcode"))
            return
        state = "original" if cur[0] == 0x7f else "patched"
        sites.append(Site(kind, match.start(), match.end(), jpos, cur[:1], b"\xeb", state,
                          f"{label} -> vaddr 0x{vaddr_of(segs, target) or 0:X}"))

    for seg in segs:
        for m in R155_M.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            target = target_for(seg, jpos)
            fallthrough = jpos + len(m.group("j"))
            reason = mm.find(b"\xb8\x00\x00\x80\x00", fallthrough,
                             target if target is not None else seg.off + seg.filesz)
            if (target is None or bytes(mm[target:target + 4]) != b"\x45\x31\xf6\xeb" or
                    reason < 0 or mm.find(b"\x41\xb6\x01", reason, target) < 0):
                rejects.append(("M", m.start(), "MV2 affected path/disable reason or safe return target mismatch"))
                continue
            cur = bytes(mm[jpos:jpos + 2])
            state = "original" if cur[:2] == b"\x0f\x8f" else "patched" if cur[:2] == b"\x90\xe9" else "unknown"
            sites.append(Site("M", m.start(), m.end(), jpos, b"\x0f\x8f", b"\x90\xe9", state,
                              f"MustRemainDisabled false-return path -> vaddr 0x{vaddr_of(segs, target) or 0:X}"))

        for m in R155_M_ALT.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            target = target_for(seg, jpos)
            reason = (mm.find(b"\xba\x00\x00\x80\x00\xe8", m.end(), target)
                      if target is not None else -1)
            if (target is None or
                    bytes(mm[target:target + 9]) != b"\x64\x48\x8b\x04\x25\x28\x00\x00\x00" or
                    reason < 0):
                rejects.append(("M", m.start(), "MustRemainDisabled clone exit or 0x800000 path did not validate"))
                continue
            cur = bytes(mm[jpos:jpos + 6])
            state = "original" if cur[:2] == b"\x0f\x85" else "patched" if cur[:2] == b"\x90\xe9" else "unknown"
            sites.append(Site("M", m.start(), m.end(), jpos, b"\x0f\x85", b"\x90\xe9", state,
                              f"MustRemainDisabled MV2-only path -> vaddr 0x{vaddr_of(segs, target) or 0:X}"))

        for m in R155_A1.finditer(mm, seg.off, seg.off + seg.filesz):
            short_branch_site("A", seg, m,
                              (b"\x48\x8b\x46\x08", b"\x49\x8b\x45\x08"),
                              "extension-overload checker")
        for m in R155_A2.finditer(mm, seg.off, seg.off + seg.filesz):
            short_branch_site("A", seg, m, b"\x4c\x8d\x65\xc0", "second extension-overload checker")
        for m in R155_I.finditer(mm, seg.off, seg.off + seg.filesz):
            short_branch_site("I", seg, m, b"\x31\xc0\xeb\xfb", "integer-argument checker false return")

        for m in R155_D.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            target = target_for(seg, jpos)
            if (target is None or
                    bytes(mm[target:target + 7]) != b"\x48\x83\xc4\x28\x5b\x41\x5e"):
                rejects.append(("D", m.start(), "ReEnablePolicy return target or type checks did not validate"))
                continue
            cur = bytes(mm[jpos:jpos + 2])
            state = "original" if cur[:2] == b"\x0f\x85" else "patched" if cur[:2] == b"\x90\xe9" else "unknown"
            sites.append(Site("D", m.start(), m.end(), jpos, b"\x0f\x85", b"\x90\xe9", state,
                              f"bypass MV2-only re-enable detail -> vaddr 0x{vaddr_of(segs, target) or 0:X}"))

        for m in R155_D_ALT.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            target = target_for(seg, jpos)
            reason = mm.find(b"\xc7\x00\x00\x00\x80\x00", m.end(),
                             min(m.start() + 0x500, seg.off + seg.filesz))
            if (target is None or bytes(mm[target:target + 6]) != b"\x49\x8b\x47\x08\x48\x85" or
                    reason < 0):
                rejects.append(("D", m.start(), "disable-list next-item or 0x800000 path did not validate"))
                continue
            cur = bytes(mm[jpos:jpos + 6])
            state = "original" if cur[:2] == b"\x0f\x8f" else "patched" if cur[:2] == b"\x90\xe9" else "unknown"
            sites.append(Site("D", m.start(), m.end(), jpos, b"\x0f\x8f", b"\x90\xe9", state,
                              f"skip MV2 disable-list insertion -> vaddr 0x{vaddr_of(segs, target) or 0:X}"))

        for m in R155_U.finditer(mm, seg.off, seg.off + seg.filesz):
            short_branch_site("U", seg, m, b"\x48\x8d\x1d", "UserMayInstall normal policy path")

        for m in RHASH.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            target = target_for(seg, jpos)
            if target is None or bytes(mm[target:target + 4]) != b"\xb0\x01\x5d\xc3":
                rejects.append(("H", m.start(), "ContentHash return-true target did not validate"))
                continue
            cur = bytes(mm[jpos:jpos + 2])
            if cur == b"\x75\x0a":
                state = "ignored"
            elif cur == b"\xeb\x0a":
                rejects.append(("H", m.start(), "ContentHash gate was changed by an older patch; restore the original binary"))
                continue
            else:
                rejects.append(("H", m.start(), "unknown ContentHash branch bytes"))
                continue
            sites.append(Site("H", m.start(), m.end(), jpos, cur, cur, state,
                              f"preserve signed-resource hash filter -> vaddr 0x{vaddr_of(segs, target) or 0:X}"))

        for m in R158_V1.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            cur = bytes(mm[jpos:jpos + 2])
            safe = decode_jump(mm, jpos + 4)
            safe_target = safe[0] if safe else None
            detail_ok = (bytes(mm[jpos + 6:jpos + 9]) == b"\x89\xc1\x31" and
                         bytes(mm[jpos + 9:jpos + 13]) == b"\xc0\x83\xfb\x08")
            safe_ok = (safe_target is not None and in_segment(seg, safe_target, 11) and
                       bytes(mm[safe_target:safe_target + 11]) ==
                       b"\x48\x83\xc4\x08\x5b\x41\x5e\x41\x5f\x5d\xc3")
            if not detail_ok or not safe_ok:
                rejects.append(("V", m.start(), "Extension IsExtensionAffected branch paths did not validate"))
                continue
            if cur == b"\x7e\x04":
                state = "original"
            elif cur == b"\x90\x90":
                state = "patched"
            else:
                rejects.append(("V", m.start(), "Extension IsExtensionAffected: unknown branch bytes"))
                continue
            sites.append(Site("V", m.start(), m.end(), jpos, b"\x7e\x04", b"\x90\x90", state,
                              f"Extension IsExtensionAffected clear-result path -> vaddr "
                              f"0x{vaddr_of(segs, safe_target) or 0:X}"))

        for m in R158_V2.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            cur = bytes(mm[jpos:jpos + 2])
            target = target_for(seg, jpos)
            if target is None or bytes(mm[target:target + 2]) != b"\x5d\xc3":
                rejects.append(("V", m.start(), "scalar IsExtensionAffected unaffected return did not validate"))
                continue
            if cur == b"\x7f\x1d":
                state = "original"
            elif cur == b"\xeb\x1d":
                state = "patched"
            else:
                rejects.append(("V", m.start(), "scalar IsExtensionAffected: unknown branch bytes"))
                continue
            sites.append(Site("V", m.start(), m.end(), jpos, b"\x7f\x1d", b"\xeb\x1d", state,
                              f"scalar IsExtensionAffected unaffected return -> vaddr "
                              f"0x{vaddr_of(segs, target) or 0:X}"))

        for m in RWIN_V1.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            cur = bytes(mm[jpos:jpos + 2])
            detail = target_for(seg, jpos) if cur == b"\x7e\x04" else jpos + 6
            safe = decode_jump(mm, jpos + 4)
            safe_target = safe[0] if safe else None
            if (detail != m.start() + 10 or
                    bytes(mm[detail:detail + 3]) != b"\x89\xc1\x31" or
                    safe_target is None or not in_segment(seg, safe_target, 7) or
                    bytes(mm[safe_target:safe_target + 7]) != b"\x48\x83\xc4\x28\x5f\x5e\xc3"):
                rejects.append(("V", m.start(), "Windows extension-overload branch destinations did not validate"))
                continue
            state = "original" if cur == b"\x7e\x04" else "patched" if cur == b"\x90\x90" else "unknown"
            sites.append(Site("V", m.start(), m.end(), jpos, b"\x7e\x04", b"\x90\x90", state,
                              f"Windows extension IsExtensionAffected clear-result -> vaddr "
                              f"0x{vaddr_of(segs, safe_target) or 0:X}"))

        for m in RWIN_V2.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            # This scalar checker is covered by the more specific Windows
            # integer-overload rule below; avoid writing the same byte twice.
            if mm[:2] == b"MZ" and any(
                    candidate.start() + 5 == jpos
                    for candidate in WIN_INTEGER_SPLIT.finditer(mm, seg.off, seg.off + seg.filesz)):
                continue
            cur = bytes(mm[jpos:jpos + 2])
            target = target_for(seg, jpos)
            if target is None or not in_segment(seg, target, 1) or mm[target] != 0xc3:
                rejects.append(("V", m.start(), "Windows scalar IsExtensionAffected return target did not validate"))
                continue
            if cur == b"\x7f\x1f":
                state = "original"
            elif cur == b"\xeb\x1f":
                state = "patched"
            else:
                state = "unknown"
            sites.append(Site("V", m.start(), m.end(), jpos, b"\x7f\x1f", b"\xeb\x1f", state,
                              f"Windows scalar IsExtensionAffected unaffected return -> vaddr "
                              f"0x{vaddr_of(segs, target) or 0:X}"))

        for m in R155_S.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            if any(site.kind == "A" and site.jpos == jpos for site in sites):
                continue
            cur = bytes(mm[jpos:jpos + 2])
            fallthrough = jpos + 2
            target = target_for(seg, jpos) if cur[1] != 0 else None
            next_item = (b"\x49\x8b\x7e\x18", b"\x4d\x8b\x76\x18")
            target_ok = (target is not None and any(bytes(mm[target:target + len(op)]) == op
                                                     for op in next_item))
            patched_ok = cur == b"\x7f\x00" and any(
                mm.find(op, fallthrough, min(fallthrough + 128, seg.off + seg.filesz)) >= 0
                for op in next_item)
            if not (target_ok or patched_ok):
                rejects.append(("S", m.start(), "startup disable target does not match the validated helper"))
                continue
            state = "patched" if patched_ok else "original"
            sites.append(Site("S", m.start(), m.end(), jpos, b"\x7f" + cur[1:2] if not patched_ok else b"\x7f\x00",
                              b"\x7f\x00", state,
                              "neutralize version branch before the verified 0x800000 disable-reason helper"))
    # Startup branch
    for s in segs:
        pos = s.off
        end = s.off + s.filesz
        while True:
            n = mm.find(S_NEEDLE, pos, end)
            if n < 0:
                break
            pos = n + 1
            st = n - S_LEAD
            if st < s.off:
                continue
            window = bytes(mm[st:st + 120])
            m = RS.match(window)
            if not m:
                continue
            jpos = st + m.start("j")
            # Some Chrome 155 layouts place the startup version branch at
            # the same instruction as an already-validated extension checker.
            # The A patch jumps over the policy detail path; do not emit a
            # conflicting second edit for that byte range.
            if any(site.kind == "A" and site.jpos == jpos for site in sites):
                continue
            d = decode_jump(mm, jpos)
            cur = bytes(mm[jpos:jpos + 2])
            state = "original" if cur == b"\x0f\x84" else "patched" if cur == b"\x90\xe9" else "unknown"
            sites.append(Site("S", st, st + m.end(), jpos, b"\x0f\x84", b"\x90\xe9", state,
                              f"skip->vaddr 0x{vaddr_of(segs, d[0]) or 0:X}" if d else ""))
    # Chrome 152/155 also have compiler-generated install, disable, and
    # re-enable clones. Validate the complete family before recognizing PE.
    if mm[:2] == b"MZ":
        for seg in segs:
            lo, hi = seg.off, seg.off + seg.filesz
            is158_8106 = WIN_INSTALL_V12_ERROR.search(mm, lo, hi) is not None
            is158 = (is158_8106 or
                     WIN_INSTALL_V11_ERROR.search(mm, lo, hi) is not None)
            split7 = list(WIN_SPLIT_V7.finditer(mm, lo, hi))
            split5 = sorted(
                [*WIN_SPLIT_V5.finditer(mm, lo, hi), *WIN_SPLIT_V5_ALT.finditer(mm, lo, hi)],
                key=lambda match: match.start())
            if not split7 and not split5:
                continue
            is155 = bool(split7)
            family = "Chrome 158" if is158 else "Chrome 155" if is155 else "Chrome 152"
            splits = split7 if is155 else split5
            if is158 and not is158_8106:
                filters = list(WIN_EXTENSION_FILTER_V11.finditer(mm, lo, hi))
                if len(filters) != 1:
                    rejects.append(("A", splits[0].start(), f"{family}: expected one extension filter, found {len(filters)}"))
                else:
                    m = filters[0]; j = m.start() + 5; target = _win_short_target(mm, j)
                    if (not (lo <= target and target + 9 <= hi) or
                            bytes(mm[target:target + 9]) != b"\x48\x8b\x51\x08\x48\x85\xd2\x0f\x85"):
                        rejects.append(("A", m.start(), "extension filter does not branch to the verified next-item path"))
                    else:
                        cur = bytes(mm[j:j + 1]); state = "original" if cur == b"\x7f" else "patched" if cur == b"\xeb" else "unknown"
                        sites.append(Site("A", m.start(), m.end(), j, b"\x7f", b"\xeb", state,
                                          f"{family} extension-version filter"))
            if len(splits) != 2:
                rejects.append(("W1", splits[0].start(), f"{family}: expected two Extension checker copies, found {len(splits)}"))
                continue
            for m in splits:
                j = m.start() + 4
                target = _win_short_target(mm, j)
                if not (lo <= target and target + 4 <= hi and mm[target] == 0x31 and mm[target + 2] == 0xeb):
                    rejects.append(("W1", m.start(), "Extension checker does not reach its false-return block"))
                    continue
                cur = bytes(mm[j:j + 1])
                state = "original" if cur == b"\x7f" else "patched" if cur == b"\xeb" else "unknown"
                sites.append(Site("W1", m.start(), m.end(), j, b"\x7f", b"\xeb", state,
                                  f"{family} split Extension checker false return"))

            integers = list(WIN_INTEGER_SPLIT.finditer(mm, lo, hi))
            if len(integers) != 1:
                rejects.append(("W2", splits[0].start(), f"{family}: expected one integer checker, found {len(integers)}"))
            else:
                m = integers[0]; j = m.start() + 5; target = _win_short_target(mm, j)
                if not (lo <= target < hi and mm[target] == 0xc3):
                    rejects.append(("W2", m.start(), "integer checker target is not the shared RET"))
                else:
                    cur = bytes(mm[j:j + 1]); state = "original" if cur == b"\x7f" else "patched" if cur == b"\xeb" else "unknown"
                    sites.append(Site("W2", m.start(), m.end(), j, b"\x7f", b"\xeb", state,
                                      f"{family} integer checker false return"))

            disable_rx = WIN_MUST_DISABLE_V7 if is155 else WIN_MUST_DISABLE_V5
            disabled = list(disable_rx.finditer(mm, lo, hi))
            if len(disabled) != 1:
                rejects.append(("W3", splits[0].start(), f"{family}: expected one MustRemainDisabled clone, found {len(disabled)}"))
            else:
                m = disabled[0]; j = m.start() + 4; cur = bytes(mm[j:j + 2])
                state = "original" if cur == b"\x0f\x8f" else "patched" if cur == b"\x90\xe9" else "unknown"
                target = j + 6 + struct.unpack_from("<i", mm, j + 2)[0]
                reason = mm.find(b"\xb8\x00\x00\x80\x00", j, min(j + 128, hi)) >= 0
                if (state == "unknown" or not (lo <= target and target + 3 <= hi) or
                        mm[target] != 0x31 or mm[target + 2] != 0xeb or not reason):
                    rejects.append(("W3", m.start(), "MustRemainDisabled false-return/0x800000 path did not validate"))
                else:
                    sites.append(Site("W3", m.start(), m.end(), j, b"\x0f\x8f", b"\x90\xe9", state,
                                      f"{family} MustRemainDisabled clone false return"))

            reenable_rx = WIN_REENABLE_V7 if is155 else WIN_REENABLE_V5
            reenable = list(reenable_rx.finditer(mm, lo, hi))
            if len(reenable) != 1:
                rejects.append(("W4", splits[0].start(), f"{family}: expected one re-enable clone, found {len(reenable)}"))
            else:
                m = reenable[0]; j = m.start() + 4; target = _win_short_target(mm, j)
                if not (lo <= target and target + 2 <= hi and bytes(mm[target:target + 2]) == b"\x48\x8b"):
                    rejects.append(("W4", m.start(), "re-enable branch misses disable-reason removal path"))
                else:
                    cur = bytes(mm[j:j + 1]); state = "original" if cur == b"\x7f" else "patched" if cur == b"\xeb" else "unknown"
                    sites.append(Site("W4", m.start(), m.end(), j, b"\x7f", b"\xeb", state, f"{family} re-enable clone"))

            install_rx = WIN_INSTALL_V8 if is155 else WIN_INSTALL_V5
            installs = list(install_rx.finditer(mm, lo, hi))
            if len(installs) != 1:
                rejects.append(("W5", splits[0].start(), f"{family}: expected one UserMayInstall clone, found {len(installs)}"))
            else:
                m = installs[0]; j = m.start() + 4; target = _win_short_target(mm, j)
                valid = lo <= target and target + 2 <= hi and bytes(mm[target:target + 2]) == b"\x4c\x8d"
                install_label = family
                if is155:
                    error_profiles = (
                        (WIN_INSTALL_V8_ERROR, "Chrome 155"),
                        (WIN_INSTALL_V9_ERROR, "Chrome 156"),
                        (WIN_INSTALL_V10_ERROR, "Chrome 157"),
                        (WIN_INSTALL_V11_ERROR, "Chrome 158"),
                        (WIN_INSTALL_V12_ERROR, "Chrome 158.0.8106"),
                        (WIN_INSTALL_V13_ERROR, "Chrome 156.0.8078.48"),
                    )
                    validated_error = next(
                        (label for error_rx, label in error_profiles
                         if _win_install_policy_valid(mm, seg, m.start(), error_rx)),
                        None)
                    valid = valid and validated_error is not None
                    if validated_error is not None:
                        install_label = validated_error
                if not valid:
                    rejects.append(("W5", m.start(), "UserMayInstall policy/error paths did not validate"))
                else:
                    cur = bytes(mm[j:j + 1]); state = "original" if cur == b"\x7f" else "patched" if cur == b"\xeb" else "unknown"
                    install_kind = {
                        "Chrome 157": "W5_157",
                        "Chrome 158": "W5_158",
                        "Chrome 158.0.8106": "W5_158_8106",
                        "Chrome 156.0.8078.48": "W5_156",
                    }.get(install_label, "W5")
                    sites.append(Site(install_kind, m.start(), m.end(), j, b"\x7f", b"\xeb", state,
                                      f"{install_label} UserMayInstall clone"))

            startup_v11 = is158 and not is158_8106
            startup_rx = WIN_STARTUP_V11 if startup_v11 else WIN_STARTUP_V6 if (is155 or is158_8106) else WIN_STARTUP_V5
            target_rx = WIN_STARTUP_TARGET_V11 if startup_v11 else WIN_STARTUP_TARGET_V6 if (is155 or is158_8106) else WIN_STARTUP_TARGET_V5
            startups = list(startup_rx.finditer(mm, lo, hi))
            if len(startups) != 1:
                rejects.append(("W6", splits[0].start(), f"{family}: expected one startup-disable branch, found {len(startups)}"))
            else:
                m = startups[0]; j = m.start() + 8; disp = bytes(mm[j + 2:j + 6])
                if bytes(mm[j:j + 2]) != b"\x0f\x85":
                    rejects.append(("W6", m.start(), "startup-disable opcode is not JNE"))
                elif disp == b"\0\0\0\0":
                    if len(list(target_rx.finditer(mm, lo, hi))) != 1:
                        rejects.append(("W6", m.start(), "patched startup branch has no unique disable-reason loop"))
                    else:
                        sites.append(Site("W6", m.start(), m.end(), j + 2, disp, b"\0" * 4, "patched", f"{family} startup disable branch"))
                else:
                    target = j + 6 + struct.unpack_from("<i", disp)[0]
                    if not (lo <= target and target_rx.match(mm, target)):
                        rejects.append(("W6", m.start(), "startup branch misses verified 0x800000 loop"))
                    else:
                        sites.append(Site("W6", m.start(), m.end(), j + 2, disp, b"\0" * 4, "original", f"{family} startup disable branch"))
    sites.sort(key=lambda x: x.start)
    return sites, rejects


# ------------------------------------------------------------------ output
def hexs(b):
    return " ".join(f"{x:02X}" for x in b)


def dump(mm, segs, off, before, after, title):
    start = max(0, off - before)
    data = bytes(mm[start:off + after])
    va = vaddr_of(segs, off)
    print(f"--- {title} file_off=0x{off:X} vaddr={'0x%X' % va if va else '?'}")
    print("hex: " + hexs(data))
    if CS:
        base = vaddr_of(segs, start) or 0
        for ins in CS.disasm(data, base):
            print(f"  {ins.address:#x}: {ins.mnemonic:<6} {ins.op_str}")
    print()


def discover(mm, segs, sites):
    """Show similar but unclassified sites; share them to help refine the rules."""
    spans = [(s.start - 4, s.end + 4) for s in sites]

    def inside(o):
        return any(a <= o < b for a, b in spans)

    print("=== Similar unclassified sites (share this section) ===")
    shown = 0
    cmp_rx = re.compile(HDR)
    for s in segs:
        for m in cmp_rx.finditer(mm, s.off, s.off + s.filesz):
            o = m.start()
            if inside(o):
                continue
            win = bytes(mm[o:o + 160])
            if b"\x28\x02\x00\x00" in win and b"\x88\x00\x00\x00" in win:
                if shown < 25:
                    st = o - 1 if o and mm[o - 1] == 0x41 else o
                    dump(mm, segs, st, 0, 168, f"resembles a check (cmp [reg+0x50],2) #{shown + 1}")
                shown += 1
    print(f"[similar cmp sites outside known patterns: {shown}]\n")

    shown = 0
    bt_rx = re.compile(rb"\x0f\xa3[\xc0-\xff]", F)
    cmp8 = re.compile(rb"\x83[\xf8-\xff]\x08", F)
    for s in segs:
        for m in bt_rx.finditer(mm, s.off, s.off + s.filesz):
            o = m.start()
            if inside(o) or o < 16:
                continue
            if cmp8.search(bytes(mm[o - 14:o])):
                if shown < 25:
                    dump(mm, segs, o, 56, 72, f"bt mask outside known patterns #{shown + 1}")
                shown += 1
    print(f"[bt sites with nearby cmp 8 outside known patterns: {shown}]\n")


def analyze(path, verbose=True, with_discovery=True):
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        segs = parse_exec_segments(mm)
        sites, rejects = find_sites(mm, segs)
        kinds = set().union(*(set(profile) for profile in EXPECT_PROFILES.values()))
        counts = {k: sum(1 for s in sites if s.kind == k) for k in kinds}
        profiles = [name for name, expected in EXPECT_PROFILES.items()
                    if counts == {k: expected.get(k, 0) for k in kinds}]
        ok_counts = len(profiles) == 1
        states = {s.state for s in sites if s.state != "ignored"}
        if verbose:
            print(f"binary : {path}")
            print(f"size   : {os.path.getsize(path)}")
            print("Detected sites:")
            for s in sites:
                print(f"  [{s.kind}] file_off=0x{s.jpos:X} vaddr=0x{vaddr_of(segs, s.jpos) or 0:X} "
                      f"state={s.state:<9} {s.info}")
            for kind, off, why in rejects:
                print(f"  rejected [{kind}] file_off=0x{off:X}: {why}")
            print(f"Counts: {counts}")
            if ok_counts:
                print(f"Profile: {profiles[0]} -> OK")
            else:
                expected = {name: {k: values.get(k, 0) for k in sorted(kinds)}
                            for name, values in EXPECT_PROFILES.items()}
                print(f"Profile not recognized; expected site counts: {expected}")
            if with_discovery:
                print()
                discover(mm, segs, sites)
        if not ok_counts or rejects or "unknown" in states:
            return None, "fail", [(s.jpos, s.orig, s.new, s.state) for s in sites]
        if states == {"patched"}:
            status = "patched"
        elif states == {"original"}:
            status = "original"
        else:
            status = "mixed"
        return sites, status, None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_ignoring_sites(path, sites):
    ignored = sorted((site.jpos, len(site.orig)) for site in sites)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        offset = 0
        while True:
            block = f.read(1 << 22)
            if not block:
                break
            end = offset + len(block)
            mutable = bytearray(block)
            for start, length in ignored:
                stop = start + length
                left, right = max(start, offset), min(stop, end)
                if left < right:
                    mutable[left - offset:right - offset] = b"\0" * (right - left)
            h.update(mutable)
            offset = end
    return h.hexdigest()


def find_bin(args):
    for a in args:
        if not a.startswith("-"):
            return os.path.realpath(a)
    for p in AUTO_PATHS:
        if os.path.isfile(p):
            return os.path.realpath(p)
    raise SystemExit("Binary not found. Specify its path explicitly.")


def check_size(path):
    if os.path.getsize(path) < 10_000_000:
        raise SystemExit(f"{path} is too small; this is a launcher, not a browser binary.")


def atomic_install(src_tmp, dst):
    metadata = os.stat(dst, follow_symlinks=False)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(src_tmp, metadata.st_uid, metadata.st_gid)
    elif hasattr(os, "geteuid") and (os.geteuid(), os.getegid()) != (metadata.st_uid, metadata.st_gid):
        raise SystemExit("Cannot preserve Chromium file ownership without root; run this command with sudo.")
    fd = os.open(src_tmp, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(src_tmp, dst)
    if os.name != "nt":
        dir_fd = os.open(os.path.dirname(dst) or ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def ensure_chromium_stopped(path):
    expected = os.path.realpath(path)
    if os.name == "nt":
        try:
            result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, check=False)
            names = {"chrome.exe", "chromium.exe"}
            if result.returncode == 0 and any(name in result.stdout.lower() for name in names):
                raise SystemExit("Close Chromium completely before replacing its executable.")
        except FileNotFoundError:
            pass
        return
    if sys.platform == "darwin":
        result = subprocess.run(["ps", "-axo", "comm="], capture_output=True, text=True, check=False)
        target = os.path.basename(expected).lower()
        if result.returncode == 0 and any(os.path.basename(row.strip()).lower() == target
                                          for row in result.stdout.splitlines()):
            raise SystemExit("Close Chromium completely before replacing its executable.")
        return
    proc = "/proc"
    if not os.path.isdir(proc):
        return
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        exe = os.path.join(proc, entry, "exe")
        try:
            running = os.path.realpath(os.readlink(exe).removesuffix(" (deleted)"))
        except (OSError, PermissionError):
            continue
        if running == expected:
            raise SystemExit(
                f"Chromium PID {entry} is still running from this file. Fully close the browser and retry.")


def cmd_apply(path, assume_yes):
    check_size(path)
    ensure_chromium_stopped(path)
    sites, status, bad = analyze(path, verbose=True, with_discovery=False)
    if status == "fail":
        raise SystemExit("\nABORTED: binary structure did not match expectations. Nothing was written.\n"
                         "Run `analyze` and share its output.")
    if status == "patched":
        raise SystemExit("\nAlready patched. No changes made.")
    if (not hasattr(os, "geteuid") or os.geteuid() != 0) and not os.access(os.path.dirname(path), os.W_OK):
        raise SystemExit("\nWrite access to the binary's directory is required; run with sudo.")
    pending = [site for site in sites if site.state == "original" and site.orig != site.new]
    if not pending:
        raise SystemExit("No original bytes available to patch.")
    print(f"\nSites to be changed: {len(pending)} (out of {len(sites)} validated).")
    if not assume_yes:
        if input("Continue? [y/N] ").strip().lower() != "y":
            raise SystemExit("Cancelled.")

    backup = path + BACKUP_SUFFIX
    if os.path.exists(backup):
        backup_sites, backup_status, _ = analyze(backup, verbose=False, with_discovery=False)
        if (backup_status != "original" or os.path.getsize(backup) != os.path.getsize(path)
                or sha256_ignoring_sites(backup, sites) != sha256_ignoring_sites(path, sites)):
            raise SystemExit(
                "ABORTED: the existing .mv2orig is not a verified original copy of this version. "
                "It was left unchanged.")
        print("Verified original backup already exists:", backup)
    elif status == "original":
        print("Creating original backup:", backup)
        tmpb = backup + ".tmp"
        shutil.copy2(path, tmpb)
        os.replace(tmpb, backup)
    else:
        raise SystemExit(
            "ABORTED: the binary is already partially modified and no verified original copy exists. "
            "Refusing to create a backup from a partially patched file.")

    tmp = path + ".mv2new"
    shutil.copy2(path, tmp)
    try:
        with open(tmp, "r+b") as f:
            for s in pending:
                f.seek(s.jpos)
                if f.read(len(s.orig)) != s.orig:
                    raise SystemExit("Bytes in the copy did not match expectations; aborting.")
                f.seek(s.jpos)
                f.write(s.new)
            f.flush()
            os.fsync(f.fileno())
        _, st2, _ = analyze(tmp, verbose=False, with_discovery=False)
        if st2 != "patched":
            raise SystemExit(f"Patch self-check failed (status={st2}). Original left untouched.")
        atomic_install(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    print("Done. Restart Chromium and load the MV2 extension (chrome://extensions → Developer mode).")
    print(f"Restore: sudo python3 {sys.argv[0]} restore")


def cmd_launch(path, browser_args):
    """Launch only a verified patched binary; Chromium reuses the standard profile and session."""
    check_size(path)
    _, status, _ = analyze(path, verbose=False, with_discovery=False)
    if status != "patched":
        raise SystemExit(f"Launch aborted: binary status is {status}. Run apply first.")
    if not os.access(path, os.X_OK):
        raise SystemExit("Binary is not executable: " + path)
    if any(arg == "--no-sandbox" for arg in browser_args):
        raise SystemExit("--no-sandbox is not allowed by this launcher.")
    print(f"Launching verified patched browser: {path}", flush=True)
    os.execv(path, [path, *browser_args])


def _desktop_quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`") + '"'


def cmd_install_shortcut(path):
    check_size(path)
    _, status, _ = analyze(path, verbose=False, with_discovery=False)
    if status not in ("patched", "original"):
        raise SystemExit("Browser does not match a supported profile.")
    xdg_data = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    appdir = os.path.join(xdg_data, "applications")
    os.makedirs(appdir, mode=0o755, exist_ok=True)
    command = [sys.executable, os.path.realpath(__file__), "launch", path]
    desktop = "[Desktop Entry]\nType=Application\nName=Chromium with Manifest V2\nComment=Launch the locally patched Chromium build\nExec=" + " ".join(_desktop_quote(x) for x in command) + "\nTerminal=false\nCategories=Network;WebBrowser;\n"
    appfile = os.path.join(appdir, "chromium-mv2.desktop")
    tmp = appfile + f".{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        stream.write(desktop)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(tmp, 0o755)
    os.replace(tmp, appfile)
    desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    if os.path.isdir(desktop_dir):
        link = os.path.join(desktop_dir, "Chromium with Manifest V2.desktop")
        link_tmp = link + f".{os.getpid()}.tmp"
        shutil.copy2(appfile, link_tmp)
        os.chmod(link_tmp, 0o755)
        os.replace(link_tmp, link)
        print("Desktop shortcut:", link)
    print("Application shortcut:", appfile)
    if status == "original":
        print("Run apply with write permissions before launching the shortcut.")


def cmd_restore(path):
    ensure_chromium_stopped(path)
    backup = path + BACKUP_SUFFIX
    if not os.path.exists(backup):
        raise SystemExit("Backup not found: " + backup)
    tmp = path + ".mv2new"
    shutil.copy2(backup, tmp)
    atomic_install(tmp, path)
    print("Original restored from", backup)


UNSUPPORTED_MANIFEST_VERSION_REASON = 1 << 23


def _remove_empty_containers(node):
    if isinstance(node, dict):
        result = {}
        for key, value in node.items():
            value = _remove_empty_containers(value)
            if value not in ({}, []):
                result[key] = value
        return result
    if isinstance(node, list):
        result = [_remove_empty_containers(value) for value in node]
        return [value for value in result if value not in ({}, [])]
    return node


def _canonical_json(node):
    serialized = __import__("json").dumps(
        _remove_empty_containers(node), ensure_ascii=False, separators=(",", ":"))
    return serialized.replace("<", "\\u003C").encode("utf-8")


def _compute_pref_mac(seed, path, value):
    import hmac
    message = path.encode("utf-8") + _canonical_json(value)
    return hmac.new(seed, message, hashlib.sha256).hexdigest().upper()


def _iter_resource_candidates(resources_path):
    with open(resources_path, "rb") as f:
        pack = f.read()
    if len(pack) < 18 or struct.unpack_from("<I", pack, 0)[0] != 5:
        raise ValueError("resources.pak must use the validated version 5 format")
    resource_count = struct.unpack_from("<H", pack, 8)[0]
    for index in range(resource_count):
        current = 12 + index * 6
        following = current + 6
        if following + 6 > len(pack):
            raise ValueError("Resource index is truncated in resources.pak")
        start = struct.unpack_from("<I", pack, current + 2)[0]
        end = struct.unpack_from("<I", pack, following + 2)[0]
        if 0 < end - start <= 512 and end <= len(pack):
            yield pack[start:end]


def _find_preference_seed(resources_path, roots):
    samples = []
    for root in roots:
        settings = root.get("extensions", {}).get("settings", {})
        macs = root.get("protection", {}).get("macs", {}).get("extensions", {}).get("settings", {})
        for extension_id, extension in settings.items():
            expected = macs.get(extension_id)
            if isinstance(extension, dict) and isinstance(expected, str):
                samples.append((f"extensions.settings.{extension_id}", extension, expected))
    if not samples:
        raise ValueError("No protected extension entry is available to validate the MAC seed; profile unchanged")

    # Chromium's Linux device-id implementation is a stub and returns
    # NOT_IMPLEMENTED; GenerateDeviceId() consequently uses an empty ID.
    # The seed is still accepted only after a stored HMAC validates.
    for candidate in _iter_resource_candidates(resources_path):
        for path, value, expected in samples[:32]:
            if hmac_compare(_compute_pref_mac(candidate, path, value), expected):
                return candidate
    raise ValueError("Could not verify Chromium's MAC seed against the profile; profile unchanged")


def hmac_compare(left, right):
    import hmac
    return hmac.compare_digest(left.upper(), right.upper())


def _has_mv2_disable_reason(extension):
    reasons = extension.get("disable_reasons")
    if isinstance(reasons, list):
        return any(type(item) is int and item == UNSUPPORTED_MANIFEST_VERSION_REASON for item in reasons)
    return type(reasons) is int and bool(reasons & UNSUPPORTED_MANIFEST_VERSION_REASON)


def _remove_mv2_disable_reason(extension):
    reasons = extension.get("disable_reasons")
    if isinstance(reasons, list):
        kept = [item for item in reasons if not (
            type(item) is int and item == UNSUPPORTED_MANIFEST_VERSION_REASON)]
        if len(kept) == len(reasons):
            return False
        if kept:
            extension["disable_reasons"] = kept
        else:
            extension.pop("disable_reasons", None)
        return True
    if type(reasons) is not int or not (reasons & UNSUPPORTED_MANIFEST_VERSION_REASON):
        return False
    remaining = reasons & ~UNSUPPORTED_MANIFEST_VERSION_REASON
    if remaining:
        extension["disable_reasons"] = remaining
    else:
        extension.pop("disable_reasons", None)
    return True


def _profile_browser_is_running():
    if os.name == "nt":
        try:
            result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, check=False)
            return result.returncode == 0 and any(
                row.split(",", 1)[0].strip('"').lower() in {"chrome.exe", "chromium.exe"}
                for row in result.stdout.splitlines())
        except FileNotFoundError:
            return False
    if sys.platform == "darwin":
        result = subprocess.run(["ps", "-axo", "comm="], capture_output=True, text=True, check=False)
        return result.returncode == 0 and any(
            os.path.basename(row.strip()).lower() in {"google chrome", "chromium"}
            for row in result.stdout.splitlines())
    proc = "/proc"
    if not os.path.isdir(proc):
        return False
    browser_names = {"chromium", "chromium-browser", "chrome", "google-chrome"}
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        try:
            executable = os.path.basename(os.readlink(os.path.join(proc, entry, "exe")))
        except OSError:
            continue
        if executable in browser_names:
            return True
    return False


def cmd_repair_profile(profile_dir, resources_path):
    if sys.platform != "linux":
        raise SystemExit("Profile repair is currently validated only for Linux Chromium profiles; no changes were made.")
    profile_dir = os.path.realpath(os.path.expanduser(profile_dir))
    secure_path = os.path.join(profile_dir, "Secure Preferences")
    if not os.path.isfile(secure_path):
        raise SystemExit("Secure Preferences not found: " + secure_path)
    if _profile_browser_is_running():
        raise SystemExit("Close Chromium completely first. The profile cannot be changed while the browser is running.")

    import json
    with open(secure_path, "r", encoding="utf-8") as f:
        root = json.load(f)
    settings = root.get("extensions", {}).get("settings", {})
    affected = [extension_id for extension_id, extension in settings.items()
                if isinstance(extension, dict) and _has_mv2_disable_reason(extension)]
    if not affected:
        print("No MV2-disabled bit (0x800000) found in Secure Preferences; no changes made.")
        return

    protection = root.get("protection")
    macs = protection.get("macs") if isinstance(protection, dict) else None
    ext_macs = macs.get("extensions") if isinstance(macs, dict) else None
    settings_macs = ext_macs.get("settings") if isinstance(ext_macs, dict) else None
    if not isinstance(settings_macs, dict):
        raise SystemExit("Missing protection.macs.extensions.settings; profile unchanged.")
    seed = _find_preference_seed(resources_path, [root])

    changed = []
    for extension_id in affected:
        extension = settings[extension_id]
        if not _remove_mv2_disable_reason(extension):
            continue
        extension.pop("state", None)
        if "mv2_deprecation_did_disable" in extension:
            extension["mv2_deprecation_did_disable"] = False
        settings_macs[extension_id] = _compute_pref_mac(
            seed, f"extensions.settings.{extension_id}", extension)
        changed.append(extension_id)
    if not changed:
        print("No MV2 disable reasons to remove; no changes made.")
        return

    # Linux has no Windows Registry mirror. Drop only optional encrypted
    # authenticators and restamp the verified legacy super HMAC as Chrome's
    # Windows port does, so Chrome can regenerate its encrypted store.
    ext_macs.pop("settings_encrypted_hash", None)
    protection.pop("super_encrypted_hash", None)
    protection["super_mac"] = _compute_pref_mac(seed, "", macs)

    backup = secure_path + ".mv2ctl.bak"
    if os.path.exists(backup):
        raise SystemExit("Backup already exists; refusing to overwrite: " + backup)
    shutil.copy2(secure_path, backup)
    tmp = secure_path + f".mv2ctl.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(root, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, stat.S_IMODE(os.stat(secure_path).st_mode))
        if hasattr(os, "chown") and hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(tmp, os.stat(secure_path).st_uid, os.stat(secure_path).st_gid)
        os.replace(tmp, secure_path)
        if os.name != "nt":
            dir_fd = os.open(profile_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    print(f"Removed only the MV2 disable reason from {len(changed)} extensions: {', '.join(changed)}")
    print("Backup: " + backup)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("analyze", "apply", "restore", "status", "repair-profile", "launch", "install-shortcut"):
        print(__doc__)
        raise SystemExit(1)
    cmd, rest = sys.argv[1], sys.argv[2:]
    if cmd == "repair-profile":
        if sys.platform == "win32":
            profile_dir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data", "Default")
        elif sys.platform == "darwin":
            profile_dir = os.path.expanduser("~/Library/Application Support/Google/Chrome/Default")
        else:
            profile_dir = os.path.expanduser("~/.config/chromium/Default")
        resources_path = None
        index = 0
        while index < len(rest):
            arg = rest[index]
            if arg == "--resources" and index + 1 < len(rest):
                resources_path = os.path.realpath(rest[index + 1])
                index += 2
                continue
            if arg.startswith("-"):
                raise SystemExit(f"Unknown option: {arg}")
            profile_dir = arg
            index += 1
        if resources_path is None:
            resources_path = next((os.path.join(os.path.dirname(p), "resources.pak")
                                   for p in AUTO_PATHS
                                   if os.path.isfile(os.path.join(os.path.dirname(p), "resources.pak"))), None)
        if resources_path is None:
            raise SystemExit("resources.pak not found; specify --resources PATH")
        cmd_repair_profile(profile_dir, resources_path)
        return

    if cmd == "launch":
        if "--" in rest:
            split = rest.index("--")
            path = find_bin(rest[:split])
            browser_args = rest[split + 1:]
        else:
            path = find_bin(rest)
            browser_args = []
        cmd_launch(path, browser_args)
        return
    path = find_bin(rest)
    if cmd == "install-shortcut":
        cmd_install_shortcut(path)
    elif cmd == "analyze":
        check_size(path)
        _, status, _ = analyze(path, verbose=True, with_discovery=True)
        print("Result:", {"original": "ready to patch", "patched": "already patched",
                        "mixed": "mixed state", "fail": "structure mismatch"}[status])
    elif cmd == "status":
        _, status, _ = analyze(path, verbose=False, with_discovery=False)
        print(status)
    elif cmd == "apply":
        cmd_apply(path, "--yes" in rest or "-y" in rest)
    elif cmd == "restore":
        cmd_restore(path)


if __name__ == "__main__":
    main()
