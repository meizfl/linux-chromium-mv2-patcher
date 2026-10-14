#!/usr/bin/env python3
"""
mv2patch.py — патч Chromium (Linux x86-64) на диске: возвращает поддержку Manifest V2.

  python3 mv2ctl.py analyze [BIN]             только чтение, показывает найденные места
  sudo python3 mv2ctl.py apply [BIN]          бэкап + патч (атомарная замена файла)
  sudo python3 mv2ctl.py restore [BIN]        вернуть оригинал из бэкапа
  python3 mv2ctl.py status [BIN]              состояние бинарника
  python3 mv2ctl.py repair-profile [PROFILE]  восстановить отключённые MV2-расширения
  python3 mv2ctl.py launch [BIN] [-- ARGS]   запустить проверенный пропатченный браузер
  python3 mv2ctl.py install-shortcut [BIN]    создать ярлык приложения

BIN по умолчанию ищется автоматически (/usr/lib/chromium/chromium).

Как это работает. Компилятор встроил проверку IsExtensionAffected() в несколько мест.
Во всех копиях первой идёт проверка «manifest_version > 2 -> не затронуто». Мы заставляем эту ветку
срабатывать всегда (как Windows-версия: jg -> jmp). Каждая копия проверяется по полной
последовательности байт и по тому, что ВСЕ «безопасные выходы» ведут в одну точку.
Любое несовпадение количества или структуры — отказ без записи (fail-closed).

Запись идёт во временную копию, которая атомарно подменяет оригинал (работающий Chromium не ломается).
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
BACKUP_SUFFIX = ".mv2orig"
EXPECT = {"A": 4, "B": 1, "C": 1, "D": 1, "S": 1, "U": 1}
EXPECT_PROFILES = {
    "Chromium 154-compatible ELF layout": EXPECT,
    "Google Chrome 155 / 156 Beta ELF layout": {"A": 2, "B": 0, "C": 0, "D": 1, "S": 1, "U": 1,
                                                 "M": 1, "I": 1, "V": 1, "H": 1},
    "Google Chrome 157 Canary ELF layout": {"A": 2, "B": 0, "C": 0, "D": 1, "S": 1, "U": 0,
                                             "M": 1, "I": 1, "V": 1, "H": 1},
    "Chromium 158 centralized MV2 policy ELF": {"A": 0, "B": 0, "C": 0, "D": 0, "S": 0,
                                                 "U": 0, "M": 0, "I": 0, "V": 2, "H": 1},
}

# ------------------------------------------------------------------ regex-блоки
F = re.DOTALL
HDR = rb"\x83[\x78-\x7f]\x50\x02"                             # cmp dword [reg+0x50], 2
FLAGCHK = rb"\x41?\x80[\xb8-\xbf]\x08\x02\x00\x00\x00\x75."   # cmp byte [reg+0x208],0 ; jne
LOAD228 = rb"[\x48-\x4f]\x8b[\x80-\xbf]\x28\x02\x00\x00"      # mov r64,[r64+0x228]
LOADLOC = rb"\x41?\x8b[\x40-\x7f]\x50"                        # mov r32,[r64+0x50]
LOADTYP = rb"\x41?\x8b[\x80-\xbf]\x88\x00\x00\x00"            # mov r32,[r64+0x88]
MASK_BT = rb"[\xb8-\xbf]\x0a\x01\x00\x00\x0f\xa3[\xc0-\xff]"  # mov r32,0x10A ; bt r32,r32

# Форма A: jg short (inline-копии с короткими переходами)
RA = re.compile(
    HDR + rb"(?P<j>[\x7f\xeb].)" + LOAD228 + LOADLOC + FLAGCHK + LOADTYP +
    rb"\x83[\xf8-\xff]\x08(?P<ja>\x77.)" + MASK_BT + rb"(?P<jae>\x73.)" +
    rb"\x83\xf8[\x05\x0a](?P<je>\x74.)\x83\xf8[\x05\x0a](?P<jne>\x75.|\x0f\x85....)", F)

# Форма B: jg near (rel32), тот же код с длинными переходами
RB = re.compile(
    HDR + rb"(?P<j>\x0f\x8f....|\x90\xe9....)" + LOAD228 + LOADLOC + FLAGCHK + LOADTYP +
    rb"\x83[\xf8-\xff]\x08(?P<ja>\x0f\x87....)\x0f\xa3[\xc0-\xff](?P<jae>\x0f\x83....)" +
    rb"\x83[\xf8-\xff][\x05\x0a](?P<je1>\x0f\x84....)\x83[\xf8-\xff][\x05\x0a](?P<je2>\x0f\x84....)", F)

# Форма C: инвертированная ветка: jle +4 ; xor eax,eax ; jmp  (результат «не затронуто» = 0)
RC = re.compile(
    HDR + rb"(?P<j>\x7e\x04|\x90\x90)\x31\xc0\xeb." + LOAD228 + LOADLOC + FLAGCHK + LOADTYP +
    rb"\x31\xc0\x83[\xf8-\xff]\x08\x77.[\xb8-\xbf]\x0a\x01\x00\x00\x0f\xa3[\xc0-\xff]\x73." +
    rb"\x83[\xf8-\xff][\x05\x0a]\x0f\x95[\xc0-\xc7]\x83[\xf8-\xff][\x05\x0a]\x0f\x95[\xc0-\xc7]\x20[\xc0-\xff]", F)

# Chromium 155 distro build: the compiler inserted a profile-state load before
# the same JLE -> zero/clear path and kept a stack reload before the type bit
# test's safe branch. Validate the whole function shape instead of widening RC.
RC155 = re.compile(
    HDR + rb"\x48\x8b\xb5\x98\xfd\xff\xff(?P<j>\x7e\x04|\x90\x90)\x31\xc0\xeb\x40"
    + LOAD228 + LOADLOC + FLAGCHK + LOADTYP +
    rb"\x31\xc0\x83\xfa\x08\x77.\xbe\x0a\x01\x00\x00\x0f\xa3\xd6"
    rb"\x48\x8b\xb5\x98\xfd\xff\xff\x73."
    rb"\x83\xf9\x05\x0f\x95\xc2\x83\xf9\x0a\x0f\x95\xc0\x20\xd0", F)

# Стартовая ветка: cmp r,r ; je rel32 ; ... mov edi,4 ; call new ; ... mov dword [rax],0x800000
S_NEEDLE = b"\xbf\x04\x00\x00\x00\x67\xe8"
S_LEAD = 21
RS = re.compile(
    rb"[\x48-\x4f]\x39[\xc0-\xff](?P<j>\x0f\x84....|\x90\xe9....)"
    rb"\x49\x8b\x44\x24\x20[\x48-\x4f]\x8b[\x80-\xbf]\x28\x02\x00\x00"
    rb"\xbf\x04\x00\x00\x00\x67\xe8...."
    rb"[\x48-\x4f]\x89[\x40-\x7f].[\x48-\x4f]\xc7[\x40-\x7f].\x01\x00\x00\x00"
    rb"\xc7[\x00-\x07]\x00\x00\x80\x00", F)

# Chrome 154 Linux has an additional MV2 startup-disable helper. For manifest
# v2 it falls through into the code that sets disable reason 0x800000. The
# branch's taken target returns from the helper. Turn the conditional into an
# unconditional jump to that already-validated return path.
RD = re.compile(
    rb"\x83\x7e\x50\x02(?P<j>\x0f\x85....|\x90\xe9....)"
    rb"\x49\x89\xf6\x80\xbe\x08\x02\x00\x00\x00\x0f\x85...."
    rb"\x89\xd3\x4c\x8b\x27\x49\x8b\xb6\x28\x02\x00\x00"
    rb"\x8b\x86\x88\x00\x00\x00\x83\xf8\x08\x74."
    rb"\x83\xf8\x01\x0f\x85....\x8b\x46\x50"
    rb"\x83\xf8\x05\x74.\x83\xf8\x0a\x75.", F)

# A later Chromium build retained the same disable-reason behavior but emitted
# the entry and type checks with a different register allocation.
RD_ALT = re.compile(
    rb"\x83\x7e\x50\x02(?P<j>\x0f\x85....|\x90\xe9....)"
    rb"\x49\x89\xf6\x80\xbe\x08\x02\x00\x00\x00\x0f\x85...."
    rb"\x41\x89\xd7\x4c\x8b\x27\x49\x8b\xb6\x28\x02\x00\x00"
    rb"\x8b\x86\x88\x00\x00\x00\x83\xf8\x08\x74."
    rb"\x83\xf8\x01\x0f\x85....\x8b\x46\x50\x31\xdb"
    rb"\x83\xf8\x05\x0f\x84....\x83\xf8\x0a\x0f\x84....", F)

# UserMayLoad-style availability check. For manifest_version <= 2, JLE enters
# the detailed location/type checks, which can return disabled. The fallthrough
# explicitly clears r14d and jumps to the common allowed return path.
RU = re.compile(
    rb"\x41\x83\x7e\x50\x02(?P<j>\x7e.|\x90\x90)"
    rb"\x45\x31\xf6\xeb\x0f"
    rb"[\s\S]{4,40}?\x80\x7d\xd7\x00"
    rb"[\s\S]{40,160}?"
    rb"\x49\x8b\x8e\x28\x02\x00\x00\x8b\x41\x50"
    rb"\x41\x80\xbe\x08\x02\x00\x00\x00\x75.", F)

# Chrome 155 changed the inlined checker layout. These signatures are anchored
# on the manifest_version compare and the distinct surrounding helper flow.
# Every branch target is checked below before a site is accepted.
R155_M = re.compile(
    rb"\x41\x83\x7e\x50\x02(?P<j>\x0f\x8f....|\x90\xe9....)"
    rb"\x49\x8b\x8e\x28\x02\x00\x00\x8b\x41\x50"
    rb"\x41\x80\xbe\x08\x02\x00\x00\x00\x75."
    rb"\x8b\x89\x88\x00\x00\x00\x83\xf9\x01\x75.", F)
R155_A1 = re.compile(
    rb"\x83\x79\x50\x02(?P<j>[\x7f\xeb].)"
    rb"\x48\x8b\x91\x28\x02\x00\x00\x8b\x42\x50"
    rb"\x80\xb9\x08\x02\x00\x00\x00\x75."
    rb"\x8b\x8a\x88\x00\x00\x00\x83\xf9\x01\x0f\x85...."
    rb"\x83\xf8\x05\x74.\x83\xf8\x0a\x0f\x85....", F)
R155_A2 = re.compile(
    rb"\x83\x7b\x50\x02(?P<j>[\x7f\xeb].)"
    rb"\x48\x8b\x8b\x28\x02\x00\x00\x8b\x41\x50"
    rb"\x80\xbb\x08\x02\x00\x00\x00\x75."
    rb"\x8b\x89\x88\x00\x00\x00\x83\xf9\x01\x0f\x85...."
    rb"\x83\xf8\x05\x74.\x83\xf8\x0a\x0f\x85....", F)
R155_I = re.compile(
    rb"\x83\x7e\x50\x02(?P<j>[\x7f\xeb].)\x55\x48\x89\xe5"
    rb"\x48\x8b\x8e\x28\x02\x00\x00\x8b\x41\x50"
    rb"\x80\xbe\x08\x02\x00\x00\x00\x75."
    rb"\x8b\x89\x88\x00\x00\x00\x83\xf9\x01\x75."
    rb"\x83\xf8\x05\x0f\x95\xc1\x83\xf8\x0a\x0f\x95\xc0\x20\xc8", F)
R155_D = re.compile(
    rb"\x83\x7e\x50\x02(?P<j>\x0f\x85....|\x90\xe9....)"
    rb"\x49\x89\xf6\x80\xbe\x08\x02\x00\x00\x00\x0f\x85...."
    rb"\x41\x89\xd7\x48\x8b\x3f\x49\x8b\x86\x28\x02\x00\x00"
    rb"\x8b\x88\x88\x00\x00\x00\x83\xf9\x01\x0f\x85....", F)
R155_U = re.compile(
    rb"\x83\x7f\x50\x02(?P<j>[\x7f\xeb].)"
    rb"\x41\x80\xbc\x24\x08\x02\x00\x00\x00\x0f\x85...."
    rb"\x49\x8b\x84\x24\x28\x02\x00\x00\x83\xb8\x88\x00\x00\x00\x06", F)
# ContentHash::ShouldComputeHashesForResource. This is a source-type check, not
# an MV2 manifest-version gate. Keep it recognized as read-only so legacy
# patched binaries can be rejected and restored instead of silently accepted.
RHASH = re.compile(
    rb"\x55\x48\x89\xe5\x83\x7f\x50\x02(?P<j>\x75\x0a|\xeb\x0a)"
    rb"\x48\x8b\x7f\x60\x5d\xe9....\xb0\x01\x5d\xc3", F)
# Chromium 158 centralizes the MV2 impact decision in two overloads of
# manifest_v2_util::IsExtensionAffected(). These complete byte windows include
# their distinct policy checks and make the clear/unaffected return paths
# verifiable before either branch can be changed.
R158_V1 = re.compile(
    rb"\x41\x83\xff\x02(?P<j>\x7e\x04|\x90\x90)"
    rb"\x31\xc0\xeb\x21\x89\xc1\x31\xc0\x83\xfb\x08\x77\x18"
    rb"\xba\x0a\x01\x00\x00\x0f\xa3\xda\x73\x0e"
    rb"\x83\xf9\x05\x0f\x95\xc2\x83\xf9\x0a\x0f\x95\xc0\x20\xd0", F)
R158_V2 = re.compile(
    rb"\x31\xc0\x83\xff\x02(?P<j>\x7f\x1d|\xeb\x1d)"
    rb"\x83\xfe\x08\x77\x18\xb9\x0a\x01\x00\x00\x0f\xa3\xf1\x73\x0e"
    rb"\x83\xfa\x05\x0f\x95\xc1\x83\xfa\x0a\x0f\x95\xc0\x20\xc8\x5d\xc3", F)
R155_S = re.compile(
    rb"\xba\x00\x00\x80\x00\xe8....\x84\xc0\x74."
    rb"\x83\x7b\x50\x02(?P<j>\x7f.)"
    rb"\x48\x8b\x8b\x28\x02\x00\x00\x8b\x41\x50"
    rb"\x80\xbb\x08\x02\x00\x00\x00\x75.", F)


# ------------------------------------------------------------------ ELF
class Seg:
    def __init__(self, off, vaddr, filesz):
        self.off, self.vaddr, self.filesz = off, vaddr, filesz


def parse_exec_segments(mm):
    if mm[:4] != b"\x7fELF" or mm[4] != 2 or mm[5] != 1:
        raise SystemExit("Это не ELF64 little-endian файл.")
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
    """Возвращает (абсолютный файловый офсет цели, длина) для jmp/jcc; nop+jmp тоже понимает."""
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


# ------------------------------------------------------------------ поиск мест
class Site:
    def __init__(self, kind, start, end, jpos, orig, new, state, info):
        self.kind, self.start, self.end = kind, start, end
        self.jpos, self.orig, self.new, self.state, self.info = jpos, orig, new, state, info


def make_site(kind, mm, m, jname, orig, new, info):
    jpos = m.start(jname)
    cur = bytes(mm[jpos:jpos + len(orig)])
    state = "original" if cur == orig else "patched" if cur == new else "unknown"
    return Site(kind, m.start(), m.end(), jpos, orig, new, state, info)


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
                        bad = f"не удалось разобрать переход {n}"
                        break
                    targets[n] = d[0]
                if bad is None and len(set(targets.values())) > 1:
                    bad = "«безопасные» выходы ведут в разные места: " + \
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
                    sites.append(make_site("C", mm, m, "j", b"\x7e\x04", b"\x90\x90", "xor eax,eax-путь"))
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
                    rejects.append(("D", m.start(), "не удалось разобрать переход версии manifest"))
                    continue
                target = decoded[0]
                fallthrough = jpos + 6
                call_limit = min(target, s.off + s.filesz)
                reason = b"\xba\x00\x00\x80\x00"
                reason_pos = mm.find(reason, fallthrough, call_limit)
                if reason_pos < 0 or mm[reason_pos + len(reason):reason_pos + len(reason) + 2] != b"\x67\xe8":
                    rejects.append(("D", m.start(), "в обходимой ветке не найден вызов с disable reason 0x800000"))
                    continue
                if not (s.off <= target < s.off + s.filesz):
                    rejects.append(("D", m.start(), "безопасная цель выходит из исполняемого сегмента"))
                    continue
                epilogue = bytes(mm[target:min(target + 48, s.off + s.filesz)])
                if b"\x48\x83\xc4" not in epilogue or b"\xc3" not in epilogue:
                    rejects.append(("D", m.start(), "цель перехода не похожа на возврат из функции"))
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
                rejects.append(("U", m.start(), "не найдена подробная проверка назначения расширения"))
                continue
            allowed_jump = decode_jump(mm, jpos + 5)
            allowed_target = allowed_jump[0] if allowed_jump else None
            expected_allowed = b"\x80\x7d\xd7\x00"
            if (allowed_jump is None or allowed_target < s.off or
                    allowed_target >= s.off + s.filesz or
                    bytes(mm[allowed_target:allowed_target + len(expected_allowed)]) != expected_allowed):
                rejects.append(("U", m.start(), "путь разрешения не ведёт к ожидаемому общему выходу"))
                continue
            if cur[0] == 0x7e:
                disp = mm[jpos + 1]
                disp -= 256 if disp > 127 else 0
                target = jpos + 2 + disp
                if target != detail_pos:
                    rejects.append(("U", m.start(), "JLE не ведёт непосредственно в блок подробной проверки"))
                    continue
                state = "original"
            elif cur == b"\x90\x90":
                state = "patched"
            else:
                rejects.append(("U", m.start(), "неизвестные байты у JLE"))
                continue
            info = f"bypass UserMayLoad detail -> allowed vaddr 0x{vaddr_of(segs, allowed_target) or 0:X}"
            sites.append(Site("U", m.start(), m.end(), jpos,
                              b"\x7e" + bytes([mm[jpos + 1]]) if state == "original" else b"\x90\x90",
                              b"\x90\x90", state, info))
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
        if target is None or bytes(mm[target:target + len(expected_target)]) != expected_target:
            rejects.append((kind, match.start(), f"цель перехода не совпадает с ожидаемым путем: {label}"))
            return
        cur = bytes(mm[jpos:jpos + 2])
        if cur[0] not in (0x7f, 0xeb):
            rejects.append((kind, match.start(), "неожиданный opcode короткого перехода"))
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

        for m in R155_A1.finditer(mm, seg.off, seg.off + seg.filesz):
            short_branch_site("A", seg, m, b"\x48\x8b\x46\x08", "extension-overload checker")
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

        for m in R155_S.finditer(mm, seg.off, seg.off + seg.filesz):
            jpos = m.start("j")
            cur = bytes(mm[jpos:jpos + 2])
            fallthrough = jpos + 2
            target = target_for(seg, jpos) if cur[1] != 0 else None
            target_ok = (target is not None and bytes(mm[target:target + 4]) == b"\x49\x8b\x7e\x18")
            patched_ok = cur == b"\x7f\x00" and mm.find(b"\x49\x8b\x7e\x18", fallthrough,
                                                           min(fallthrough + 128, seg.off + seg.filesz)) >= 0
            if not (target_ok or patched_ok):
                rejects.append(("S", m.start(), "startup disable target does not match the validated helper"))
                continue
            state = "patched" if patched_ok else "original"
            sites.append(Site("S", m.start(), m.end(), jpos, b"\x7f" + cur[1:2] if not patched_ok else b"\x7f\x00",
                              b"\x7f\x00", state,
                              "neutralize version branch before the verified 0x800000 disable-reason helper"))
    # стартовая ветка
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
            d = decode_jump(mm, jpos)
            cur = bytes(mm[jpos:jpos + 2])
            state = "original" if cur == b"\x0f\x84" else "patched" if cur == b"\x90\xe9" else "unknown"
            sites.append(Site("S", st, st + m.end(), jpos, b"\x0f\x84", b"\x90\xe9", state,
                              f"skip->vaddr 0x{vaddr_of(segs, d[0]) or 0:X}" if d else ""))
    sites.sort(key=lambda x: x.start)
    return sites, rejects


# ------------------------------------------------------------------ вывод
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
    """Похожие, но НЕ классифицированные места — их нужно прислать для доработки правил."""
    spans = [(s.start - 4, s.end + 4) for s in sites]

    def inside(o):
        return any(a <= o < b for a, b in spans)

    print("=== Неклассифицированные похожие места (пришлите этот раздел) ===")
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
                    dump(mm, segs, st, 0, 168, f"похож на проверку (cmp [reg+0x50],2) #{shown + 1}")
                shown += 1
    print(f"[похожих cmp-мест вне правил: {shown}]\n")

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
                    dump(mm, segs, o, 56, 72, f"bt-маска вне правил #{shown + 1}")
                shown += 1
    print(f"[bt-мест с cmp 8 рядом вне правил: {shown}]\n")


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
            print("Найденные места:")
            for s in sites:
                print(f"  [{s.kind}] file_off=0x{s.jpos:X} vaddr=0x{vaddr_of(segs, s.jpos) or 0:X} "
                      f"state={s.state:<9} {s.info}")
            for kind, off, why in rejects:
                print(f"  отклонено [{kind}] file_off=0x{off:X}: {why}")
            print(f"Количество: {counts}")
            if ok_counts:
                print(f"Профиль: {profiles[0]} -> OK")
            else:
                expected = {name: {k: values.get(k, 0) for k in sorted(kinds)}
                            for name, values in EXPECT_PROFILES.items()}
                print(f"Профиль не распознан; ожидаемые наборы: {expected}")
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
    raise SystemExit("Бинарник не найден. Укажите путь явно.")


def check_size(path):
    if os.path.getsize(path) < 10_000_000:
        raise SystemExit(f"{path} слишком мал — это лаунчер, а не браузер.")


def atomic_install(src_tmp, dst):
    metadata = os.stat(dst, follow_symlinks=False)
    if os.geteuid() == 0:
        os.chown(src_tmp, metadata.st_uid, metadata.st_gid)
    elif (os.geteuid(), os.getegid()) != (metadata.st_uid, metadata.st_gid):
        raise SystemExit("Невозможно сохранить владельца Chromium без root; запустите команду через sudo.")
    fd = os.open(src_tmp, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(src_tmp, dst)
    dir_fd = os.open(os.path.dirname(dst) or ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def ensure_chromium_stopped(path):
    expected = os.path.realpath(path)
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
                f"Chromium PID {entry} ещё запущен из этого файла. Полностью закройте браузер и повторите команду.")


def cmd_apply(path, assume_yes):
    check_size(path)
    ensure_chromium_stopped(path)
    sites, status, bad = analyze(path, verbose=True, with_discovery=False)
    if status == "fail":
        raise SystemExit("\nОТКАЗ: структура не совпала с ожидаемой. Ничего не записано.\n"
                         "Запустите `analyze` и пришлите вывод.")
    if status == "patched":
        raise SystemExit("\nУже пропатчено. Ничего не делаю.")
    if os.geteuid() != 0 and not os.access(os.path.dirname(path), os.W_OK):
        raise SystemExit("\nНужны права на запись в каталог бинарника: запустите через sudo.")
    pending = [site for site in sites if site.state == "original" and site.orig != site.new]
    if not pending:
        raise SystemExit("Нет исходных байт для изменения.")
    print(f"\nБудет изменено мест: {len(pending)} (из {len(sites)} проверенных).")
    if not assume_yes:
        if input("Продолжить? [y/N] ").strip().lower() != "y":
            raise SystemExit("Отменено.")

    backup = path + BACKUP_SUFFIX
    if os.path.exists(backup):
        backup_sites, backup_status, _ = analyze(backup, verbose=False, with_discovery=False)
        if (backup_status != "original" or os.path.getsize(backup) != os.path.getsize(path)
                or sha256_ignoring_sites(backup, sites) != sha256_ignoring_sites(path, sites)):
            raise SystemExit(
                "ОТКАЗ: существующий .mv2orig не является проверенной исходной копией этой версии. "
                "Он оставлен без изменений.")
        print("Проверенная исходная резервная копия уже существует:", backup)
    elif status == "original":
        print("Создаю бэкап оригинала:", backup)
        tmpb = backup + ".tmp"
        shutil.copy2(path, tmpb)
        os.replace(tmpb, backup)
    else:
        raise SystemExit(
            "ОТКАЗ: бинарник уже частично изменён, а проверенной исходной копии нет. "
            "Не буду создавать бэкап из частично пропатченного файла.")

    tmp = path + ".mv2new"
    shutil.copy2(path, tmp)
    try:
        with open(tmp, "r+b") as f:
            for s in pending:
                f.seek(s.jpos)
                if f.read(len(s.orig)) != s.orig:
                    raise SystemExit("Байты в копии не совпали с ожидаемыми — отмена.")
                f.seek(s.jpos)
                f.write(s.new)
            f.flush()
            os.fsync(f.fileno())
        _, st2, _ = analyze(tmp, verbose=False, with_discovery=False)
        if st2 != "patched":
            raise SystemExit(f"Самопроверка патча не пройдена (status={st2}). Оригинал не тронут.")
        atomic_install(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    print("Готово. Запустите Chromium заново и загрузите MV2-расширение (chrome://extensions → режим разработчика).")
    print(f"Откат: sudo python3 {sys.argv[0]} restore")


def cmd_launch(path, browser_args):
    """Запускает только проверенный патч; стандартный Chromium сам переиспользует профиль и сессию."""
    check_size(path)
    _, status, _ = analyze(path, verbose=False, with_discovery=False)
    if status != "patched":
        raise SystemExit(f"Запуск отменён: бинарник имеет состояние {status}. Сначала выполните apply.")
    if not os.access(path, os.X_OK):
        raise SystemExit("Бинарник не имеет права на запуск: " + path)
    if any(arg == "--no-sandbox" for arg in browser_args):
        raise SystemExit("--no-sandbox запрещён этим лаунчером.")
    print(f"Запускаю проверенный пропатченный браузер: {path}", flush=True)
    os.execv(path, [path, *browser_args])


def _desktop_quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`") + '"'


def cmd_install_shortcut(path):
    check_size(path)
    _, status, _ = analyze(path, verbose=False, with_discovery=False)
    if status not in ("patched", "original"):
        raise SystemExit("Браузер не распознан поддерживаемым профилем.")
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
        print("Ярлык рабочего стола:", link)
    print("Ярлык приложения:", appfile)
    if status == "original":
        print("Перед запуском ярлыка сначала выполните apply с правами на запись.")


def cmd_restore(path):
    ensure_chromium_stopped(path)
    backup = path + BACKUP_SUFFIX
    if not os.path.exists(backup):
        raise SystemExit("Бэкап не найден: " + backup)
    tmp = path + ".mv2new"
    shutil.copy2(backup, tmp)
    atomic_install(tmp, path)
    print("Оригинал восстановлен из", backup)


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
        raise ValueError("resources.pak должен иметь проверенный формат версии 5")
    resource_count = struct.unpack_from("<H", pack, 8)[0]
    for index in range(resource_count):
        current = 12 + index * 6
        following = current + 6
        if following + 6 > len(pack):
            raise ValueError("В resources.pak обрезан индекс ресурсов")
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
        raise ValueError("Нет защищённой записи расширения для проверки MAC-seed; профиль не изменён")

    # Chromium's Linux device-id implementation is a stub and returns
    # NOT_IMPLEMENTED; GenerateDeviceId() consequently uses an empty ID.
    # The seed is still accepted only after a stored HMAC validates.
    for candidate in _iter_resource_candidates(resources_path):
        for path, value, expected in samples[:32]:
            if hmac_compare(_compute_pref_mac(candidate, path, value), expected):
                return candidate
    raise ValueError("Не удалось подтвердить MAC-seed Chromium по профилю; профиль не изменён")


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
    profile_dir = os.path.realpath(os.path.expanduser(profile_dir))
    secure_path = os.path.join(profile_dir, "Secure Preferences")
    if not os.path.isfile(secure_path):
        raise SystemExit("Secure Preferences не найден: " + secure_path)
    if _profile_browser_is_running():
        raise SystemExit("Сначала полностью закройте Chromium. Профиль нельзя менять во время работы браузера.")

    import json
    with open(secure_path, "r", encoding="utf-8") as f:
        root = json.load(f)
    settings = root.get("extensions", {}).get("settings", {})
    affected = [extension_id for extension_id, extension in settings.items()
                if isinstance(extension, dict) and _has_mv2_disable_reason(extension)]
    if not affected:
        print("В Secure Preferences не найден бит отключения MV2 (0x800000); изменений нет.")
        return

    protection = root.get("protection")
    macs = protection.get("macs") if isinstance(protection, dict) else None
    ext_macs = macs.get("extensions") if isinstance(macs, dict) else None
    settings_macs = ext_macs.get("settings") if isinstance(ext_macs, dict) else None
    if not isinstance(settings_macs, dict):
        raise SystemExit("Нет protection.macs.extensions.settings; профиль не изменён.")
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
        print("Нет MV2-причин для удаления; изменений нет.")
        return

    # Linux has no Windows Registry mirror. Drop only optional encrypted
    # authenticators and restamp the verified legacy super HMAC as Chrome's
    # Windows port does, so Chrome can regenerate its encrypted store.
    ext_macs.pop("settings_encrypted_hash", None)
    protection.pop("super_encrypted_hash", None)
    protection["super_mac"] = _compute_pref_mac(seed, "", macs)

    backup = secure_path + ".mv2ctl.bak"
    if os.path.exists(backup):
        raise SystemExit("Бэкап уже существует, отказ перезаписывать: " + backup)
    shutil.copy2(secure_path, backup)
    tmp = secure_path + f".mv2ctl.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(root, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, stat.S_IMODE(os.stat(secure_path).st_mode))
        os.chown(tmp, os.stat(secure_path).st_uid, os.stat(secure_path).st_gid)
        os.replace(tmp, secure_path)
        dir_fd = os.open(profile_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    print(f"Снята только MV2-причина у {len(changed)} расширений: {', '.join(changed)}")
    print("Бэкап: " + backup)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("analyze", "apply", "restore", "status", "repair-profile", "launch", "install-shortcut"):
        print(__doc__)
        raise SystemExit(1)
    cmd, rest = sys.argv[1], sys.argv[2:]
    if cmd == "repair-profile":
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
                raise SystemExit(f"Неизвестный параметр: {arg}")
            profile_dir = arg
            index += 1
        if resources_path is None:
            resources_path = next((os.path.join(os.path.dirname(p), "resources.pak")
                                   for p in AUTO_PATHS
                                   if os.path.isfile(os.path.join(os.path.dirname(p), "resources.pak"))), None)
        if resources_path is None:
            raise SystemExit("resources.pak не найден; задайте --resources PATH")
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
        print("Итог:", {"original": "готов к патчу", "patched": "уже пропатчен",
                        "mixed": "смешанное состояние", "fail": "структура НЕ совпала"}[status])
    elif cmd == "status":
        _, status, _ = analyze(path, verbose=False, with_discovery=False)
        print(status)
    elif cmd == "apply":
        cmd_apply(path, "--yes" in rest or "-y" in rest)
    elif cmd == "restore":
        cmd_restore(path)


if __name__ == "__main__":
    main()
