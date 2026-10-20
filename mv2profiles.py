"""Validated Chromium binary signatures and expected site counts.

Add a profile only after confirming every matched branch target against its
control flow. The patching and validation algorithms live in mv2ctl.py.
"""
import re


def _byte_pattern(spec):
    """Compile a space-separated hex pattern with ?? wildcard bytes."""
    tokens = spec.split()
    return re.compile(b"".join(
        b"." if token in ("?", "??") else re.escape(bytes([int(token, 16)]))
        for token in tokens
    ), re.DOTALL)

EXPECT = {"A": 4, "B": 1, "C": 1, "D": 1, "S": 1, "U": 1}
EXPECT_PROFILES = {
    "Chromium 154-compatible ELF layout": EXPECT,
    "Google Chrome 155 / 156 Beta ELF layout": {"A": 2, "B": 0, "C": 0, "D": 1, "S": 1, "U": 1,
                                                 "M": 1, "I": 1, "V": 1, "H": 1},
    "Alacrium Browser 155-based ELF layout": {"A": 2, "B": 0, "C": 0, "D": 1, "S": 1, "U": 1,
                                              "M": 1, "I": 2, "V": 1, "H": 1},
    "Google Chrome 157 Canary ELF layout": {"A": 2, "B": 0, "C": 0, "D": 1, "S": 1, "U": 0,
                                             "M": 1, "I": 1, "V": 1, "H": 1},
    "Google Chrome for Testing 158.0.8113.0 ELF x86-64": {
        "A": 2, "B": 0, "C": 0, "D": 0, "S": 1, "U": 0,
        "M": 1, "I": 1, "V": 1, "H": 1,
    },
    "Chromium 158 centralized MV2 policy x86-64": {"A": 0, "B": 0, "C": 0, "D": 0, "S": 0,
                                                 "U": 0, "M": 0, "I": 0, "V": 2, "H": 1},
    "Chromium 158 Windows PE x86-64": {"A": 0, "B": 0, "C": 0, "D": 0, "S": 0,
                                       "U": 0, "M": 0, "I": 0, "V": 2, "H": 0},
    "Google Chrome 152.0.7977.65 Windows PE x86-64": {
        "A": 0, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 1, "W6": 1,
    },
    "Chrome 155 Windows PE x86-64": {
        "A": 1, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 1, "W5_157": 0, "W5_158": 0, "W6": 1,
    },
    "Google Chrome for Testing 157.0.8103.6 Windows PE x86-64": {
        "A": 1, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 0, "W5_157": 1, "W5_158": 0, "W6": 1,
    },
    "Google Chrome for Testing 158.0.8113.0 Windows PE x86-64": {
        "A": 1, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 0, "W5_157": 0, "W5_158": 1, "W6": 1,
    },
    "Google Chrome for Testing 158.0.8106.0 Windows PE x86-64": {
        "A": 1, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 0, "W5_157": 0, "W5_158": 0, "W5_158_8106": 1, "W6": 1,
    },
}

# ------------------------------------------------------------------ regex patterns
F = re.DOTALL
HDR = rb"\x83[\x78-\x7f]\x50\x02"                             # cmp dword [reg+0x50], 2
FLAGCHK = rb"\x41?\x80[\xb8-\xbf]\x08\x02\x00\x00\x00\x75."   # cmp byte [reg+0x208],0 ; jne
LOAD228 = rb"[\x48-\x4f]\x8b[\x80-\xbf]\x28\x02\x00\x00"      # mov r64,[r64+0x228]
LOADLOC = rb"\x41?\x8b[\x40-\x7f]\x50"                        # mov r32,[r64+0x50]
LOADTYP = rb"\x41?\x8b[\x80-\xbf]\x88\x00\x00\x00"            # mov r32,[r64+0x88]
MASK_BT = rb"[\xb8-\xbf]\x0a\x01\x00\x00\x0f\xa3[\xc0-\xff]"  # mov r32,0x10A ; bt r32,r32

# Form A: jg short (inlined copies with short branches)
RA = re.compile(
    HDR + rb"(?P<j>[\x7f\xeb].)" + LOAD228 + LOADLOC + FLAGCHK + LOADTYP +
    rb"\x83[\xf8-\xff]\x08(?P<ja>\x77.)" + MASK_BT + rb"(?P<jae>\x73.)" +
    rb"\x83\xf8[\x05\x0a](?P<je>\x74.)\x83\xf8[\x05\x0a](?P<jne>\x75.|\x0f\x85....)", F)

# Form B: jg near (rel32), same code with long branches
RB = re.compile(
    HDR + rb"(?P<j>\x0f\x8f....|\x90\xe9....)" + LOAD228 + LOADLOC + FLAGCHK + LOADTYP +
    rb"\x83[\xf8-\xff]\x08(?P<ja>\x0f\x87....)\x0f\xa3[\xc0-\xff](?P<jae>\x0f\x83....)" +
    rb"\x83[\xf8-\xff][\x05\x0a](?P<je1>\x0f\x84....)\x83[\xf8-\xff][\x05\x0a](?P<je2>\x0f\x84....)", F)

# Form C: inverted branch: jle +4 ; xor eax,eax ; jmp ("unaffected" result = 0)
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

# Startup branch: cmp r,r ; je rel32 ; ... mov edi,4 ; call new ; ... mov dword [rax],0x800000
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
RWIN_V1 = re.compile(
    rb"\x83\x7f\x50\x02(?P<j>\x7e\x04|\x90\x90)\x31\xc0\xeb\x21"
    rb"\x89\xc1\x31\xc0\x83\xf9\x08\x77\x18\xba\x0a\x01\x00\x00"
    rb"\x0f\xa3\xca\x73\x0e\x83\xfe\x05\x0f\x95\xc1\x83\xfe\x0a"
    rb"\x0f\x95\xc0\x20\xc8\x48\x83\xc4\x28\x5f\x5e\xc3", F)
RWIN_V2 = re.compile(
    rb"\x31\xc0\x83\xf9\x02(?P<j>\x7f\x1f|\xeb\x1f)"
    rb"\x83\xfa\x08\x77\x1a\xb9\x0a\x01\x00\x00\x0f\xa3\xd1\x73\x10"
    rb"\x41\x83\xf8\x05\x0f\x95\xc1\x41\x83\xf8\x0a\x0f\x95\xc0"
    rb"\x20\xc8\xc3", F)

# Windows Chrome 152–155 rules ported from the semantic RAM patcher. The
# grouped rules cover both split Extension& checker copies, the integer
# overload, install/disable/re-enable clones, and the startup MV2-disable loop.
WIN_SPLIT_V5 = _byte_pattern(
    "83 7A 50 02 ?? ?? 48 8B 8A 28 02 00 00 8B 41 30 "
    "80 BA 08 02 00 00 00 75 ?? 8B 49 68 83 F9 01 75 ?? "
    "83 F8 05 0F 95 C1 83 F8 0A 0F 95 C0 20 C8 C3 "
    "83 F9 08 74 ?? 83 F9 03 74 ?? 31 C0 EB ?? CC CC")
WIN_SPLIT_V5_ALT = _byte_pattern(
    "83 79 50 02 ?? ?? 48 8B 91 28 02 00 00 8B 42 30 "
    "80 B9 08 02 00 00 00 ?? ?? 8B 4A 68 83 F9 01 ?? ?? "
    "83 F8 05 0F 95 C1 83 F8 0A 0F 95 C0 20 C8 C3 "
    "83 F9 08 74 ?? 83 F9 03 74 ?? 31 C0 EB ?? CC CC")
WIN_SPLIT_V7 = _byte_pattern(
    "83 7A 50 02 ?? ?? 48 8B 8A 28 02 00 00 8B 41 50 "
    "80 BA 08 02 00 00 00 75 ?? 8B 89 88 00 00 00 83 F9 01 75 ?? "
    "83 F8 05 0F 95 C1 83 F8 0A 0F 95 C0 20 C8 C3 "
    "83 F9 08 74 ?? 83 F9 03 74 ?? 31 C0 EB ?? CC CC")
WIN_INTEGER_SPLIT = _byte_pattern(
    "31 C0 83 F9 02 ?? ?? 83 FA 08 77 ?? B9 0A 01 00 00 "
    "0F A3 D1 73 ?? 41 83 F8 05 0F 95 C1 41 83 F8 0A "
    "0F 95 C0 20 C8 C3 CC CC")
WIN_MUST_DISABLE_V5 = _byte_pattern(
    "83 7F 50 02 ?? ?? ?? ?? ?? ?? 48 8B 8F 28 02 00 00 8B 41 30 "
    "80 BF 08 02 00 00 00 75 ?? 8B 49 68 83 F9 01 75 ?? 31 FF "
    "83 F8 05 74 ?? 83 F8 0A 75 ??")
WIN_MUST_DISABLE_V7 = _byte_pattern(
    "83 7F 50 02 ?? ?? ?? ?? ?? ?? 48 8B 8F 28 02 00 00 8B 41 50 "
    "80 BF 08 02 00 00 00 75 ?? 8B 89 88 00 00 00 83 F9 01 75 ?? 31 FF "
    "83 F8 05 74 ?? 83 F8 0A 75 ??")
WIN_REENABLE_V5 = _byte_pattern(
    "83 7E 50 02 ?? ?? 48 8B 8E 28 02 00 00 8B 41 30 "
    "80 BE 08 02 00 00 00 75 ?? 8B 49 68 83 F9 01 75 ?? "
    "83 F8 0A 74 ?? 83 F8 05 74 ?? 48 83 C4 20 5B 5F 5E C3")
WIN_REENABLE_V7 = _byte_pattern(
    "83 7E 50 02 ?? ?? 48 8B 8E 28 02 00 00 8B 41 50 "
    "80 BE 08 02 00 00 00 75 ?? 8B 89 88 00 00 00 83 F9 01 75 ?? "
    "83 F8 0A 74 ?? 83 F8 05 74 ?? 48 83 C4 20 5B 5F 5E C3")
WIN_INSTALL_V5 = _byte_pattern(
    "83 7F 50 02 ?? ?? 48 8B 8F 28 02 00 00 8B 41 30 "
    "80 BF 08 02 00 00 00 75 ?? 8B 49 68 83 F9 01 0F 85 ?? ?? ?? ?? "
    "83 F8 05 74 ?? 83 F8 0A 74 ?? 4C 8D B4 24 80 00 00 00 "
    "4C 89 F1 BA B3 1F 00 00")
WIN_INSTALL_V7 = _byte_pattern(
    "83 7F 50 02 ?? ?? 48 8B 8F 28 02 00 00 8B 41 50 "
    "80 BF 08 02 00 00 00 75 ?? 8B 89 88 00 00 00 83 F9 01 0F 85 ?? ?? ?? ?? "
    "83 F8 05 74 ?? 83 F8 0A 74 ?? 4C 8D B4 24 80 00 00 00 "
    "4C 89 F1 BA B3 1F 00 00")
WIN_INSTALL_V8 = _byte_pattern(
    "83 7F 50 02 ?? ?? 48 8B 8F 28 02 00 00 8B 41 50 "
    "80 BF 08 02 00 00 00 75 ?? 8B 89 88 00 00 00 83 F9 01 0F 85 ?? ?? ?? ?? "
    "83 F8 05 74 ?? 83 F8 0A 0F 85 ?? ?? ?? ?? "
    "4C 8D B4 24 50 02 00 00 48 89 D9 48 89 FA 4D 89 F0 E8 ?? ?? ?? ??")
WIN_INSTALL_V8_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA C1 1F 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
WIN_INSTALL_V9_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA B9 1F 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
WIN_INSTALL_V10_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA C2 1F 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
WIN_INSTALL_V11_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA 34 20 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
WIN_INSTALL_V12_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA F7 1F 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
WIN_INSTALL_V8_TYPES = _byte_pattern(
    "83 F9 08 0F 84 ?? ?? ?? ?? 83 F9 03 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? ??")
WIN_STARTUP_V5 = _byte_pattern(
    "4C 8B 74 24 40 4D 39 FE 0F 85 ?? ?? ?? ?? "
    "48 8B 4C 24 48 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 56 18")
WIN_STARTUP_V6 = _byte_pattern(
    "4C 8B 7C 24 48 4D 39 E7 0F 85 ?? ?? ?? ?? "
    "48 8B 4C 24 50 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 56 18")
WIN_STARTUP_TARGET_V5 = _byte_pattern(
    "48 89 C7 48 8D 5C 24 28 B9 04 00 00 00 E8 ?? ?? ?? ?? "
    "48 89 44 24 28 4C 8D 40 04 4C 89 44 24 38 C7 00 00 00 80 00")
WIN_STARTUP_TARGET_V6 = _byte_pattern(
    "48 89 C3 41 BD 01 00 00 00 4C 8D 74 24 40 B9 04 00 00 00 E8 ?? ?? ?? ?? "
    "48 89 44 24 28 4C 89 6C 24 38 C7 00 00 00 80 00")
WIN_EXTENSION_FILTER_V11 = _byte_pattern(
    "41 83 78 50 02 ?? ?? 4D 8B 88 28 02 00 00 41 8B 51 50 "
    "41 80 B8 08 02 00 00 00 75 ?? 45 8B 81 88 00 00 00 41 83 F8 01 0F 85 ?? ?? ?? ?? "
    "83 FA 05 74 ?? 83 FA 0A 0F 85 ?? ?? ?? ?? 48 8B 51 08 48 85 D2 0F 85 ?? ?? ?? ??")
WIN_STARTUP_V11 = _byte_pattern(
    "48 8B 6C 24 40 4C 39 F5 0F 85 ?? ?? ?? ?? "
    "48 8B 4C 24 48 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 56 18")
WIN_STARTUP_TARGET_V11 = _byte_pattern(
    "BB 01 00 00 00 4C 8D 6C 24 38 4D 89 F7 B9 04 00 00 00 49 89 C6 E8 ?? ?? ?? ?? "
    "48 89 44 24 20 48 89 5C 24 30 C7 00 00 00 80 00 48 89 5C 24 28 "
    "4C 8D 40 04 48 89 F9 48 89 C2 E8 ?? ?? ?? ??")
R155_S = re.compile(
    rb"\xba\x00\x00\x80\x00\xe8....\x84\xc0\x74."
    rb"\x83\x7b\x50\x02(?P<j>\x7f.)"
    rb"\x48\x8b\x8b\x28\x02\x00\x00\x8b\x41\x50"
    rb"\x80\xbb\x08\x02\x00\x00\x00\x75.", F)
