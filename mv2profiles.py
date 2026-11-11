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

EXPECT = {"A": 4, "B": 1, "C": 1, "D": 1, "M": 1, "S": 1, "U": 1}
EXPECT_PROFILES = {
    "Chrome / Chrome for Testing 159–160 Linux x86-64 (complete install policy)": {
        "N1": 1, "N2": 1, "N3": 1, "N4": 1, "N5": 1, "N6": 1, "V": 1, "H": 1,
    },
    "Chrome for Testing Canary 159.0.8151.0 Windows x86-64": {
        "N1": 2, "N2": 1, "N3": 1, "N4": 1, "N5": 1, "N6": 1, "V": 1,
    },
    "Chromium 154-compatible ELF layout": EXPECT,
    "Chromium distro ELF layout (alternate MustRemainDisabled call encoding)": {
        "A": 4, "B": 1, "C": 1, "D": 0, "H": 1, "M": 1, "S": 0, "U": 1,
    },
    "Chromium distro ELF layout (ManifestV2Handler startup gates)": {
        "A": 4, "B": 0, "C": 1, "D": 1, "H": 0, "I": 0, "M": 0,
        "S": 0, "T": 1, "U": 0, "V": 0,
    },
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
    "Google Chrome 155.0.8059.79 Linux ELF x86-64": {
        "A": 4, "B": 0, "C": 1, "D": 1, "S": 0, "U": 1,
        "M": 1, "I": 0, "V": 0, "H": 1,
    },
    "Chromium 158 centralized MV2 policy x86-64": {"A": 0, "B": 0, "C": 0, "D": 0, "S": 0,
                                                 "U": 0, "M": 0, "I": 0, "V": 2, "H": 1},
    "Chromium 158.0.8120.0 Windows PE x86-64": {"A": 0, "B": 0, "C": 0, "D": 0, "S": 0,
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
    "Google Chrome for Testing 158.0.8113.0 / 8116.0 / 8117.2 Windows PE x86-64": {
        "A": 1, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 0, "W5_157": 0, "W5_158": 1, "W6": 1,
    },
    "Chrome 159.0.8130.0 Windows PE x86-64": {
        "A": 1, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 0,
        "W5_157": 0, "W5_158": 0, "W5_159": 1, "W6": 1,
    },
    "Google Chrome Beta 158.0.8127.2 / 8127.18 Windows PE x86-64": {
        "A": 1, "W1": 2, "W2": 1, "W3": 1, "W4": 1,
        "W5_158_8127": 1, "W6": 1,
    },
    "Google Chrome for Testing Canary 159.0.8141.0 Windows PE x86-64": {
        "A": 1, "W1": 2, "W2": 1, "W3": 1, "W4": 1,
        "W5_159_8141": 1, "W6": 1,
    },
    "Google Chrome for Testing Dev 159.0.8144.0 Windows PE x86-64": {
        "A": 1, "W1": 2, "W2": 1, "W3": 1, "W4": 1,
        "W5_159_8144": 1, "W6": 1,
    },
    "Google Chrome for Testing Canary 159.0.8146.0 Windows PE x86-64": {
        "A": 1, "W1": 2, "W2": 1, "W3": 1, "W4": 1,
        "W5_159_8146": 1, "W6": 1,
    },
    "Google Chrome for Testing 158.0.8106.0 Windows PE x86-64": {
        "A": 1, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 0, "W5_157": 0, "W5_158": 0, "W5_158_8106": 1, "W6": 1,
    },
    "Google Chrome for Testing 156.0.8078.48 Windows PE x86-64": {
        "A": 1, "B": 0, "C": 0, "D": 0, "S": 0, "U": 0,
        "M": 0, "I": 0, "V": 0, "H": 0,
        "W1": 2, "W2": 1, "W3": 1, "W4": 1, "W5": 0, "W5_156": 1,
        "W5_157": 0, "W5_158": 0, "W5_158_8106": 0, "W6": 1,
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
RU_ALT = re.compile(
    rb"\x41\x83\x7e\x50\x02(?P<j>\x7e\x51|\x90\x90)"
    rb"\x45\x31\xf6\xeb\x16\xb8\x00\x40\x00\x00\xeb\x05"
    rb"\xb8\x00\x00\x40\x00\x48\x85\xdb\x74\x02\x89\x03\x41\xb6\x01"
    rb"\xf6\x45\xc0\x01\x74\x11\x48\x8b\x75\xc0\x48\x8b\x7d\xd0"
    rb"\x48\x83\xe6\xfe\xe8....\x64\x48\x8b\x04\x25\x28\x00\x00\x00", F)

# Chrome 155 changed the inlined checker layout. These signatures are anchored
# on the manifest_version compare and the distinct surrounding helper flow.
# Every branch target is checked below before a site is accepted.
R155_M = re.compile(
    rb"\x41\x83\x7e\x50\x02(?P<j>\x0f\x8f....|\x90\xe9....)"
    rb"\x49\x8b\x8e\x28\x02\x00\x00\x8b\x41\x50"
    rb"\x41\x80\xbe\x08\x02\x00\x00\x00\x75."
    rb"\x8b\x89\x88\x00\x00\x00\x83\xf9\x01\x75.", F)
R155_M_ALT = re.compile(
    rb"\x83\x7e\x50\x02(?P<j>\x0f\x85....|\x90\xe9....)\x49\x89\xf6"
    rb"\x80\xbe\x08\x02\x00\x00\x00\x0f\x85....\x41\x89\xd7\x4c\x8b\x27"
    rb"\x49\x8b\xb6\x28\x02\x00\x00\x8b\x86\x88\x00\x00\x00"
    rb"\x83\xf8\x08\x74.\x83\xf8\x01\x0f\x85....", F)
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
R155_D_ALT = re.compile(
    rb"\x83\x78\x50\x02(?P<j>\x0f\x8f....|\x90\xe9....)"
    rb"\x48\x8b\x90\x28\x02\x00\x00\x8b\x4a\x50\x80\xb8\x08\x02\x00\x00\x00\x75."
    rb"\x8b\x92\x88\x00\x00\x00\x83\xfa\x08\x0f\x87....\x41\x0f\xa3\xd4"
    rb"\x0f\x83....\x83\xf9\x05\x0f\x84....\x83\xf9\x0a\x0f\x84....", F)
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
WIN_INSTALL_V13_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA BA 1F 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
WIN_INSTALL_V14_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA 3F 20 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
WIN_INSTALL_V15_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA 8B 20 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
# Chrome Beta 158.0.8127.2 uses resource 8302 (0x206E). The policy,
# extension-type and shared-cleanup branches are checked independently.
WIN_INSTALL_V16_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA 6E 20 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
# Chrome for Testing Canary 159.0.8141.0: resource 8332 (0x208C),
# paired with the validated V11 startup-disable loop rather than V13.
WIN_INSTALL_V17_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA 8C 20 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
# Chrome for Testing Dev 159.0.8144.0 uses resource 8202 (0x200A).
WIN_INSTALL_V18_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA 0A 20 00 00 E8 ?? ?? ?? ?? "
    "48 8D 4C 24 60 C6 41 F8 00 48 8D 5C 24 58 E9 ?? ?? ?? ??")
# Chrome for Testing Canary 159.0.8146.0 uses resource 8212 (0x2014).
WIN_INSTALL_V19_ERROR = _byte_pattern(
    "4C 8D B4 24 50 02 00 00 4C 89 F1 BA 14 20 00 00 E8 ?? ?? ?? ?? "
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
# Chrome for Testing 158.0.8116.0 uses the same startup-disable flow but
# allocates its reason object through a different helper/register layout.
WIN_STARTUP_V12 = _byte_pattern(
    "48 8B 6C 24 40 4C 39 FD 0F 85 ?? ?? ?? ?? "
    "48 8B 4C 24 48 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 56 18")
WIN_STARTUP_TARGET_V12 = _byte_pattern(
    "BB 01 00 00 00 4C 8D 74 24 38 4D 89 FC B9 04 00 00 00 48 BA ?? ?? ?? ?? ?? ?? ?? ?? "
    "49 89 C7 E8 ?? ?? ?? ?? 48 89 44 24 20 48 89 5C 24 30 C7 00 00 00 80 00 "
    "48 89 5C 24 28 4C 8D 40 04 48 89 F9 48 89 C2 E8 ?? ?? ?? ??")
WIN_STARTUP_V13 = _byte_pattern(
    "48 8B 6C 24 48 4C 39 F5 0F 85 ?? ?? ?? ?? "
    "48 8B 4C 24 50 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 56 18")
WIN_STARTUP_TARGET_V13 = _byte_pattern(
    "BB 01 00 00 00 4C 8D 6C 24 40 4D 89 F7 B9 04 00 00 00 49 89 C6 E8 ?? ?? ?? ?? "
    "48 89 44 24 28 48 89 5C 24 38 C7 00 00 00 80 00 48 89 5C 24 30 "
    "4C 8D 40 04 48 89 F9 48 89 C2 E8 ?? ?? ?? ??")
R155_S = re.compile(
    rb"\xba\x00\x00\x80\x00\xe8....\x84\xc0\x74."
    rb"\x83\x7b\x50\x02(?P<j>\x7f.)"
    rb"\x48\x8b\x8b\x28\x02\x00\x00\x8b\x41\x50"
    rb"\x80\xbb\x08\x02\x00\x00\x00\x75.", F)

def _policy_pattern(before, original, patched, after, legacy=None):
    alternatives = [original, patched] + ([legacy] if legacy else [])
    return re.compile(_byte_pattern(before).pattern + b"(?P<j>" +
                      b"|".join(re.escape(bytes.fromhex(value)) for value in alternatives) + b")" +
                      _byte_pattern(after).pattern, F)

# Earlier profiles skipped the entire re-enable helper. Recognize those exact
# old bytes for upgrade, but require the normal reason-removal path now.
R159_LEGACY_REENABLE = {"ELF": bytes.fromhex('ebef'), "PE": bytes.fromhex('ebf2')}

# Chrome / Chrome for Testing 159.0.8151.0: inlined policy gates.
# Full control-flow windows preserve type/location exclusions, disable reasons,
# epilogues and internal branch distances. Linker addresses alone are masked.
# (format, kind, pattern, original, patched, detailed offset, safe offset,
#  safe bytes, description). Offsets are relative to the matched window.
R159_POLICY = [
    ('ELF', 'N1', _policy_pattern(
        '83 7E 50 02',
        '7e03', '9090',
        '31 C0 C3 55 48 89 E5 48 8B 86 28 02 00 00 8B 48 50 80 BE 08 '
        '02 00 00 00 75 17 8B 90 88 00 00 00 31 C0 83 FA 08 77 18 BE '
        '0A 01 00 00 0F A3 D6 73 0E 83 F9 05 0F 95 C2 83 F9 0A 0F 95 '
        'C0 20 D0 5D EB C0'
        ), bytes.fromhex('7e03'), bytes.fromhex('9090'), 9, 6,
        bytes.fromhex('31c0c3'), 'extension impact checker'),
    ('ELF', 'N2', _policy_pattern(
        '41 83 7E 50 02',
        '7e3e', '9090',
        '45 31 F6 80 7D E7 00 0F 88 8C 00 00 00 44 89 F0 48 83 C4 18 '
        '5B 41 5E 41 5F 5D C3 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 '
        'C0 74 B5 E8 ?? ?? ?? ?? 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? '
        'EB ?? 49 8B 8E 28 02 00 00 8B 41 50 41 80 BE 08 02 00 00 00 '
        '75 18 8B 89 88 00 00 00 45 31 F6 83 F9 08 77 A3 BA 0A 01 00 '
        '00 0F A3 CA 73 99 45 31 F6 83 F8 05 74 91 83 F8 0A 74 8C B8 '
        '00 00 80 00 EB 0C B8 00 40 00 00 EB 05 B8 00 00 40 00 48 85 '
        'DB 74 02 89 03 41 B6 01 E9 6A FF FF FF'
        ), bytes.fromhex('7e3e'), bytes.fromhex('9090'), 69, 7,
        bytes.fromhex('4531f6'), 'MustRemainDisabled false-result path'),
    ('ELF', 'N3', _policy_pattern(
        '83 7E 50 02',
        '7456', '9090',
        '48 83 C4 30 5B 41 5E 5D C3 41 89 D6 E8 ?? ?? ?? ?? 48 89 C3 '
        '48 8B 7D E8 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 BA 00 00 80 00 '
        'E8 ?? ?? ?? ?? 45 84 F6 74 08 84 C0 0F 85 15 01 00 00 0F B6 '
        'D8 83 C3 03 48 8B 45 E8 48 8B 80 28 02 00 00 EB ?? 48 8D 05 '
        '?? ?? ?? ?? EB ?? 80 BE 08 02 00 00 00 75 A1 48 8B 3F 48 8B '
        '86 28 02 00 00 8B 88 88 00 00 00 83 F9 08 74 05 83 F9 01 75 '
        '87 48 89 75 E8 8B 48 50 31 DB 83 F9 05 74 09 83 F9 0A 0F 85 '
        '79 FF FF FF'
        ), bytes.fromhex('7456'), bytes.fromhex('9090'), 92, 6,
        bytes.fromhex('4883c4305b415e5dc3'), 'startup disable helper return'),
    ('ELF', 'N4', _policy_pattern(
        '48 83 C4 08 5B 41 5E 41 5F 5D C3 83 7B 50 02',
        '7e2e', '9090',
        '49 8B 7E 18 E8 ?? ?? ?? ?? 49 89 C6 48 89 DF E8 ?? ?? ?? ?? '
        '4C 89 F7 48 89 C6 BA 00 00 80 00 48 83 C4 08 5B 41 5E 41 5F '
        '5D E9 ?? ?? ?? ?? 48 8B 8B 28 02 00 00 8B 41 50 80 BB 08 02 '
        '00 00 00 75 15 8B 89 88 00 00 00 83 F9 08 77 B4 BA 0A 01 00 '
        '00 0F A3 CA 73 AA 83 F8 0A 74 A5 83 F8 05 74 A0 EB 8D'
        , legacy='ebef'), bytes.fromhex('7e2e'), bytes.fromhex('9090'), 63, 17,
        bytes.fromhex('498b7e18'), 're-enable helper removes unsupported-manifest reason'),
    ('PE', 'N1', _policy_pattern(
        '83 7A 50 02',
        '7e03', '9090',
        '31 C0 C3 48 8B 82 28 02 00 00 8B 48 50 80 BA 08 02 00 00 00 '
        '75 19 8B 90 88 00 00 00 31 C0 83 FA 08 77 DF 41 B8 0A 01 00 '
        '00 41 0F A3 D0 73 D3 83 F9 05 0F 95 C2 83 F9 0A 0F 95 C0 20 '
        'D0 EB C3'
        ), bytes.fromhex('7e03'), bytes.fromhex('9090'), 9, 6,
        bytes.fromhex('31c0c3'), 'extension impact checker (both copies)'),
    ('PE', 'N2', _policy_pattern(
        '83 7F 50 02',
        '7e38', '9090',
        '31 FF 80 7C 24 37 00 0F 88 8A 00 00 00 48 8B 44 24 48 48 31 '
        'E0 48 8B 0D ?? ?? ?? ?? 48 39 C1 75 0A 89 F8 48 83 C4 50 5B '
        '5F 5E C3 48 8B 4C 24 48 48 31 E1 E8 ?? ?? ?? ?? 48 8B 8F 28 '
        '02 00 00 8B 41 50 80 BF 08 02 00 00 00 75 17 8B 89 88 00 00 '
        '00 31 FF 83 F9 08 77 AA BA 0A 01 00 00 0F A3 CA 73 A0 31 FF '
        '83 F8 05 74 99 83 F8 0A 74 94 B8 00 00 80 00 EB 13 B8 00 00 '
        '40 00 EB 0C B8 00 40 00 00 EB 05 B8 00 01 00 00 48 85 F6 74 '
        '02 89 06 40 B7 01 E9 6B FF FF FF'
        ), bytes.fromhex('7e38'), bytes.fromhex('9090'), 62, 6,
        bytes.fromhex('31ff'), 'MustRemainDisabled false-result path'),
    ('PE', 'N3', _policy_pattern(
        '83 7A 50 02',
        '0f8481000000', '909090909090',
        '48 8B 84 24 80 00 00 00 48 31 E0 48 8B 0D ?? ?? ?? ?? 48 39 '
        'C1 75 0A 48 81 C4 88 00 00 00 5F 5E C3 48 8B 8C 24 80 00 00 '
        '00 48 31 E1 E8 ?? ?? ?? ?? 44 89 C7 E8 ?? ?? ?? ?? 48 89 C6 '
        '48 8B 4C 24 28 E8 ?? ?? ?? ?? 48 89 F1 48 89 C2 41 B8 00 00 '
        '80 00 E8 ?? ?? ?? ?? 40 84 FF 74 08 84 C0 0F 85 43 01 00 00 '
        '0F B6 F0 83 C6 03 48 8B 44 24 28 48 8B 80 28 02 00 00 EB ?? '
        '48 8D 05 ?? ?? ?? ?? EB ?? 80 BA 08 02 00 00 00 0F 85 72 FF '
        'FF FF 48 8B 09 48 8B 82 28 02 00 00 44 8B 88 88 00 00 00 41 '
        '83 F9 08 74 0A 41 83 F9 01 0F 85 51 FF FF FF 48 89 54 24 28 '
        '8B 50 50 31 F6 83 FA 05 74 09 83 FA 0A 0F 85 6A FF FF FF'
        ), bytes.fromhex('0f8481000000'), bytes.fromhex('909090909090'), 139, 10,
        bytes.fromhex('488b842480000000'), 'startup disable helper return'),
    ('PE', 'N4', _policy_pattern(
        '48 83 C4 20 5B 5F 5E C3 83 7E 50 02',
        '7e3a', '9090',
        '48 8B 7F 18 E8 ?? ?? ?? ?? 48 89 C1 48 89 FA 41 B0 01 E8 ?? '
        '?? ?? ?? 48 89 C7 48 89 F1 E8 ?? ?? ?? ?? 48 89 F9 48 89 C2 '
        '41 B8 00 00 80 00 48 83 C4 20 5B 5F 5E E9 ?? ?? ?? ?? 48 8B '
        '8E 28 02 00 00 8B 41 50 80 BE 08 02 00 00 00 75 15 8B 89 88 '
        '00 00 00 83 F9 08 77 A8 BA 0A 01 00 00 0F A3 CA 73 9E 83 F8 '
        '0A 74 99 83 F8 05 74 94 EB 84'
        , legacy='ebf2'), bytes.fromhex('7e3a'), bytes.fromhex('9090'), 72, 14,
        bytes.fromhex('488b7f18'), 're-enable helper removes unsupported-manifest reason'),
]

# UserMayInstall's version gate precedes the outlined detail block by hundreds
# of bytes. Match the entry and detail separately, then validate every policy
# exclusion's return to the normal UserMayLoad/callback path in mv2ctl.py.
# The resource IDs were checked against each official build's en-US.pak.
R159_INSTALL = [
    ('ELF', re.compile(
        rb'\x49\x8b\x7f\x08\xe8....\x48\x85\xc0\x74\x0a\x83\x7b\x50\x02'
        rb'(?P<j>\x0f\x8e....|\x90{6})'
        rb'(?P<safe>\x4c\x8d\x65\xc0\x4c\x89\xff\x48\x89\xde\x4c\x89\xe2\xe8....)', F),
     re.compile(
        rb'\x48\x8b\x8b\x28\x02\x00\x00\x8b\x41\x50'
        rb'\x80\xbb\x08\x02\x00\x00\x00\x75\x1d'
        rb'\x8b\x89\x88\x00\x00\x00\x83\xf9\x08(?P<ja>\x0f\x87....)'
        rb'\xba\x0a\x01\x00\x00\x0f\xa3\xca(?P<jae>\x0f\x83....)'
        rb'\x83\xf8\x05(?P<je1>\x0f\x84....)\x83\xf8\x0a(?P<je2>\x0f\x84....)'
        rb'\x4c\x8d\x7d\xc0\x4c\x89\xff\xbe(?P<resource>....)\xe8....'
        rb'\x48\x8d\xbd\x40\xff\xff\xff\xc6\x47\xf8\x00', F),
     frozenset((0x201b, 0x14c9))),
    ('PE', re.compile(
        rb'\x48\x85\xc0\x74\x0a\x83\x7f\x50\x02'
        rb'(?P<j>\x0f\x8e....|\x90{6})'
        rb'(?P<safe>\x4c\x8d\xb4\x24\x50\x02\x00\x00\x48\x89\xd9'
        rb'\x48\x89\xfa\x4d\x89\xf0\xe8....)', F),
     re.compile(
        rb'\x48\x8b\x8f\x28\x02\x00\x00\x8b\x41\x50'
        rb'\x80\xbf\x08\x02\x00\x00\x00\x75\x1d'
        rb'\x8b\x89\x88\x00\x00\x00\x83\xf9\x08(?P<ja>\x0f\x87....)'
        rb'\xba\x0a\x01\x00\x00\x0f\xa3\xca(?P<jae>\x0f\x83....)'
        rb'\x83\xf8\x05(?P<je1>\x0f\x84....)\x83\xf8\x0a(?P<je2>\x0f\x84....)'
        rb'\x4c\x8d\xb4\x24\x50\x02\x00\x00\x4c\x89\xf1'
        rb'\xba(?P<resource>....)\xe8....\x48\x8d\x4c\x24\x60\xc6\x41\xf8\x00', F),
     frozenset((0x200d,))),
]

# DisableAffectedExtensions: skip collecting MV2 entries for startup disable.
# Include the complete iteration, 0x800000 insertion and outlined policy tail.
R159_POLICY.extend([
    ('ELF', "N6", _policy_pattern(
        '41 BF 0A 01 00 00 48 8B 4E 38 83 79 50 02',
        '0f8e0a010000', "909090909090",
        '48 8B 46 08 48 85 C0 75 5C 48 89 F0 48 8B 76 10 48 3B 06 75 '
        'F4 48 89 75 B8 48 3B 75 D0 75 D3 48 8D 7D D0 E8 ?? ?? ?? ?? '
        '4C 8D 75 B8 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 7B 18 E8 ?? ?? ?? '
        '?? 48 89 C3 4C 8B 65 A0 48 8D 45 A8 49 39 C4 75 25 48 8B 7D '
        'A8 E8 ?? ?? ?? ?? 48 83 C4 38 5B 41 5C 41 5D 41 5E 41 5F 5D '
        'C3 48 89 C6 48 8B 00 48 85 C0 75 F5 EB A3 49 BD C5 E5 52 64 '
        'EE BD 04 05 49 8B 7C 24 20 E8 ?? ?? ?? ?? 49 89 C7 BF 04 00 '
        '00 00 4C 89 EE E8 ?? ?? ?? ?? 48 89 45 B8 B9 01 00 00 00 48 '
        '89 4D C8 C7 00 00 00 80 00 48 89 4D C0 48 8D 50 04 4C 89 F7 '
        '48 89 C6 E8 ?? ?? ?? ?? 48 89 DF 4C 89 FE 4C 89 F2 E8 ?? ?? '
        '?? ?? 4C 89 75 D0 48 8D 7D D0 E8 ?? ?? ?? ?? 49 8B 44 24 08 '
        '48 85 C0 74 19 49 89 C4 48 8B 00 48 85 C0 75 F5 48 8D 45 A8 '
        '49 39 C4 75 87 E9 53 FF FF FF 4C 89 E0 4D 8B 64 24 10 49 3B '
        '04 24 75 F2 EB E2 48 8B 91 28 02 00 00 8B 42 50 80 B9 08 02 '
        '00 00 00 75 19 8B 8A 88 00 00 00 83 F9 08 0F 87 D4 FE FF FF '
        '41 0F A3 CF 0F 83 CA FE FF FF 83 F8 05 0F 84 C1 FE FF FF 83 '
        'F8 0A 0F 84 B8 FE FF FF 48 83 C6 38 4C 89 F7 E8 ?? ?? ?? ?? '
        '48 8B 75 B8 E9 A3 FE FF FF'
        ), bytes.fromhex('0f8e0a010000'), b"\x90" * 6, 286, 20,
        bytes.fromhex('488b4608'), "DisableAffectedExtensions next-item path"),
    ('PE', "N6", _policy_pattern(
        'BA 0A 01 00 00 4C 8B 49 38 41 83 79 50 02',
        '0f8e44020000', "909090909090",
        '4C 8B 41 08 4D 85 C0 0F 85 F6 00 00 00 49 89 C8 48 8B 49 10 '
        '4C 3B 01 75 F4 48 39 C1 75 D3 48 8B 5E 18 E8 ?? ?? ?? ?? 48 '
        '89 C1 48 89 DA 41 B0 01 E8 ?? ?? ?? ?? 48 8B 6C 24 48 4C 39 '
        'FD 0F 85 53 01 00 00 48 8B 4C 24 50 E8 ?? ?? ?? ?? 48 8B 0D '
        '?? ?? ?? ?? 48 8B 56 18 48 8B 01 48 8B 80 38 03 00 00 FF 15 '
        '?? ?? ?? ?? 84 C0 74 5D 48 8B 4E 18 E8 ?? ?? ?? ?? 48 89 C7 '
        '48 89 74 24 48 4C 8B 70 08 48 8D 58 10 49 39 DE 74 2E 48 8D '
        '74 24 48 49 8B 56 38 48 89 F1 41 B0 01 E8 ?? ?? ?? ?? 49 8B '
        '46 08 48 85 C0 75 6C 4C 89 F0 4D 8B 76 10 49 3B 06 75 F4 49 '
        '39 DE 75 D7 48 8B 5F 28 48 83 C7 30 48 39 FB 0F 85 8D 00 00 '
        '00 48 8B 44 24 68 48 31 E0 48 8B 0D ?? ?? ?? ?? 48 39 C1 75 '
        '19 0F 28 74 24 70 48 81 C4 88 00 00 00 5B 5D 5F 5E 41 5C 41 '
        '5D 41 5E 41 5F C3 48 8B 4C 24 68 48 31 E1 E8 ?? ?? ?? ?? 4C '
        '89 C1 4D 8B 00 4D 85 C0 75 F5 E9 06 FF FF FF 49 89 C6 48 8B '
        '00 48 85 C0 75 F5 EB 93 48 8B 57 38 48 89 F1 E8 ?? ?? ?? ?? '
        '48 8B 47 08 48 85 C0 74 10 48 89 C7 48 8B 00 48 85 C0 75 F5 '
        'E9 ?? ?? ?? ?? 48 89 F8 48 8B 7F 10 48 3B 07 75 F4 E9 ?? ?? '
        '?? ?? 48 8D 74 24 48 48 8B 53 38 48 89 F1 45 31 C0 E8 ?? ?? '
        '?? ?? 48 8B 43 08 48 85 C0 74 15 48 89 C3 48 8B 00 48 85 C0 '
        '75 F5 48 39 FB 75 D8 E9 41 FF FF FF 48 89 D8 48 8B 5B 10 48 '
        '3B 03 75 F4 EB E8 BB 01 00 00 00 4C 8D 74 24 40 4D 89 FC B9 '
        '04 00 00 00 48 BA C5 E5 52 64 EE BD 04 05 49 89 C7 E8 ?? ?? '
        '?? ?? 48 89 44 24 28 48 89 5C 24 38 C7 00 00 00 80 00 48 89 '
        '5C 24 30 4C 8D 40 04 48 89 F9 48 89 C2 E8 ?? ?? ?? ?? 48 8B '
        '4D 20 E8 ?? ?? ?? ?? 4D 89 FD 4C 89 F9 48 89 C2 49 89 F8 E8 '
        '?? ?? ?? ?? 48 89 7C 24 40 4C 89 F1 E8 ?? ?? ?? ?? 48 89 E8 '
        '48 8B 4D 08 48 85 C9 74 22 48 89 C8 48 8B 09 48 85 C9 75 F5 '
        '4D 89 E7 48 89 C5 4C 39 E0 4C 89 E8 0F 85 72 FF FF FF E9 10 '
        'FE FF FF 48 89 C1 48 8B 50 10 48 89 D0 48 3B 0A 75 F1 EB D8 '
        '4D 8B 91 28 02 00 00 45 8B 42 50 41 80 B9 08 02 00 00 00 75 '
        '1B 45 8B 8A 88 00 00 00 41 83 F9 08 0F 87 96 FD FF FF 44 0F '
        'A3 CA 0F 83 8C FD FF FF 41 83 F8 05 0F 84 82 FD FF FF 41 83 '
        'F8 0A 0F 84 78 FD FF FF 4C 8D 41 38 49 89 CC 48 89 D9 4C 89 '
        'F2 49 89 C5 E8 ?? ?? ?? ?? BA 0A 01 00 00 4C 89 E1 4C 89 E8 '
        'E9 53 FD FF FF'
        ), bytes.fromhex('0f8e44020000'), b"\x90" * 6, 600, 20,
        bytes.fromhex('4c8b4108'), "DisableAffectedExtensions next-item path"),
])
