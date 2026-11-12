"""Block-level MV2 proofs and a bounded, non-authorizing coverage audit.

Functions are not the unit of patching: two branches in the same function can
have independent policy/error blocks. Signatures supply instruction landmarks;
actual control-flow edges associate those landmarks and authorize each edit.
"""
from collections import defaultdict, deque
from dataclasses import dataclass
import re
import struct

try:
    import capstone
    from capstone import x86_const as x86
except ImportError:
    capstone = None
    x86 = None


@dataclass(frozen=True)
class BlockProof:
    branch: int
    entry: int
    detail: int
    end: int
    safe: int
    original: bytes
    replacement: bytes
    state: str
    evidence: tuple


def install_blocks(mm, segs, fmt, rules, decode_jump):
    """Associate every install gate with its own verified detail/exit block.

    Original gates identify the detail by their taken edge. Patched gates have
    lost that displacement, so reconstruct it only from a unique detail whose
    four exclusions point to this gate's normal policy path. Nearby independent
    blocks do not make one another ambiguous, and no function-entry guess or
    fixed forward byte window is needed.
    """
    proofs, rejects = [], []
    for required_fmt, entry_rx, detail_rx, resources in rules:
        if fmt != required_fmt:
            continue
        for seg in segs:
            end = seg.off + seg.filesz
            entries = list(entry_rx.finditer(mm, seg.off, end))
            details = list(detail_rx.finditer(mm, seg.off, end))
            by_target = {detail.start(): detail for detail in details}
            by_exit = defaultdict(list)
            valid = {}
            for detail in details:
                exits = [decode_jump(mm, detail.start(name))
                         for name in ('ja', 'jae', 'je1', 'je2')]
                targets = {exit[0] for exit in exits if exit is not None}
                resource = struct.unpack_from('<I', mm, detail.start('resource'))[0]
                if (any(exit is None for exit in exits) or len(targets) != 1 or
                        resource not in resources):
                    continue
                safe = targets.pop()
                if seg.off <= safe < end:
                    by_exit[safe].append(detail)
                    valid[detail.start()] = safe
            used = set()
            for entry in entries:
                branch, safe = entry.start('j'), entry.start('safe')
                current = bytes(mm[branch:branch + 6])
                if current[:2] == b'\x0f\x8e':
                    edge = decode_jump(mm, branch)
                    detail = by_target.get(edge[0]) if edge else None
                    candidates = [detail] if detail is not None else []
                elif current == b'\x90' * 6:
                    candidates = by_exit.get(safe, [])
                else:
                    candidates = []
                if len(candidates) != 1 or valid.get(candidates[0].start()) != safe:
                    rejects.append(('N5', entry.start(),
                                    'install gate has no unique verified detail/policy edge'))
                    continue
                detail = candidates[0]
                displacement = detail.start() - branch - 6
                if not -(1 << 31) <= displacement < (1 << 31):
                    rejects.append(('N5', branch, 'install detail is outside rel32 range'))
                    continue
                original = b'\x0f\x8e' + struct.pack('<i', displacement)
                if current not in (original, b'\x90' * 6):
                    rejects.append(('N5', branch, 'install branch misses its verified detail'))
                    continue
                proofs.append(BlockProof(
                    branch, entry.start(), detail.start(), detail.end(), safe,
                    original, b'\x90' * 6,
                    'original' if current == original else 'patched',
                    ((entry.start(), entry.end()), (detail.start(), detail.end()))))
                used.add(detail.start())
            for detail in details:
                if detail.start() not in used:
                    rejects.append(('N5', detail.start(),
                                    'unbound MV2 install error block; no validated controlling gate'))
    return proofs, rejects


def profile_matches(counts, expected, repeatable=()):
    """Retain required roles/copy minima; count additional proven blocks too."""
    return all(actual >= expected.get(kind, 0)
               if kind in repeatable and expected.get(kind, 0) else
               actual == expected.get(kind, 0)
               for kind, actual in counts.items())


def unique_sites(sites):
    """Deduplicate each role proof; allow identical edits shared by legacy roles."""
    found, roles, rejects = {}, {}, []
    for site in sites:
        previous = found.get(site.jpos)
        if previous is None:
            found[site.jpos] = site
        elif (previous.orig, previous.new, previous.state) != (
                site.orig, site.new, site.state):
            rejects.append((site.kind, site.jpos, 'conflicting proofs for one branch'))
            continue
        # Legacy profiles count independently validated roles that can share
        # one instruction (e.g. M and D). Preserve those landmarks, but collapse
        # duplicate proofs of the same role. The writer deduplicates edits.
        roles.setdefault((site.jpos, site.kind), site)
    edits = sorted(found.values(), key=lambda site: site.jpos)
    for left, right in zip(edits, edits[1:]):
        if right.jpos < left.jpos + max(len(left.orig), len(left.new)):
            rejects.append((right.kind, right.jpos, 'validated edits overlap instruction bytes'))
    return sorted(roles.values(), key=lambda site: (site.jpos, site.kind)), rejects


# Seed instructions, not function prologues. Include REX, disp32 and SIB forms;
# Capstone verifies the operands and the immediately controlled branch below.
_VERSION_SEEDS = re.compile(
    rb'[\x40-\x4f]?(?:\x83[\x78-\x7f]\x50\x02|'
    rb'\x81[\x78-\x7f]\x50\x02\x00\x00\x00|'
    rb'\x83[\xb8-\xbf]\x50\x00\x00\x00\x02|'
    rb'\x83\x7c.\x50\x02|\x83\xbc.\x50\x00\x00\x00\x02)', re.DOTALL)
_LOADED_VERSION_SEEDS = re.compile(
    rb'[\x40-\x4f]?\x8b[\x40-\x7f]\x50[\x40-\x4f]?\x83[\xf8-\xff]\x02', re.DOTALL)


def _manifest_compare(ins):
    return (ins.mnemonic == 'cmp' and len(ins.operands) == 2 and
            ins.operands[0].type == x86.X86_OP_MEM and
            ins.operands[0].mem.disp == 0x50 and
            ins.operands[1].type == x86.X86_OP_IMM and ins.operands[1].imm == 2)


def _loaded_compare(load, compare):
    return (load is not None and load.mnemonic == 'mov' and len(load.operands) == 2 and
            load.operands[0].type == x86.X86_OP_REG and
            load.operands[1].type == x86.X86_OP_MEM and load.operands[1].mem.disp == 0x50 and
            compare.mnemonic == 'cmp' and len(compare.operands) == 2 and
            compare.operands[0].type == x86.X86_OP_REG and
            compare.operands[0].reg == load.operands[0].reg and
            compare.operands[1].type == x86.X86_OP_IMM and compare.operands[1].imm == 2)


def _comparisons(mm, seg, decoder):
    end = seg.off + seg.filesz
    for pattern in (_VERSION_SEEDS, _LOADED_VERSION_SEEDS):
        for match in pattern.finditer(mm, seg.off, end):
            off = match.start()
            first = next(decoder.disasm(bytes(mm[off:min(off + 15, end)]), off, count=1), None)
            if first is None:
                continue
            if pattern is _VERSION_SEEDS:
                if _manifest_compare(first):
                    yield off, first
            else:
                pc = off + first.size
                compare = next(decoder.disasm(bytes(mm[pc:min(pc + 15, end)]), pc, count=1), None)
                if compare is not None and _loaded_compare(first, compare):
                    yield pc, compare


def _landmarks(mm, seg, seed, roots, decoder):
    """Bounded local CFG: follow conditional/direct edges, stop at calls/returns.

    Do not borrow evidence from a second manifest gate. Calls are opaque rather
    than guessed to return register/field values. This audit only rejects strong
    unclassified candidates; it never manufactures a patch authorization.
    """
    pending, visited = deque(roots), set()
    offsets, comparisons, mask, bit_test = set(), set(), False, False
    low, high = max(seg.off, seed - 64), min(seg.off + seg.filesz, seed + 0x4000)
    while pending and len(visited) < 384:
        pc = pending.popleft()
        previous = None
        while low <= pc < high and pc not in visited and len(visited) < 384:
            visited.add(pc)
            ins = next(decoder.disasm(bytes(mm[pc:min(pc + 15, high)]), pc, count=1), None)
            if ins is None or _manifest_compare(ins) or _loaded_compare(previous, ins):
                break
            if ins.mnemonic.startswith('call') or ins.mnemonic.startswith('ret'):
                break
            for operand in ins.operands:
                if operand.type == x86.X86_OP_MEM:
                    offsets.add(operand.mem.disp)
                elif operand.type == x86.X86_OP_IMM and operand.imm == 0x10a:
                    mask = True
            if ins.mnemonic == 'cmp' and len(ins.operands) == 2:
                if ins.operands[1].type == x86.X86_OP_IMM:
                    comparisons.add(ins.operands[1].imm)
            bit_test |= ins.mnemonic == 'bt'
            following = pc + ins.size
            if ins.mnemonic.startswith('j'):
                target = next((op.imm for op in ins.operands if op.type == x86.X86_OP_IMM), None)
                if target is not None:
                    pending.append(target)
                if ins.mnemonic != 'jmp':
                    pending.append(following)
                break
            if ins.mnemonic in ('int3', 'ud2', 'ud1', 'hlt'):
                break
            previous, pc = ins, following
    return ({0x208, 0x228, 0x88} <= offsets and {5, 10} <= comparisons and
            bit_test and (mask or 8 in comparisons))


def audit_unclassified(mm, segs, sites):
    """Find additional MV2 comparisons even inside another proof's byte span.

    Classification is keyed by the actual branch instruction. A broad regex
    window, a function entry, or satisfying profile minima never hides a second
    block. These are coverage alarms, not automatic edits of unknown code.
    """
    if capstone is None:
        return [('coverage', 0, 'Capstone is required for modern MV2 block coverage validation')]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    known = {site.jpos for site in sites}
    rejects, seen = [], set()
    for seg in segs:
        end = seg.off + seg.filesz
        for off, ins in _comparisons(mm, seg, decoder):
            pc = off + ins.size
            # Permit padding, but never skip a real intervening instruction.
            for _ in range(7):
                branch = next(decoder.disasm(bytes(mm[pc:min(pc + 15, end)]), pc, count=1), None)
                if branch is None or branch.mnemonic != 'nop':
                    break
                pc += branch.size
            if pc in known or pc in seen or branch is None:
                continue
            if not branch.mnemonic.startswith('j') or branch.mnemonic == 'jmp':
                continue
            target = next((op.imm for op in branch.operands if op.type == x86.X86_OP_IMM), None)
            if target is None:
                continue
            seen.add(pc)
            if _landmarks(mm, seg, off, (target, pc + branch.size), decoder):
                rejects.append(('coverage', pc,
                                'unclassified MV2 block with flag/type/location control flow; '
                                'profile minima do not authorize this branch'))
    return rejects
