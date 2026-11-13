"""Block-level MV2 proofs and a bounded, non-authorizing coverage audit.

Functions are not the unit of patching: two branches in the same function can
have independent policy/error blocks. Signatures supply instruction landmarks;
actual control-flow edges associate those landmarks and authorize each edit.
"""
from collections import defaultdict, deque
from dataclasses import dataclass
import re
from pathlib import Path
import struct

try:
    import capstone
    from capstone import x86_const as x86
except ImportError:
    capstone = None
    x86 = None


def _register_root(decoder, register):
    """Canonical 64-bit register name for pointer/value liveness checks."""
    name = decoder.reg_name(register)
    if name.startswith('e'):
        return 'r' + name[1:]
    if name.startswith('r') and name[-1:] in ('d', 'w', 'b') and name[1:-1].isdigit():
        return name[:-1]
    return name


UNSUPPORTED_MANIFEST_MESSAGE = (
    'Cannot install extension because it uses an unsupported manifest version.')


def locale_pack_for(binary):
    """Locate English assets for Linux and versioned Windows distributions."""
    directory = Path(binary).resolve().parent
    for root in (directory, directory.parent):
        for name in ('locales', 'Locales'):
            candidate = root / name / 'en-US.pak'
            if candidate.is_file():
                return candidate
    return None


def manifest_resource_ids(path):
    """Resolve the error by content, including DataPack aliases, never ID ranges.

    Validate the whole index before using an ID. When assets are present, their
    result replaces the historical numeric allowlist, even when it is empty.
    """
    pack = Path(path).read_bytes()
    if len(pack) < 12 or struct.unpack_from('<I', pack)[0] != 5:
        raise ValueError('unsupported en-US.pak header (expected DataPack v5)')
    encoding = pack[4]
    if encoding not in (1, 2):
        raise ValueError('en-US.pak has an unsupported text encoding')
    count, aliases = struct.unpack_from('<HH', pack, 8)
    table_end = 12 + (count + 1) * 6
    data_start = table_end + aliases * 4
    if data_start > len(pack):
        raise ValueError('truncated en-US.pak resource index')
    entries = [struct.unpack_from('<HI', pack, 12 + i * 6) for i in range(count + 1)]
    ids = [rid for rid, _ in entries[:-1]]
    if ids != sorted(set(ids)):
        raise ValueError('en-US.pak resource IDs are not unique and ordered')
    offsets = [offset for _, offset in entries]
    if offsets != sorted(offsets) or offsets[0] < data_start or offsets[-1] > len(pack):
        raise ValueError('invalid en-US.pak resource bounds')
    expected = UNSUPPORTED_MANIFEST_MESSAGE.encode('utf-8' if encoding == 1 else 'utf-16-le')
    matching = {i for i in range(count)
                if pack[offsets[i]:offsets[i + 1]] == expected}
    resolved = {entries[i][0] for i in matching}
    seen = set(ids)
    for i in range(aliases):
        rid, index = struct.unpack_from('<HH', pack, table_end + i * 4)
        if index >= count or rid in seen:
            raise ValueError('invalid en-US.pak resource alias')
        seen.add(rid)
        if index in matching:
            resolved.add(rid)
    return frozenset(resolved)


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


def unclassified_install_messages(mm, segs, resource_ids, bound_messages):
    """Audit direct localization calls independently of install-body signatures.

    A moved/changed policy block must not disappear merely because another
    install gate already satisfied a profile minimum. These references only
    reject missing coverage; they never authorize a new edit.
    """
    rejects = []
    if not resource_ids:
        return rejects
    # Resource numbers also occur as lengths and unrelated constants. Only
    # calls to an independently proven formatter, in its proven argument slot,
    # establish error-message coverage evidence.
    def formatter_key(position):
        width = 2 if mm[position:position + 2] == b'\x41\xb8' else 1
        call = position + width + 4
        return (bytes(mm[position:position + width]), call + 5 + struct.unpack_from('<i', mm, call + 1)[0])
    formatters = {formatter_key(position) for position in bound_messages}
    resource_pattern = re.compile(
        rb'(?:[\xbe\xba]|\x41\xb8)(?:' + b'|'.join(re.escape(struct.pack('<I', rid))
                                        for rid in sorted(resource_ids)) + rb')\xe8....', re.DOTALL)
    for seg in segs:
        for match in resource_pattern.finditer(mm, seg.off, seg.off + seg.filesz):
            # E8 is an explicit rel32 call; resolve it independently.
            _, target = formatter_key(match.start())
            if not any(s.off <= target < s.off + s.filesz for s in segs):
                continue
            if formatters and formatter_key(match.start()) not in formatters:
                continue
            if match.start() not in bound_messages:
                rejects.append(('coverage', match.start(),
                                'unsupported-manifest error call has no independently '
                                'validated install gate; inspect its policy control flow'))
    return rejects


def install_blocks(mm, segs, fmt, rules, decode_jump, resource_ids=None):
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
        accepted_resources = resources if resource_ids is None else resource_ids
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
                if resource not in accepted_resources:
                    rejects.append(('N5', detail.start('resource'),
                                    f'install error resource 0x{resource:X} is not verified; '
                                    'matching locales/en-US.pak must identify the unsupported-manifest message'))
                if (any(exit is None for exit in exits) or len(targets) != 1 or
                        resource not in accepted_resources):
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


def reenable_blocks(mm, segs, known_branches, fmt="ELF"):
    """Prove inlined re-enable gates by operands and CFG, not whole functions.

    The unaffected path inserts reason 0x800000 into the removal set. All four
    exclusions must return to that insertion; the affected path must bypass
    exactly the insertion/call. Force the unaffected path, preserving cleanup.
    """
    if capstone is None:
        return []
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    proofs = []
    seed = re.compile(rb'[\x48-\x4f]\x8b[\x80-\xbf]\x28\x02\x00\x00')
    def reg(op):
        return op.reg if op.type == x86.X86_OP_REG else None
    def mem(op, base, displacement):
        return (op.type == x86.X86_OP_MEM and op.mem.base == base and
                not op.mem.index and op.mem.disp == displacement)
    def imm(op, value):
        return op.type == x86.X86_OP_IMM and op.imm == value
    def target(ins):
        return ins.operands[0].imm if len(ins.operands) == 1 and ins.operands[0].type == x86.X86_OP_IMM else None
    for seg in segs:
        end = seg.off + seg.filesz
        for off, compare in _comparisons(mm, seg, decoder):
            branch = off + compare.size
            if branch in known_branches or compare.operands[0].type != x86.X86_OP_MEM:
                continue
            current = bytes(mm[branch:branch + 6])
            if current[:2] != b'\x0f\x8e' and current != b'\x90' * 6:
                continue
            reason = branch + 6
            argument_registers = ([x86.X86_REG_RCX, x86.X86_REG_RDX, x86.X86_REG_R8, x86.X86_REG_R9]
                                  if fmt == 'PE' else [x86.X86_REG_RDI, x86.X86_REG_RSI, x86.X86_REG_RDX])
            count = len(argument_registers) + 2
            insert = list(decoder.disasm(bytes(mm[reason:min(reason + 80, end)]), reason, count=count))
            if len(insert) != count:
                continue
            write, *args, call = insert
            if (write.mnemonic != 'mov' or len(write.operands) != 2 or
                    write.operands[0].type != x86.X86_OP_MEM or
                    write.operands[0].mem.base not in (x86.X86_REG_RBP, x86.X86_REG_RSP) or
                    write.operands[0].mem.index or write.operands[0].size != 4 or
                    not imm(write.operands[1], 0x800000) or
                    any(i.mnemonic != 'mov' or len(i.operands) != 2 or
                        any(op.type != x86.X86_OP_REG for op in i.operands) for i in args) or
                    [reg(i.operands[0]) for i in args] != argument_registers or
                    reg(args[-2].operands[1]) != reg(args[-1].operands[1]) or
                    call.mnemonic != 'call' or target(call) is None or
                    not any(s.off <= target(call) < s.off + s.filesz for s in segs)):
                continue
            skip = call.address + call.size
            obj = compare.operands[0].mem.base
            candidates = []
            for match in seed.finditer(mm, max(seg.off, branch - 0x4000), min(end, branch + 0x4000)):
                pc = match.start()
                block = list(decoder.disasm(bytes(mm[pc:min(pc + 128, end)]), pc, count=15))
                if len(block) != 15:
                    continue
                a,b,c,d,e,f,g,h,i,j,k,l,m,n,o = block
                try:
                    props, typ, loc, mask = reg(a.operands[0]), reg(b.operands[0]), reg(e.operands[0]), reg(h.operands[0])
                    valid = (a.mnemonic == b.mnemonic == e.mnemonic == h.mnemonic == 'mov' and
                        props and typ and loc and mask and len({typ, loc, mask}) == 3 and
                        a.operands[0].size == 8 and b.operands[0].size == e.operands[0].size == h.operands[0].size == 4 and
                        mem(a.operands[1], obj, 0x228) and
                        mem(b.operands[1], props, 0x50) and mem(e.operands[1], props, 0x88) and
                        c.mnemonic == 'cmp' and mem(c.operands[0], obj, 0x208) and c.operands[0].size == 1 and imm(c.operands[1], 0) and
                        d.mnemonic == 'jne' and target(d) == k.address and
                        f.mnemonic == 'cmp' and reg(f.operands[0]) == loc and imm(f.operands[1], 8) and
                        g.mnemonic == 'ja' and target(g) == reason and imm(h.operands[1], 0x10a) and
                        i.mnemonic == 'bt' and reg(i.operands[0]) == mask and reg(i.operands[1]) == loc and
                        j.mnemonic == 'jae' and target(j) == reason and
                        k.mnemonic == m.mnemonic == 'cmp' and reg(k.operands[0]) == reg(m.operands[0]) == typ and
                        {k.operands[1].imm, m.operands[1].imm} == {5, 10} and
                        k.operands[1].type == m.operands[1].type == x86.X86_OP_IMM and
                        l.mnemonic == n.mnemonic == 'je' and target(l) == target(n) == reason and
                        o.mnemonic == 'jmp' and target(o) == skip)
                except IndexError:
                    valid = False
                if valid:
                    candidates.append((pc, o.address + o.size))
            original_target = branch + 6 + struct.unpack_from('<i', current, 2)[0] if current[:2] == b'\x0f\x8e' else None
            if original_target is not None:
                candidates = [candidate for candidate in candidates if candidate[0] == original_target]
            if len(candidates) != 1:
                continue
            detail, detail_end = candidates[0]
            original = b'\x0f\x8e' + struct.pack('<i', detail - branch - 6)
            proofs.append(BlockProof(branch, off, detail, detail_end, reason, original, b'\x90' * 6,
                                     'original' if current == original else 'patched',
                                     ((off, skip), (detail, detail_end))))
    return proofs


def inline_windows_install(mm, segs, sites, error_rx, resource_ids, decode_jump):
    """Validate inlined impact operands and bind installation to its real error.

    This compiler family uses four direct unaffected branches in callers rather
    than shared N1/V helpers. A proved install branch also counts as N5, while
    the writer still makes one physical edit at that address.
    """
    proofs, messages, rejects = [], set(), []
    if capstone is None:
        return proofs, messages, [('coverage', 0, 'Capstone is required for inline Windows policy validation')]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    def reg(op):
        return op.reg if op.type == x86.X86_OP_REG else None
    def mem(op, base, disp):
        return op.type == x86.X86_OP_MEM and op.mem.base == base and not op.mem.index and op.mem.disp == disp
    def imm(op, value):
        return op.type == x86.X86_OP_IMM and op.imm == value
    def target(ins):
        return ins.operands[0].imm if len(ins.operands) == 1 and ins.operands[0].type == x86.X86_OP_IMM else None
    for site in sites:
        if site.kind != 'A':
            continue
        block = list(decoder.disasm(bytes(mm[site.start:site.end]), site.start))
        valid = len(block) == 16
        try:
            a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p = block
            obj = a.operands[0].mem.base
            props, typ, loc, mask = reg(c.operands[0]), reg(d.operands[0]), reg(g.operands[0]), reg(j.operands[0])
            safe, affected = target(b), target(p)
            valid = (valid and a.mnemonic == 'cmp' and mem(a.operands[0], obj, 0x50) and imm(a.operands[1], 2) and
                b.mnemonic in ('jg', 'jmp') and props and typ and loc and mask and len({typ, loc, mask}) == 3 and
                c.mnemonic == d.mnemonic == g.mnemonic == j.mnemonic == 'mov' and
                mem(c.operands[1], obj, 0x228) and mem(d.operands[1], props, 0x50) and
                e.mnemonic == 'cmp' and mem(e.operands[0], obj, 0x208) and imm(e.operands[1], 0) and
                f.mnemonic == 'jne' and target(f) == m.address and mem(g.operands[1], props, 0x88) and
                h.mnemonic == 'cmp' and reg(h.operands[0]) == loc and imm(h.operands[1], 8) and
                i.mnemonic == 'ja' and target(i) == safe and imm(j.operands[1], 0x10a) and
                k.mnemonic == 'bt' and reg(k.operands[0]) == mask and reg(k.operands[1]) == loc and
                l.mnemonic == 'jae' and target(l) == safe and
                m.mnemonic == o.mnemonic == 'cmp' and reg(m.operands[0]) == reg(o.operands[0]) == typ and
                m.operands[1].type == o.operands[1].type == x86.X86_OP_IMM and
                {m.operands[1].imm, o.operands[1].imm} == {5, 10} and
                n.mnemonic == 'je' and target(n) == safe and p.mnemonic == 'jne' and affected != safe and
                any(s.off <= affected < s.off + s.filesz for s in segs) and site.end <= safe <= site.end + 16)
            if valid and safe > site.end:
                padding = list(decoder.disasm(bytes(mm[site.end:safe]), site.end))
                valid = sum(ins.size for ins in padding) == safe - site.end and all(ins.mnemonic == 'nop' for ins in padding)
        except (ValueError, IndexError):
            valid = False
        if not valid:
            rejects.append(('A', site.jpos, 'inline impact operand relationships or safe/affected exits do not validate'))
            continue
        error = error_rx.match(mm, affected)
        if error is None:
            continue
        resource = struct.unpack_from('<I', mm, error.start('resource'))[0]
        call = error.start('call')
        callee = call + 5 + struct.unpack_from('<i', mm, call + 1)[0]
        if resource_ids is None or resource not in resource_ids or not any(s.off <= callee < s.off + s.filesz for s in segs):
            rejects.append(('N5', affected, 'inline install error resource/callee is not verified against matching en-US.pak'))
            continue
        proofs.append(BlockProof(site.jpos, site.start, affected, error.end(), safe,
                                 site.orig, site.new, site.state,
                                 ((site.start, site.end), (affected, error.end()))))
        messages.add(error.start('resource') - 2)  # mov r8d, resource
    return proofs, messages, rejects


def shared_policy_entries(mm, segs, sites, decode_jump):
    """Bind independent entries to already-proved detail and unaffected exits.

    A compiler can duplicate the version check on another predecessor while
    sharing the detailed flag/type/location block. Both edges, and the same
    extension operand, must agree. Recover erased branches only uniquely.
    """
    if capstone is None:
        return []
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    def key(ins):
        op = ins.operands[0]
        return (op.mem.base, op.mem.index, op.mem.scale, op.mem.disp, op.size)
    known, anchors = {site.jpos for site in sites}, {}
    for site in sites:
        if site.kind not in ('A', 'N6'):
            continue
        cmp_ins = next(decoder.disasm(bytes(mm[site.start:site.jpos]), site.start, count=1), None)
        if cmp_ins is None or not _manifest_compare(cmp_ins):
            continue
        edge = decode_jump(mm, site.jpos)
        if edge is None:
            continue
        detail = site.jpos + edge[1]
        anchors[(key(cmp_ins), edge[0], detail)] = site
    proofs = []
    for seg in segs:
        for off, cmp_ins in _comparisons(mm, seg, decoder):
            if cmp_ins.operands[0].type != x86.X86_OP_MEM:
                continue
            branch = off + cmp_ins.size
            if branch in known:
                continue
            current = bytes(mm[branch:branch + 6])
            if current[:2] != b'\x0f\x8e' and current != b'\x90' * 6:
                continue
            jump = decode_jump(mm, branch + 6)
            if jump is None or mm[branch + 6] not in (0xe9, 0xeb):
                continue
            candidates = [(detail, site) for (operand, safe, detail), site in anchors.items()
                          if operand == key(cmp_ins) and safe == jump[0]]
            if current[:2] == b'\x0f\x8e':
                taken = decode_jump(mm, branch)[0]
                candidates = [(detail, site) for detail, site in candidates if detail == taken]
            if len(candidates) != 1:
                continue
            detail, site = candidates[0]
            original = b'\x0f\x8e' + struct.pack('<i', detail - branch - 6)
            proofs.append(BlockProof(branch, off, detail, site.end, jump[0],
                                     original, b'\x90' * 6,
                                     'original' if current == original else 'patched',
                                     ((off, branch + 6 + jump[1]), (site.start, site.end))))
    return proofs


def pure_impact_blocks(mm, segs, known_branches):
    """Prove small impact predicates across argument/type/location registers."""
    if capstone is None:
        return []
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    def reg(op):
        return op.reg if op.type == x86.X86_OP_REG else None
    def mem(op, base, disp):
        return op.type == x86.X86_OP_MEM and op.mem.base == base and not op.mem.index and op.mem.disp == disp
    def imm(op, value):
        return op.type == x86.X86_OP_IMM and op.imm == value
    def target(ins):
        return ins.operands[0].imm if len(ins.operands) == 1 and ins.operands[0].type == x86.X86_OP_IMM else None
    def zero(ins):
        return ins.mnemonic == 'xor' and len(ins.operands) == 2 and reg(ins.operands[0]) == reg(ins.operands[1]) == x86.X86_REG_EAX
    proofs = []
    for seg in segs:
        end = seg.off + seg.filesz
        for off, compare in _comparisons(mm, seg, decoder):
            branch = off + compare.size
            if branch in known_branches or compare.operands[0].type != x86.X86_OP_MEM:
                continue
            current = bytes(mm[branch:branch + 2])
            if current != b'\x7e\x03' and current != b'\x90\x90':
                continue
            block = list(decoder.disasm(bytes(mm[branch + 2:min(branch + 150, end)]), branch + 2, count=19))
            if len(block) != 19:
                continue
            a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s = block
            try:
                obj = compare.operands[0].mem.base
                props, typ, loc, mask = reg(c.operands[0]), reg(d.operands[0]), reg(g.operands[0]), reg(k.operands[0])
                temp = reg(o.operands[0])
                valid = (compare.operands[0].size == 4 and zero(a) and b.mnemonic == 'ret' and c.address == branch + 5 and
                    c.mnemonic == d.mnemonic == g.mnemonic == k.mnemonic == 'mov' and props and typ and loc and mask and
                    len({typ, loc, mask}) == 3 and
                    'rax' not in {_register_root(decoder, r) for r in (typ, loc, mask)} and
                    _register_root(decoder, props) != _register_root(decoder, obj) and
                    _register_root(decoder, typ) not in {_register_root(decoder, props), _register_root(decoder, obj)} and
                    c.operands[0].size == 8 and
                    d.operands[0].size == g.operands[0].size == k.operands[0].size == 4 and
                    mem(c.operands[1], obj, 0x228) and mem(d.operands[1], props, 0x50) and
                    e.mnemonic == 'cmp' and mem(e.operands[0], obj, 0x208) and e.operands[0].size == 1 and imm(e.operands[1], 0) and
                    f.mnemonic == 'jne' and target(f) == n.address and mem(g.operands[1], props, 0x88) and zero(h) and
                    i.mnemonic == 'cmp' and reg(i.operands[0]) == loc and imm(i.operands[1], 8) and
                    j.mnemonic == 'ja' and target(j) == b.address and imm(k.operands[1], 0x10a) and
                    l.mnemonic == 'bt' and reg(l.operands[0]) == mask and reg(l.operands[1]) == loc and
                    m.mnemonic == 'jae' and target(m) == b.address and
                    n.mnemonic == p.mnemonic == 'cmp' and reg(n.operands[0]) == reg(p.operands[0]) == typ and
                    n.operands[1].type == p.operands[1].type == x86.X86_OP_IMM and {n.operands[1].imm, p.operands[1].imm} == {5, 10} and
                    o.mnemonic == q.mnemonic == 'setne' and o.operands[0].size == 1 and temp != x86.X86_REG_AL and
                    reg(q.operands[0]) == x86.X86_REG_AL and r.mnemonic == 'and' and
                    reg(r.operands[0]) == x86.X86_REG_AL and reg(r.operands[1]) == temp and
                    s.mnemonic == 'jmp' and target(s) == b.address)
            except IndexError:
                valid = False
            if valid:
                finish = s.address + s.size
                proofs.append(BlockProof(branch, off, c.address, finish, a.address,
                                         b'\x7e\x03', b'\x90\x90',
                                         'original' if current == b'\x7e\x03' else 'patched',
                                         ((off, finish),)))
    return proofs


def startup_collection_blocks(mm, segs, known_branches, decode_jump):
    """Prove a collection gate from policy edges and both iterator advances.

    The body between iteration and policy may grow or move. Require the four
    unaffected policy exits, the collection call with restored iterator/end,
    the complete tree-step edges, and the associated 0x800000 reason store.
    """
    if capstone is None:
        return []
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    mask_rx = re.compile(rb'[\x40-\x4f]?[\xb8-\xbf]\x0a\x01\x00\x00')
    detail_rx = re.compile(rb'[\x48-\x4f]\x8b[\x80-\xbf]\x28\x02\x00\x00')
    def reg(op):
        return op.reg if op.type == x86.X86_OP_REG else None
    def mem(op, base, disp):
        return op.type == x86.X86_OP_MEM and op.mem.base == base and not op.mem.index and op.mem.disp == disp
    def imm(op, value):
        return op.type == x86.X86_OP_IMM and op.imm == value
    def target(ins):
        return ins.operands[0].imm if len(ins.operands) == 1 and ins.operands[0].type == x86.X86_OP_IMM else None
    def mov(ins, destination, source):
        return ins.mnemonic == 'mov' and reg(ins.operands[0]) == destination and reg(ins.operands[1]) == source
    def decode(off, end, count):
        return list(decoder.disasm(bytes(mm[off:min(off + count * 15, end)]), off, count=count))
    proofs = []
    for seg in segs:
        end = seg.off + seg.filesz
        for seed in mask_rx.finditer(mm, seg.off, end):
            head = decode(seed.start(), end, 3)
            if len(head) != 3:
                continue
            mask_ins, load, cmp_ins = head
            branch = cmp_ins.address + cmp_ins.size
            if branch in known_branches or not _manifest_compare(cmp_ins):
                continue
            try:
                mask, obj = reg(mask_ins.operands[0]), reg(load.operands[0])
                iterator = load.operands[1].mem.base
                if (mask_ins.mnemonic != 'mov' or mask_ins.operands[0].size != 4 or not imm(mask_ins.operands[1], 0x10a) or
                        load.mnemonic != 'mov' or load.operands[0].size != 8 or not obj or not mem(load.operands[1], iterator, 0x38) or
                        cmp_ins.operands[0].size != 4 or
                        not mem(cmp_ins.operands[0], obj, 0x50)):
                    continue
                current = bytes(mm[branch:branch + 6])
                if current[:2] != b'\x0f\x8e' and current != b'\x90' * 6:
                    continue
                safe = branch + 6
                loop = decode(safe, end, 9)
                if len(loop) != 9:
                    continue
                a,b,c,d,e,f,g,h,i = loop
                child, endreg = reg(a.operands[0]), reg(h.operands[1])
                if (a.mnemonic != 'mov' or not child or not mem(a.operands[1], iterator, 8) or
                        b.mnemonic != 'test' or reg(b.operands[0]) != child or reg(b.operands[1]) != child or c.mnemonic != 'jne' or
                        not mov(d, child, iterator) or e.mnemonic != 'mov' or reg(e.operands[0]) != iterator or
                        not mem(e.operands[1], iterator, 0x10) or f.mnemonic != 'cmp' or reg(f.operands[0]) != child or
                        not mem(f.operands[1], iterator, 0) or g.mnemonic != 'jne' or target(g) != d.address or
                        h.mnemonic != 'cmp' or reg(h.operands[0]) != iterator or not endreg or
                        i.mnemonic != 'jne' or target(i) != load.address):
                    continue
                live = {_register_root(decoder, r) for r in (iterator, endreg)}
                if (_register_root(decoder, obj) in live or _register_root(decoder, mask) in live or
                        _register_root(decoder, obj) == _register_root(decoder, mask)):
                    continue
                tree_start = target(c)
                if tree_start is None or not seg.off <= tree_start < end:
                    continue
                tree = decode(tree_start, end, 5)
                if len(tree) != 5:
                    continue
                t0,t1,t2,t3,t4 = tree
                if (not mov(t0, iterator, child) or t1.mnemonic != 'mov' or reg(t1.operands[0]) != child or
                        not mem(t1.operands[1], child, 0) or t2.mnemonic != 'test' or
                        reg(t2.operands[0]) != child or reg(t2.operands[1]) != child or
                        t3.mnemonic != 'jne' or target(t3) != tree_start or t4.mnemonic != 'jmp' or target(t4) != h.address):
                    continue
            except IndexError:
                continue
            details = []
            original_edge = decode_jump(mm, branch) if current[:2] == b'\x0f\x8e' else None
            starts = [original_edge[0]] if original_edge else [m.start() for m in detail_rx.finditer(
                mm, max(seg.off, branch - 0x4000), min(end, branch + 0x4000))]
            for position in starts:
                if not seg.off <= position < end:
                    continue
                block = decode(position, end, 23)
                if len(block) != 23:
                    continue
                a,b,c,d,e,f,g,h,i,j,k,l,m,*tail = block
                try:
                    props, typ, loc = reg(a.operands[0]), reg(b.operands[0]), reg(e.operands[0])
                    valid = (a.mnemonic == b.mnemonic == e.mnemonic == 'mov' and props and typ and loc and
                        len({typ, loc, mask}) == 3 and a.operands[0].size == 8 and
                        b.operands[0].size == e.operands[0].size == 4 and
                        not ({_register_root(decoder, r) for r in (props, typ, loc)} & live) and
                        _register_root(decoder, props) not in {_register_root(decoder, obj), _register_root(decoder, mask)} and
                        _register_root(decoder, typ) not in {_register_root(decoder, obj), _register_root(decoder, props)} and
                        mem(a.operands[1], obj, 0x228) and mem(b.operands[1], props, 0x50) and
                        c.mnemonic == 'cmp' and mem(c.operands[0], obj, 0x208) and imm(c.operands[1], 0) and
                        d.mnemonic == 'jne' and target(d) == j.address and mem(e.operands[1], props, 0x88) and
                        f.mnemonic == 'cmp' and reg(f.operands[0]) == loc and imm(f.operands[1], 8) and
                        g.mnemonic == 'ja' and target(g) == safe and h.mnemonic == 'bt' and
                        reg(h.operands[0]) == mask and reg(h.operands[1]) == loc and i.mnemonic == 'jae' and target(i) == safe and
                        j.mnemonic == l.mnemonic == 'cmp' and reg(j.operands[0]) == reg(l.operands[0]) == typ and
                        j.operands[1].type == l.operands[1].type == x86.X86_OP_IMM and {j.operands[1].imm,l.operands[1].imm} == {5,10} and
                        k.mnemonic == m.mnemonic == 'je' and target(k) == target(m) == safe)
                    t0,t1,t2,t3,t4,t5,t6,t7,t8,t9 = tail
                    saved_iter, saved_end = reg(t1.operands[0]), reg(t4.operands[0])
                    valid = (valid and t0.mnemonic == 'lea' and reg(t0.operands[0]) == x86.X86_REG_R8 and
                        mem(t0.operands[1], iterator, 0x38) and mov(t1, saved_iter, iterator) and
                        t2.mnemonic == t3.mnemonic == 'mov' and reg(t2.operands[0]) == x86.X86_REG_RCX and
                        reg(t3.operands[0]) == x86.X86_REG_RDX and reg(t2.operands[1]) and reg(t3.operands[1]) and
                        mov(t4, saved_end, endreg) and t5.mnemonic == 'call' and target(t5) is not None and
                        any(s.off <= target(t5) < s.off + s.filesz for s in segs) and
                        t6.mnemonic == 'mov' and reg(t6.operands[0]) == mask and imm(t6.operands[1], 0x10a) and
                        mov(t7, iterator, saved_iter) and mov(t8, endreg, saved_end) and t9.mnemonic == 'jmp' and target(t9) == safe)
                except IndexError:
                    valid = False
                if not valid:
                    continue
                # Associate the reason store in the same bounded collection
                # region; it is evidence in addition to the complete edges.
                reason = mm.find(b'\xc7\x00\x00\x00\x80\x00', loop[-1].address + loop[-1].size, position)
                if reason < 0:
                    continue
                finish = t9.address + t9.size
                details.append((position, finish, reason))
            if len(details) != 1:
                continue
            position, finish, reason = details[0]
            original = b'\x0f\x8e' + struct.pack('<i', position - branch - 6)
            proofs.append(BlockProof(branch, seed.start(), position, finish, safe,
                                     original, b'\x90' * 6,
                                     'original' if current == original else 'patched',
                                     ((seed.start(), loop[-1].address + loop[-1].size),
                                      (tree_start, tree[-1].address + tree[-1].size),
                                      (reason, reason + 6), (position, finish))))
    return proofs
