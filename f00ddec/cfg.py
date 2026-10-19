"""
Control-flow graph for MeP.  Carves the decoded stream into functions and basic
blocks and lifts each block.  MeP flow: bra / jmp(target) / ret / reti and an
indirect jmp end a block; conditional branches and bsr/jsr fall through.  No flag
pass is needed -- conditional branches carry their own condition.
"""

from . import ir, isa
from .lifter import lift_insn
from .decoder import target_of
from .structure import negate


class Block:
    __slots__ = ("start", "insns", "stmts", "succ", "term")

    def __init__(self, start):
        self.start = start
        self.insns = []
        self.stmts = []
        self.succ = []
        self.term = None


class Func:
    __slots__ = ("entry", "blocks", "calls", "name", "locals", "stack_args")

    def __init__(self, entry):
        self.entry = entry
        self.blocks = {}
        self.calls = set()
        self.name = None
        self.locals = {}
        self.stack_args = {}

    def ordered(self):
        return [self.blocks[k] for k in sorted(self.blocks)]


def _is_epilogue_jmp(insns, ea):
    """Return True if indirect `jmp $rm` at *ea* is a function epilogue return."""
    ins = insns.get(ea)
    if ins is None or ins.mnem != "jmp" or ins.switch_info is not None:
        return False
    if not ins.ops or ins.ops[0].mode != "reg":
        return False
    rm = ins.ops[0].reg
    # Check preceding instructions in a small window before ea
    prev_eas = [e for e in sorted(insns) if ea - 16 <= e < ea]
    if prev_eas:
        last_ins = insns[prev_eas[-1]]
        # A jump-table dispatch is immediately preceded by `lw $rm, ($rPtr)` (phrase mode)
        if (last_ins.mnem == "lw" and len(last_ins.ops) == 2
                and last_ins.ops[0].mode == "reg" and last_ins.ops[0].reg == rm
                and last_ins.ops[1].mode == "phrase"):
            return False
    if rm in (1, 11):
        return True
    for pe in prev_eas:
        pi = insns[pe]
        if (pi.mnem == "ldc" and len(pi.ops) == 2
                and pi.ops[0].mode == "reg" and pi.ops[0].reg == rm
                and pi.ops[1].mode == "reg" and pi.ops[1].reg == 17):  # CR + 1 = lp
            return True
    return False


def _hw_loops(insns, body):
    """Discover hardware loops (`repeat` / `erepeat`) within *body*.

    Returns dict mapping `latch_ea -> (kind, rpb_ea, follow_ea, repeat_ea)`.
    In Toshiba MeP, the last instruction of the repeat block is the instruction
    immediately following the address specified by `rpe`.
    """
    loops = {}
    for ea in sorted(body):
        ins = insns[ea]
        if ins.mnem not in ("repeat", "erepeat"):
            continue
        rpe = target_of(ins)
        rpb = ea + ins.size
        if rpe is None or rpb not in body or rpe not in body:
            continue
        rpe_ins = insns[rpe]
        next_after_rpe = rpe + rpe_ins.size
        if next_after_rpe in body and rpe_ins.mnem not in isa.STOP:
            latch_ea = next_after_rpe
        else:
            latch_ea = rpe
        latch_ins = insns[latch_ea]
        follow_ea = latch_ea + latch_ins.size
        loops[latch_ea] = (ins.mnem, rpb, follow_ea, ea)
    return loops


def _switches_in_body(insns, body):
    """Return `(bounds_to_sw, setup_skip_eas)` for switches in *body*."""
    bounds_to_sw = {}
    setup_skip = set()
    for ea in body:
        ins = insns[ea]
        if ins.mnem == "jmp" and ins.switch_info is not None:
            sw = ins.switch_info
            if sw.bounds_ea in body:
                bounds_to_sw[sw.bounds_ea] = sw
            setup_skip.update(sw.setup_eas - {ea})
    return bounds_to_sw, setup_skip


def _succ(ins, bounds_to_sw=None, hw_loops=None):
    m = ins.mnem
    ea = ins.ea
    nxt = ea + ins.size
    t = target_of(ins)
    if bounds_to_sw and ea in bounds_to_sw:
        return [("fall", nxt)]
    if hw_loops and ea in hw_loops:
        kind, rpb, follow_ea, _rep_ea = hw_loops[ea]
        if kind == "repeat":
            return [("cond", rpb), ("fall", follow_ea)]
        # erepeat
        if m in isa.COND_BRANCH and t == follow_ea:
            return [("cond", rpb), ("fall", follow_ea)]
        return [("jump", rpb)]
    if m == "bra" or (m == "jmp" and t is not None):
        return [("jump", t)]
    if m == "jmp":
        if ins.switch_info is not None:
            sw = ins.switch_info
            s = [("case", ct) for ct in sw.targets]
            if sw.default_ea is not None:
                s.append(("default", sw.default_ea))
            return s
        return []
    if m in isa.RET:
        return []
    if m in isa.COND_BRANCH:
        s = [("cond", t)] if t is not None else []
        s.append(("fall", nxt))
        return s
    return [("fall", nxt)]


def _collect_body(insns, entry, entry_set):
    body = set()
    work = [entry]
    while work:
        ea = work.pop()
        if ea in body or ea not in insns:
            continue
        body.add(ea)
        ins = insns[ea]
        for how, tgt in _succ(ins):
            if tgt in insns and (tgt == entry or tgt not in entry_set):
                work.append(tgt)
        if ins.mnem in ("repeat", "erepeat"):
            rpe = target_of(ins)
            if rpe in insns and (rpe == entry or rpe not in entry_set):
                work.append(rpe)
                after = rpe + insns[rpe].size
                if after in insns and (after == entry or after not in entry_set):
                    work.append(after)
    return body


def _leaders(insns, body, bounds_to_sw, hw_loops):
    leaders = set()
    for ea in body:
        ins = insns[ea]
        for how, tgt in _succ(ins, bounds_to_sw, hw_loops):
            if how in ("cond", "jump", "case", "default") and tgt in body:
                leaders.add(tgt)
        if ea in hw_loops:
            _kind, rpb, follow_ea, _rep_ea = hw_loops[ea]
            if rpb in body:
                leaders.add(rpb)
            if follow_ea in body:
                leaders.add(follow_ea)
            continue
        if ea in bounds_to_sw:
            continue
        if ins.mnem in ("repeat", "erepeat"):
            nxt = ins.ea + ins.size
            if nxt in body:
                leaders.add(nxt)
        if ins.mnem in isa.COND_BRANCH or ins.mnem in isa.CALL \
                or ins.mnem in isa.STOP:
            nxt = ins.ea + ins.size
            if nxt in body:
                leaders.add(nxt)
    return leaders


def build_func(insns, entry, entry_set):
    body = _collect_body(insns, entry, entry_set)
    if not body:
        return None
    hw_loops = _hw_loops(insns, body)
    bounds_to_sw, setup_skip = _switches_in_body(insns, body)
    leaders = _leaders(insns, body, bounds_to_sw, hw_loops)
    leaders.add(entry)

    f = Func(entry)
    cur = None
    for ea in sorted(body):
        ins = insns[ea]
        if ea in leaders or cur is None:
            cur = Block(ea)
            f.blocks[ea] = cur
        cur.insns.append(ins)
        succ = _succ(ins, bounds_to_sw, hw_loops)
        nxt = ea + ins.size
        term = None
        if ea in hw_loops:
            kind, _rpb, _follow_ea, _rep_ea = hw_loops[ea]
            if kind == "repeat" or (ins.mnem in isa.COND_BRANCH and len(succ) == 2):
                term = ("branch", succ)
            else:
                term = ("goto", succ)
        elif ea in bounds_to_sw:
            if nxt in leaders or nxt not in body:
                term = ("fall", [("fall", nxt)] if nxt in body else [])
        elif ins.mnem == "jmp" and ins.switch_info is not None:
            term = ("switch", succ)
        elif (ins.mnem == "bra" or (ins.mnem == "jmp" and target_of(ins) is not None)) and target_of(ins) not in body:
            term = ("ret", [])
        elif ins.mnem == "bra" or (ins.mnem == "jmp" and target_of(ins) is not None):
            term = ("goto", succ)
        elif ins.mnem == "jmp" or ins.mnem in isa.RET:
            term = ("ret", [])
        elif ins.mnem in isa.COND_BRANCH:
            term = ("branch", succ)
        elif nxt in leaders or nxt not in body:
            term = ("fall", [("fall", nxt)] if nxt in body else [])
        if term is not None:
            cur.term, cur.succ = term
            cur = None

    for b in f.blocks.values():
        for ins in b.insns:
            if ins.mnem in isa.CALL and target_of(ins) is not None:
                f.calls.add(target_of(ins))
            if ins.ea in setup_skip:
                continue
            if ins.mnem == "jmp" and ins.switch_info is None and target_of(ins) is None:
                if _is_epilogue_jmp(insns, ins.ea):
                    b.stmts.append(ir.Ret(ins.ea, "ret"))
                    continue
            if ins.mnem in ("jmp", "bra") and target_of(ins) is not None and target_of(ins) not in body:
                tgt = target_of(ins)
                f.calls.add(tgt)
                b.stmts.append(ir.Call(ins.ea, target=tgt, is_tail=True))
                b.stmts.append(ir.Ret(ins.ea, "ret"))
                continue
            lifted = lift_insn(ins)
            if ins.ea in hw_loops:
                kind, rpb, follow_ea, _rep_ea = hw_loops[ins.ea]
                if kind == "repeat":
                    b.stmts.extend(lifted)
                    b.stmts.append(ir.Assign(ins.ea, ir.Reg("rpc"),
                                             ir.Bin("-", ir.Reg("rpc"), ir.Const(1))))
                    b.stmts.append(ir.Branch(ins.ea,
                                             ir.Bin("!=", ir.Reg("rpc"), ir.Const(0)),
                                             rpb, follow_ea))
                else:
                    # erepeat latch
                    if lifted and isinstance(lifted[-1], ir.Branch) and lifted[-1].target == follow_ea:
                        br = lifted[-1]
                        lifted[-1] = ir.Branch(ins.ea, negate(br.cexpr), rpb, follow_ea)
                        b.stmts.extend(lifted)
                    else:
                        b.stmts.extend(lifted)
                        b.stmts.append(ir.Goto(ins.ea, rpb))
                continue
            b.stmts.extend(lifted)
    return f


def build_functions(insns, calls, extra_entries=()):
    entry_set = {e for e in (set(calls) | set(extra_entries)) if e in insns}
    funcs = {}
    for entry in sorted(entry_set):
        fn = build_func(insns, entry, entry_set)
        if fn is not None:
            funcs[entry] = fn
    return funcs

