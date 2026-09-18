"""
Control-flow graph for MeP.  Carves the decoded stream into functions and basic
blocks and lifts each block.  MeP flow: bra / jmp(target) / ret / reti and an
indirect jmp end a block; conditional branches and bsr/jsr fall through.  No flag
pass is needed -- conditional branches carry their own condition.
"""

from . import isa
from .lifter import lift_insn
from .decoder import target_of


class Block:
    __slots__ = ("start", "insns", "stmts", "succ", "term")

    def __init__(self, start):
        self.start = start
        self.insns = []
        self.stmts = []
        self.succ = []
        self.term = None


class Func:
    __slots__ = ("entry", "blocks", "calls", "name")

    def __init__(self, entry):
        self.entry = entry
        self.blocks = {}
        self.calls = set()
        self.name = None

    def ordered(self):
        return [self.blocks[k] for k in sorted(self.blocks)]


def _succ(ins):
    m = ins.mnem
    nxt = ins.ea + ins.size
    t = target_of(ins)
    if m == "bra" or (m == "jmp" and t is not None):
        return [("jump", t)]
    if m == "jmp" or m in isa.RET:          # indirect jmp or return: ends block
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
        for how, tgt in _succ(insns[ea]):
            if tgt in insns and (tgt == entry or tgt not in entry_set):
                work.append(tgt)
    return body


def _leaders(insns, body):
    leaders = set()
    for ea in body:
        ins = insns[ea]
        for how, tgt in _succ(ins):
            if how in ("cond", "jump") and tgt in body:
                leaders.add(tgt)
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
    leaders = _leaders(insns, body)
    leaders.add(entry)

    f = Func(entry)
    cur = None
    for ea in sorted(body):
        ins = insns[ea]
        if ea in leaders or cur is None:
            cur = Block(ea)
            f.blocks[ea] = cur
        cur.insns.append(ins)
        succ = _succ(ins)
        nxt = ea + ins.size
        term = None
        if ins.mnem == "bra" or (ins.mnem == "jmp" and target_of(ins) is not None):
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
            b.stmts.extend(lift_insn(ins))
    return f


def build_functions(insns, calls, extra_entries=()):
    entry_set = {e for e in (set(calls) | set(extra_entries)) if e in insns}
    funcs = {}
    for entry in sorted(entry_set):
        fn = build_func(insns, entry, entry_set)
        if fn is not None:
            funcs[entry] = fn
    return funcs
