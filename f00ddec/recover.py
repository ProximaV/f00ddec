"""
Lightweight parameter / return-value recovery for MeP (F00D) functions, using
the Toshiba MeP calling convention.

Arguments arrive in ``r1``-``r4`` (further ones on the stack); a register that is
*read before being written* on a path from the entry block (its live-in set) is
an incoming argument.  The return value comes back in ``r0``.  This is
deliberately simpler than Hex-Rays' inter-procedural type inference -- it
recovers the argument *count* (``r1``..``rN``) and whether the function yields a
value in ``r0`` -- so a signature reads ``int sub_X(int r1, int r2)`` instead of
the bare ``void sub_X(void)``.

A call clobbers the caller-saved registers (``r0``-``r7``, the link pointer
``lp`` and the ``hi``/``lo`` multiply results), so an argument register read only
*after* a call does not count.
"""

from . import ir

ARG_REGS = ("r1", "r2", "r3", "r4")
RET_REG = "r0"
CALLER_SAVED = frozenset((
    "r0", "r1", "r2", "r3", "r4",
    "lp", "hi", "lo",
))


def _regs(e, out):
    if isinstance(e, ir.Reg):
        out.add(e.name)
    elif isinstance(e, ir.Bin):
        _regs(e.l, out); _regs(e.r, out)
    elif isinstance(e, ir.Un):
        _regs(e.e, out)
    elif isinstance(e, ir.Mem):
        if isinstance(e.addr, ir.Expr):
            _regs(e.addr, out)
    elif isinstance(e, ir.IntrExpr):
        for a in e.args:
            _regs(a, out)
    return out


def _use_def(stmt):
    """(reads, writes) of register names for one IR statement."""
    use, defn = set(), set()
    if isinstance(stmt, ir.Assign):
        _regs(stmt.src, use)
        if isinstance(stmt.dst, ir.Reg):
            defn.add(stmt.dst.name)
        elif isinstance(stmt.dst, ir.Mem) and isinstance(stmt.dst.addr, ir.Expr):
            _regs(stmt.dst.addr, use)
    elif isinstance(stmt, ir.Branch):
        _regs(stmt.cexpr, use)
    elif isinstance(stmt, ir.Switch):
        _regs(stmt.expr, use)
    elif isinstance(stmt, ir.Call):
        if stmt.expr is not None:
            _regs(stmt.expr, use)
        defn |= CALLER_SAVED
    elif isinstance(stmt, ir.Intrinsic):
        for a in stmt.args:
            _regs(a, use)
    return use, defn


def _block_use_def(block, block_set=frozenset()):
    """Upward-exposed uses and the kill set for a whole block."""
    use, defn = set(), set()
    for s in block.stmts:
        u, d = _use_def(s)
        use |= (u - defn)      # used before defined in this block
        defn |= d
    # Tail-call thunk: if the block jumps out of the function after setting rK (e.g. r3, r4),
    # then r1..r(K-1) not defined in this block are passed through from the caller.
    if block.term == "goto" and block.succ and block.succ[0][1] not in block_set:
        hi_arg = -1
        for idx, r in enumerate(ARG_REGS):
            if r in defn:
                hi_arg = idx
        if hi_arg > 0:
            use |= (set(ARG_REGS[:hi_arg]) - defn)
    return use, defn


def live_in_entry(func):
    blocks = func.blocks
    bset = frozenset(blocks)
    bud = {ea: _block_use_def(b, bset) for ea, b in blocks.items()}

    live_in = {ea: set() for ea in blocks}
    changed = True
    while changed:
        changed = False
        for ea, b in blocks.items():
            out = set()
            for _, tgt in b.succ:
                if tgt in live_in:
                    out |= live_in[tgt]
            use, defn = bud[ea]
            nin = use | (out - defn)
            if nin != live_in[ea]:
                live_in[ea] = nin
                changed = True
    return live_in.get(func.entry, set())


def params(func):
    lin = live_in_entry(func)
    hi = -1
    for i, r in enumerate(ARG_REGS):
        if r in lin:
            hi = i
    stack_args = getattr(func, "stack_args", None)
    if stack_args:
        return list(ARG_REGS)
    return list(ARG_REGS[:hi + 1])


def _block_defines_ret(block):
    """Return True if *block* ends with a live explicit value in `r0`."""
    r0_live = False
    for s in block.stmts:
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == RET_REG:
            # A relational `<` in a branch block is a condition temporary, not a return value
            if isinstance(s.src, ir.Bin) and s.src.op == "<" and block.term == "branch":
                continue
            r0_live = True
        elif isinstance(s, ir.Call):
            if s.expr is not None and RET_REG in _regs(s.expr, set()):
                # `r0` was loaded as the indirect call target `(*r0)()`
                r0_live = False
    return r0_live


def returns_value(func):
    """True if `r0` is given an explicit non-flag value that reaches a normal `ret`."""
    rets = {
        ea for ea, b in func.blocks.items()
        if b.term == "ret" and any(isinstance(s, ir.Ret) and s.kind == "ret" for s in b.stmts)
    }
    if not rets:
        return False
    defs = {ea for ea, b in func.blocks.items() if _block_defines_ret(b)}
    if not defs:
        return False
    succ = {ea: [t for _, t in b.succ if t in func.blocks] for ea, b in func.blocks.items()}
    pred = {ea: [] for ea in func.blocks}
    for ea, ss in succ.items():
        for t in ss:
            pred[t].append(ea)
    seen = set(rets)
    work = list(rets)
    while work:
        n = work.pop()
        for p in pred.get(n, ()):
            if p not in seen:
                seen.add(p); work.append(p)
    return bool(defs & seen)


def _mem_bases(e, out):
    """register names used as a memory base in expression *e*."""
    if isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
        a = e.addr
        if isinstance(a, ir.Reg):
            out.add(a.name)
        elif isinstance(a, ir.Bin) and a.op == "+" and isinstance(a.l, ir.Reg):
            out.add(a.l.name)
        _mem_bases(a, out)
    elif isinstance(e, ir.Bin):
        _mem_bases(e.l, out); _mem_bases(e.r, out)
    elif isinstance(e, ir.Un):
        _mem_bases(e.e, out)
    elif isinstance(e, ir.IntrExpr):
        for a in e.args:
            _mem_bases(a, out)
    return out


def _dst_bases(s, bases):
    if isinstance(s, ir.Assign):
        _mem_bases(s.src, bases)
        if isinstance(s.dst, ir.Mem):
            if isinstance(s.dst.addr, ir.Reg):
                bases.add(s.dst.addr.name)
            elif isinstance(s.dst.addr, ir.Bin) and isinstance(s.dst.addr.l, ir.Reg):
                bases.add(s.dst.addr.l.name)
            _mem_bases(s.dst, bases)
    elif isinstance(s, ir.Branch):
        _mem_bases(s.cexpr, bases)
    elif isinstance(s, ir.Switch):
        _mem_bases(s.expr, bases)
    elif isinstance(s, ir.Intrinsic):
        for a in s.args:
            _mem_bases(a, bases)
    elif isinstance(s, ir.Call) and s.expr is not None:
        _mem_bases(s.expr, bases)
    return bases


def _pointer_params(func, ps):
    """A parameter is typed as a pointer when it (or a register that carries its
    value through single copies) is used as a memory base."""
    if not ps:
        return set()
    defcount = {}
    for b in func.blocks.values():
        for s in b.stmts:
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
                defcount[s.dst.name] = defcount.get(s.dst.name, 0) + 1
    alias = {p: p for p in ps}
    for _ in range(6):
        changed = False
        for b in func.blocks.values():
            for s in b.stmts:
                if (isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg)
                        and isinstance(s.src, ir.Reg)
                        and s.src.name in alias and defcount.get(s.dst.name, 0) == 1
                        and s.dst.name not in alias):
                    alias[s.dst.name] = alias[s.src.name]
                    changed = True
        if not changed:
            break
    ptr = set()
    for b in func.blocks.values():
        for s in b.stmts:
            bases = set()
            _dst_bases(s, bases)
            for reg in bases:
                root = alias.get(reg)
                if root in ps:
                    ptr.add(root)
    return ptr


def signature(func, name):
    ps = list(params(func))
    stack_args = getattr(func, "stack_args", None)
    if stack_args:
        for sname in sorted(stack_args, key=lambda n: int(n.split("_")[1], 16)):
            ps.append(sname)
    ret = "int" if returns_value(func) else "void"
    ptr = _pointer_params(func, ps)
    args = ", ".join(("int *%s" % p if p in ptr else "int %s" % p) for p in ps) if ps else "void"
    return "%s %s(%s)" % (ret, name, args), ps, ret == "int"

