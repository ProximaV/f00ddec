"""
Stack-frame cleanup for MeP (F00D) functions, bringing the output closer to
Hex-Rays: hide the prologue/epilogue boilerplate and turn stack memory into named
locals.

MeP frames use ``sp`` (= r15) for the stack and ``r8`` as the frame pointer
(``fp``); the return address lives in the ``lp`` control register.

* The stack adjust (``sp = sp + K`` -- MeP allocates with ``add sp,#-K`` so the
  immediate is a large unsigned constant -- and ``sp = sp - K`` / ``sp = r8``)
  and the frame-pointer setup (``r8 = sp``) are dropped.
* Callee-saved register spills -- ``mem32[sp+off] = rX`` in the prologue with the
  matching ``rX = mem32[sp+off]`` in the epilogue -- are recognised and removed;
  the working register keeps its name, so only the save/restore noise disappears.
* Every remaining stack slot ``mem[sp+off]`` becomes a local ``var_off`` (typed
  by access width: ``char``/``short``/``int``); a stack address ``sp + off``
  passed to a callee becomes ``&var_off``.

This is a structural cleanup, not full Hex-Rays variable recovery.
"""

from . import ir

# MeP frame pointer is r8; sp is r15 (named "sp"); lp is the link (return addr).
FP = "r8"
CALLEE_SAVED = frozenset(("r8", "r9", "r10", "r11", "r12", "tp", "gp", "sp", "lp"))


def _sp_off(addr):
    """Return the frame offset if *addr* is sp / sp+const, else None."""
    if isinstance(addr, ir.Reg) and addr.name == "sp":
        return 0
    if (isinstance(addr, ir.Bin) and addr.op == "+"
            and isinstance(addr.l, ir.Reg) and addr.l.name == "sp"
            and isinstance(addr.r, ir.Const)):
        return addr.r.value
    return None


def _saved_slots(func):
    """offsets that hold a callee-saved register save/restore pair."""
    stores, loads = {}, {}
    for b in func.blocks.values():
        for s in b.stmts:
            if not isinstance(s, ir.Assign):
                continue
            if isinstance(s.dst, ir.Mem) and isinstance(s.src, ir.Reg):
                off = _sp_off(s.dst.addr)
                if off is not None and s.src.name in CALLEE_SAVED:
                    stores.setdefault(off, set()).add(s.src.name)
            elif isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Mem):
                off = _sp_off(s.src.addr)
                if off is not None and s.dst.name in CALLEE_SAVED:
                    loads.setdefault(off, set()).add(s.dst.name)
    saved = {}
    for off, regs in stores.items():
        both = regs & loads.get(off, set())
        if both:
            saved[off] = both
    return saved


def rewrite(func):
    func.locals = {}
    saved = _saved_slots(func)

    def local(off, width):
        name = "var_%X" % off if off else "var_0"
        func.locals[name] = max(func.locals.get(name, 1), width)
        return name

    def xf(e):
        if isinstance(e, ir.Mem):
            off = _sp_off(e.addr)
            if off is not None and off not in saved:
                return ir.Reg(local(off, e.width))
            addr = xf(e.addr) if isinstance(e.addr, ir.Expr) else e.addr
            return ir.Mem(addr, e.width, e.signed)
        if isinstance(e, ir.Bin):
            off = _sp_off(e)
            if off is not None and off not in saved:
                return ir.Un("&", ir.Reg(local(off, 4)))
            return ir.Bin(e.op, xf(e.l), xf(e.r))
        if isinstance(e, ir.Un):
            return ir.Un(e.op, xf(e.e))
        if isinstance(e, ir.IntrExpr):
            return ir.IntrExpr(e.name, [xf(a) for a in e.args])
        return e

    def drop(s):
        # stack adjust: sp = sp <op> K, or sp = r8 (frame restore)
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == "sp":
            if isinstance(s.src, ir.Bin) and isinstance(s.src.l, ir.Reg) and s.src.l.name == "sp":
                return True
            if isinstance(s.src, ir.Reg) and s.src.name in ("sp", FP):
                return True
        # frame-pointer setup: r8 = sp
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == FP \
                and isinstance(s.src, ir.Reg) and s.src.name == "sp":
            return True
        # callee-saved spill / restore
        if isinstance(s, ir.Assign):
            if isinstance(s.dst, ir.Mem) and isinstance(s.src, ir.Reg):
                off = _sp_off(s.dst.addr)
                if off in saved and s.src.name in saved[off]:
                    return True
            if isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Mem):
                off = _sp_off(s.src.addr)
                if off in saved and s.dst.name in saved[off]:
                    return True
        return False

    for b in func.blocks.values():
        out = []
        for s in b.stmts:
            if drop(s):
                continue
            if isinstance(s, ir.Assign):
                s.src = xf(s.src)
                if isinstance(s.dst, ir.Mem):
                    off = _sp_off(s.dst.addr)
                    if off is not None and off not in saved:
                        s.dst = ir.Reg(local(off, s.dst.width))
                    else:
                        s.dst = ir.Mem(xf(s.dst.addr) if isinstance(s.dst.addr, ir.Expr) else s.dst.addr,
                                       s.dst.width, s.dst.signed)
            elif isinstance(s, ir.Branch):
                s.cexpr = xf(s.cexpr)
            elif isinstance(s, ir.Intrinsic):
                s.args = [xf(a) for a in s.args]
            elif isinstance(s, ir.Call) and s.expr is not None:
                s.expr = xf(s.expr)
            out.append(s)
        b.stmts = out
    return func


def local_decls(func):
    """Lines declaring the recovered stack locals, widest first for stability."""
    locs = getattr(func, "locals", None)
    if not locs:
        return []
    ctype = {1: "char", 2: "short", 4: "int"}
    out = []
    for name in sorted(locs, key=lambda n: int(n.split("_")[1], 16)):
        out.append("    %s %s;" % (ctype.get(locs[name], "int"), name))
    return out
