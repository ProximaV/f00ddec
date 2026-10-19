"""
Conservative, block-local optimisation for the MeP IR: constant folding plus
propagation of register constants and copies within a basic block.  The
environment tracks registers only, so a memory store never invalidates it; a
call or a memory-clobbering intrinsic clears it.  This folds the common
``movh`` + ``or3``/``add3`` address-building idiom into a single constant.
"""

from . import ir


_OPS = {
    "+": lambda a, b: (a + b) & 0xFFFFFFFF, "-": lambda a, b: (a - b) & 0xFFFFFFFF,
    "|": lambda a, b: a | b, "&": lambda a, b: a & b, "^": lambda a, b: a ^ b,
    "<<": lambda a, b: (a << (b & 31)) & 0xFFFFFFFF, ">>": lambda a, b: a >> (b & 31),
}


def _fold(e):
    if isinstance(e, ir.Bin):
        l, r = _fold(e.l), _fold(e.r)
        if isinstance(l, ir.Const) and isinstance(r, ir.Const) and e.op in _OPS:
            return ir.Const(_OPS[e.op](l.value, r.value))
        if isinstance(r, ir.Const) and r.value == 0 and e.op in ("+", "-", "|", "^", "<<", ">>"):
            return l
        if isinstance(l, ir.Bin) and l.op == "<" and isinstance(r, ir.Const) and r.value == 0:
            if e.op == "!=":
                return l
            if e.op == "==":
                return ir.Bin(">=", l.l, l.r)
        return ir.Bin(e.op, l, r)
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _fold(e.e))
    if isinstance(e, ir.Mem):
        return ir.Mem(_fold(e.addr) if isinstance(e.addr, ir.Expr) else e.addr, e.width, e.signed)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_fold(a) for a in e.args])
    return e


def _mentions(e, name):
    if isinstance(e, ir.Reg):
        return e.name == name
    if isinstance(e, ir.Bin):
        return _mentions(e.l, name) or _mentions(e.r, name)
    if isinstance(e, ir.Un):
        return _mentions(e.e, name)
    if isinstance(e, ir.Mem):
        return isinstance(e.addr, ir.Expr) and _mentions(e.addr, name)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions(a, name) for a in e.args)
    return False


def _stmt_reads(s, name):
    if isinstance(s, ir.Assign):
        if _mentions(s.src, name):
            return True
        if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
            return _mentions(s.dst.addr, name)
        return False
    if isinstance(s, ir.Branch):
        return _mentions(s.cexpr, name)
    if isinstance(s, ir.Switch):
        return _mentions(s.expr, name)
    if isinstance(s, ir.Call):
        return (s.expr is not None and _mentions(s.expr, name)) or any(
            _mentions(a, name) for a in (s.args or ())
        )
    if isinstance(s, ir.Intrinsic):
        return any(_mentions(a, name) for a in s.args)
    return False


def _subst(e, env):
    if isinstance(e, ir.Reg):
        return env.get(e.name, e)
    if isinstance(e, ir.Bin):
        return ir.Bin(e.op, _subst(e.l, env), _subst(e.r, env))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst(e.e, env))
    if isinstance(e, ir.Mem):
        return ir.Mem(_subst(e.addr, env) if isinstance(e.addr, ir.Expr) else e.addr, e.width, e.signed)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst(a, env) for a in e.args])
    return e


def _kill(env, name):
    for k in [k for k, v in env.items() if k == name or _mentions(v, name)]:
        del env[k]


_KEEP = frozenset(("ei", "di", "sleep", "syncm", "synccp", "nop", "break", "control_bus_store"))


def _opt_block(block):
    env = {}
    mem_env = {}
    folded_cmp_reg = None
    for s in block.stmts:
        if isinstance(s, ir.Assign):
            s.src = _fold(_subst(s.src, env))
            if (isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Bin)
                    and s.src.op == "<" and s.dst.name in mem_env
                    and _mentions(s.src, s.dst.name)):
                s.src = _fold(_subst(s.src, {s.dst.name: mem_env[s.dst.name]}))
            if isinstance(s.dst, ir.Reg):
                _kill(env, s.dst.name)
                _kill(mem_env, s.dst.name)
                if isinstance(s.src, (ir.Const, ir.Reg)) and not _mentions(s.src, s.dst.name):
                    env[s.dst.name] = s.src
                elif (isinstance(s.src, ir.Bin) and s.src.op == "<"
                      and not _mentions(s.src, s.dst.name)):
                    env[s.dst.name] = s.src
                elif isinstance(s.src, ir.Mem) and not _mentions(s.src, s.dst.name):
                    mem_env[s.dst.name] = s.src
            else:
                s.dst = _fold(_subst(s.dst, env))
                mem_env.clear()
        elif isinstance(s, ir.Branch):
            orig = s.cexpr
            s.cexpr = _fold(_subst(s.cexpr, env))
            if s.cexpr is not orig and isinstance(orig, ir.Bin) and isinstance(orig.l, ir.Reg):
                if orig.l.name in env and isinstance(env[orig.l.name], ir.Bin):
                    folded_cmp_reg = orig.l.name
        elif isinstance(s, ir.Switch):
            s.expr = _fold(_subst(s.expr, env))
        elif isinstance(s, ir.Intrinsic):
            s.args = [_fold(_subst(a, env)) for a in s.args]
            if s.name not in _KEEP:
                env.clear()
            mem_env.clear()
        elif isinstance(s, ir.Call):
            if s.expr is not None:
                s.expr = _fold(_subst(s.expr, env))
            env.clear()
            mem_env.clear()



    # Intra-block dead assignment elimination:
    # 1. Drop self-copies `rX = rX`.
    # 2. Drop `rX = ...` if `rX` is overwritten later in the same block before any read.
    # 3. Drop temporary `r0 = a < b` when folded into the block's terminating Branch.
    stmts = block.stmts
    keep = []
    n = len(stmts)
    for i, s in enumerate(stmts):
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
            rname = s.dst.name
            if isinstance(s.src, ir.Reg) and s.src.name == rname:
                continue
            dead = False
            for j in range(i + 1, n):
                sj = stmts[j]
                if _stmt_reads(sj, rname):
                    break
                if isinstance(sj, ir.Assign) and isinstance(sj.dst, ir.Reg) and sj.dst.name == rname:
                    dead = True
                    break
            if dead:
                continue
            if (folded_cmp_reg == rname and rname == "r0"
                    and isinstance(s.src, ir.Bin) and s.src.op == "<"
                    and not any(_stmt_reads(stmts[j], rname) for j in range(i + 1, n))):
                continue
        keep.append(s)
    block.stmts = keep


def optimize(func):
    for b in func.blocks.values():
        _opt_block(b)
    return func

