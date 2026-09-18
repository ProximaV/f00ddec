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


_KEEP = frozenset(("ei", "di", "sleep", "syncm", "nop", "break", "control_bus_store"))


def _opt_block(block):
    env = {}
    for s in block.stmts:
        if isinstance(s, ir.Assign):
            s.src = _fold(_subst(s.src, env))
            if isinstance(s.dst, ir.Reg):
                _kill(env, s.dst.name)
                if isinstance(s.src, (ir.Const, ir.Reg)) and not _mentions(s.src, s.dst.name):
                    env[s.dst.name] = s.src
            else:
                s.dst = _fold(_subst(s.dst, env))
        elif isinstance(s, ir.Branch):
            s.cexpr = _fold(_subst(s.cexpr, env))
        elif isinstance(s, ir.Intrinsic):
            s.args = [_fold(_subst(a, env)) for a in s.args]
            if s.name not in _KEEP:
                env.clear()
        elif isinstance(s, ir.Call):
            env.clear()


def optimize(func):
    for b in func.blocks.values():
        _opt_block(b)
    return func
