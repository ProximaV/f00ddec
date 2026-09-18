"""
IR for the MeP/F00D decompiler.

A register machine (like rl78dec) but simpler: MeP conditional branches are
self-contained register compares, so a :class:`Branch` carries its condition
expression directly and there is no PSW/flag layer.  Statement shapes match the
other tools so the control-flow structurer and highlighter are shared.
"""


class Expr:
    pass


class Const(Expr):
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value & 0xFFFFFFFF


class Reg(Expr):
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def __eq__(self, o):
        return isinstance(o, Reg) and o.name == self.name

    def __hash__(self):
        return hash(("reg", self.name))


class Mem(Expr):
    """Memory access; ``addr`` is an int (absolute) or an Expr (reg-based).
    width in bytes (1/2/4); ``signed`` selects sign- vs zero-extension."""
    __slots__ = ("addr", "width", "signed")

    def __init__(self, addr, width=4, signed=False):
        self.addr = addr
        self.width = width
        self.signed = signed


class Bin(Expr):
    __slots__ = ("op", "l", "r")

    def __init__(self, op, l, r):
        self.op = op
        self.l = l
        self.r = r


class Un(Expr):
    __slots__ = ("op", "e")

    def __init__(self, op, e):
        self.op = op
        self.e = e


class IntrExpr(Expr):
    __slots__ = ("name", "args")

    def __init__(self, name, args):
        self.name = name
        self.args = args


# --- statements -------------------------------------------------------------

class Assign:
    __slots__ = ("ea", "dst", "src")

    def __init__(self, ea, dst, src):
        self.ea = ea
        self.dst = dst
        self.src = src


class Call:
    __slots__ = ("ea", "target", "expr")

    def __init__(self, ea, target=None, expr=None):
        self.ea = ea
        self.target = target
        self.expr = expr


class Intrinsic:
    __slots__ = ("ea", "name", "args", "note")

    def __init__(self, ea, name, args, note=""):
        self.ea = ea
        self.name = name
        self.args = args
        self.note = note


class Ret:
    __slots__ = ("ea", "kind")

    def __init__(self, ea, kind="ret"):
        self.ea = ea
        self.kind = kind


class Goto:
    __slots__ = ("ea", "target")

    def __init__(self, ea, target):
        self.ea = ea
        self.target = target


class Branch:
    __slots__ = ("ea", "cexpr", "target", "fallthrough")

    def __init__(self, ea, cexpr, target, fallthrough):
        self.ea = ea
        self.cexpr = cexpr          # condition expression (taken when true)
        self.target = target
        self.fallthrough = fallthrough


class Nop:
    __slots__ = ("ea",)

    def __init__(self, ea):
        self.ea = ea
