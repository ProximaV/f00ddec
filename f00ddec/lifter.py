"""
Lift decoded MeP :class:`~f00ddec.decoder.Insn` objects into IR statements,
following the semantics in xyzz's Ghidra SLEIGH (``mep.sinc``).

MeP compare-and-branch instructions become an :class:`~f00ddec.ir.Branch` whose
condition is a full relational expression, so no flag modelling is needed.
Control-register, control-bus, multiply/divide (hi:lo) and CPU-control
instructions that do not map cleanly onto C are emitted as honest pseudo-calls.
"""

from . import ir, isa
from .decoder import target_of


def _reg(i):
    return ir.Reg(isa.REG[i] if i < 16 else isa.CREG[i - 16])


def op_expr(op):
    m = op.mode
    if m == "reg":
        return _reg(op.reg)
    if m == "imm":
        return ir.Const(op.value)
    if m == "mem":
        return ir.Mem(op.addr, op.width)
    if m == "phrase":
        return ir.Mem(_reg(op.base_reg), op.width)
    if m == "displ":
        base = _reg(op.base_reg)
        addr = base if op.disp == 0 else ir.Bin("+", base, ir.Const(op.disp))
        return ir.Mem(addr, op.width)
    return ir.Const(op.addr)


_ALU = {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^",
        "sll": "<<", "srl": ">>"}
_ALU3 = {"add3": "+", "and3": "&", "or3": "|", "xor3": "^"}
_LOAD = {"lb": (1, True), "lbu": (1, False), "lh": (2, True), "lhu": (2, False),
         "lw": (4, False)}
_STORE = {"sb": 1, "sh": 2, "sw": 4}
_CMP = {"beq": "==", "bne": "!=", "beqz": "==", "bnez": "!=",
        "beqi": "==", "bnei": "!=", "blti": "<", "bgei": ">="}


def lift_insn(ins):
    ea = ins.ea
    m = ins.mnem
    ops = ins.ops

    def e(i):
        return op_expr(ops[i])

    # --- moves -------------------------------------------------------------
    if m == "mov":
        return [ir.Assign(ea, e(0), e(1))]
    if m == "movu":
        return [ir.Assign(ea, e(0), e(1))]
    if m == "movh":
        return [ir.Assign(ea, e(0), e(1))]        # value already <<16 by decoder

    # --- arithmetic / logic ------------------------------------------------
    if m in _ALU:
        return [ir.Assign(ea, e(0), ir.Bin(_ALU[m], e(0), e(1)))]
    if m == "sra":
        return [ir.Assign(ea, e(0), ir.IntrExpr("sra", [e(0), e(1)]))]
    if m == "neg":
        return [ir.Assign(ea, e(0), ir.Un("-", e(1)))]
    if m == "nor":
        return [ir.Assign(ea, e(0), ir.Un("~", ir.Bin("|", e(0), e(1))))]
    if m == "abs":
        return [ir.Assign(ea, e(0), ir.IntrExpr("abs", [e(0), e(1)]))]
    if m in _ALU3:
        return [ir.Assign(ea, e(0), ir.Bin(_ALU3[m], e(1), e(2)))]
    if m == "sll3":
        return [ir.Assign(ea, e(0), ir.Bin("<<", e(1), e(2)))]
    if m == "sl1ad3":
        return [ir.Assign(ea, e(0), ir.Bin("+", ir.Bin("<<", e(1), ir.Const(1)), e(2)))]
    if m == "sl2ad3":
        return [ir.Assign(ea, e(0), ir.Bin("+", ir.Bin("<<", e(1), ir.Const(2)), e(2)))]
    if m in ("slt3", "sltu3"):
        return [ir.Assign(ea, e(0), ir.Bin("<", e(1), e(2)))]
    if m in ("extb", "exth"):
        return [ir.Assign(ea, e(0), ir.IntrExpr("sext", [e(0)]))]
    if m in ("extub", "extuh"):
        w = 1 if m == "extub" else 2
        mask = (1 << (8 * w)) - 1
        return [ir.Assign(ea, e(0), ir.Bin("&", e(0), ir.Const(mask)))]

    # --- multiply / divide (hi:lo) ----------------------------------------
    if m in ("mul", "mulu"):
        return [ir.Assign(ea, ir.Reg("lo"), ir.IntrExpr(m, [e(0), e(1)]))]
    if m in ("mulr", "mulru"):
        return [ir.Assign(ea, e(0), ir.IntrExpr(m, [e(0), e(1)]))]
    if m in ("div", "divu"):
        opd = "/" if m == "divu" else "s/"
        return [ir.Assign(ea, ir.Reg("lo"), ir.Bin(opd, e(0), e(1))),
                ir.Assign(ea, ir.Reg("hi"), ir.Bin("%", e(0), e(1)))]

    # --- loads / stores ----------------------------------------------------
    if m in _LOAD:
        w, sg = _LOAD[m]
        src = op_expr(ops[1]); src.width = w; src.signed = sg
        return [ir.Assign(ea, e(0), src)]
    if m in _STORE:
        w = _STORE[m]
        dst = op_expr(ops[1]); dst.width = w
        return [ir.Assign(ea, dst, e(0))]

    # --- control registers / bus ------------------------------------------
    if m == "ldc":
        return [ir.Assign(ea, e(0), e(1))]
    if m == "stc":
        return [ir.Assign(ea, e(1), e(0))]
    if m == "ldcb":
        return [ir.Assign(ea, e(0), ir.IntrExpr("control_bus_load", [e(1)]))]
    if m == "stcb":
        return [ir.Intrinsic(ea, "control_bus_store", [e(1), e(0)])]

    # --- control flow ------------------------------------------------------
    if m == "bra":
        return [ir.Goto(ea, target_of(ins))]
    if m == "jmp":
        t = target_of(ins)
        if t is not None:
            return [ir.Goto(ea, t)]
        return [ir.Intrinsic(ea, "jmp", [op_expr(ops[0])], note="indirect")]
    if m in ("bsr",):
        return [ir.Call(ea, target=target_of(ins))]
    if m == "jsr":
        return [ir.Call(ea, expr=op_expr(ops[0]))]
    if m in _CMP:
        tgt = target_of(ins)
        if m in ("beqz", "bnez"):
            cx = ir.Bin(_CMP[m], e(0), ir.Const(0))
        else:
            cx = ir.Bin(_CMP[m], e(0), e(1))
        return [ir.Branch(ea, cx, tgt, ea + ins.size)]
    if m in ("ret", "reti"):
        return [ir.Ret(ea, m)]

    # --- cpu control / misc ------------------------------------------------
    if m in ("ei", "di", "sleep", "syncm", "swi", "break"):
        args = [op_expr(o) for o in ops]
        return [ir.Intrinsic(ea, m, args)]
    if m in ("repeat", "erepeat"):
        return [ir.Intrinsic(ea, m, [op_expr(o) for o in ops], note="hardware loop")]
    if m == "nop":
        return [ir.Nop(ea)]

    return [ir.Intrinsic(ea, m, [op_expr(o) for o in ops], note="unmodelled")]
