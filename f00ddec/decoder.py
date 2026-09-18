"""
Standalone Toshiba MeP decoder (little-endian, 16/32-bit).

Ported from the validated IDA 9.4 processor module (``mep.py``); produces
:class:`Insn` objects with a mnemonic and typed :class:`Operand` list, with no
dependency on IDA so the whole pipeline runs headless on a raw F00D dump.

Operand ``mode`` values:
    reg     register (``reg`` = 0..15 GPR, 16..47 control register)
    imm     immediate (``value``)
    near    code target (``addr``)
    mem     absolute data address (``addr``)
    phrase  register indirect  (rm)         (``base_reg``)
    displ   disp(reg)                        (``base_reg``, ``disp``)
"""

from . import isa


def _sx(x, b):
    m = 1 << (b - 1)
    x &= (1 << b) - 1
    return (x ^ m) - m


class Operand:
    __slots__ = ("mode", "reg", "value", "addr", "base_reg", "disp", "width")

    def __init__(self, mode, reg=0, value=0, addr=0, base_reg=0, disp=0, width=4):
        self.mode = mode
        self.reg = reg
        self.value = value
        self.addr = addr
        self.base_reg = base_reg
        self.disp = disp
        self.width = width


class Insn:
    __slots__ = ("ea", "size", "mnem", "ops")

    def __init__(self, ea):
        self.ea = ea
        self.size = 0
        self.mnem = None
        self.ops = []

    def __repr__(self):
        return "<Insn %06X %s>" % (self.ea, self.mnem)


CR = 16   # control registers start at reg index 16


def decode_one(image, ea, base=0):
    off = ea - base
    if off < 0 or off + 2 > len(image):
        return None
    hw = image[off] | (image[off + 1] << 8)
    size = 2
    ext = None
    if ((hw >> 12) & 0xF) >= 0xC:
        if off + 4 > len(image):
            return None
        ext = image[off + 2] | (image[off + 3] << 8)
        size = 4
    ins = Insn(ea)
    ins.size = size
    if not _decode(ins, hw, ext, ea):
        return None
    return ins


def _decode(ins, hw, ext, ea):
    maj = (hw >> 12) & 0xF
    lo4 = hw & 0xF
    rn = (hw >> 8) & 0xF
    rm = (hw >> 4) & 0xF
    rl = hw & 0xF
    op0707 = (hw >> 7) & 1
    op0000 = hw & 1

    def R(i): return Operand("reg", reg=i)
    def I(v): return Operand("imm", value=v & 0xFFFFFFFF)
    def N(t): return Operand("near", addr=t & 0xFFFFFFFF)
    def M(a): return Operand("mem", addr=a & 0xFFFFFFFF)
    def P(r): return Operand("phrase", base_reg=r)
    def D(r, d, w=4): return Operand("displ", base_reg=r, disp=d & 0xFFFFFFFF, width=w)

    def emit(mnem, *ops):
        ins.mnem = mnem
        ins.ops = list(ops)
        return True

    if maj == 0:
        m = {0x0: "mov", 0x1: "neg", 0x2: "slt3", 0x3: "sltu3", 0x4: "sub",
             0x8: "sb", 0x9: "sh", 0xA: "sw", 0xB: "lbu", 0xC: "lb",
             0xD: "lh", 0xE: "lw", 0xF: "lhu"}.get(lo4)
        if m is None:
            return False
        if m in ("slt3", "sltu3"):
            return emit(m, R(0), R(rn), R(rm))
        if m in ("sb", "sh", "sw", "lb", "lbu", "lh", "lhu", "lw"):
            return emit(m, R(rn), P(rm))
        return emit(m, R(rn), R(rm))

    if maj == 1:
        op0815 = (hw >> 8) & 0xFF
        if op0815 == 0x10 and lo4 == 0xE:
            if rm in (1, 11):
                return emit("ret")
            return emit("jmp", P(rm))
        if op0815 == 0x10 and lo4 == 0xF:
            return emit("jsr", P(rm))
        if lo4 == 0xD:
            em = {0x0: "extb", 0x8: "extub", 0x2: "exth", 0xA: "extuh"}.get(rm)
            return emit(em, R(rn)) if em else False
        m = {0x0: "or", 0x1: "and", 0x2: "xor", 0x3: "nor", 0x4: "mul",
             0x5: "mulu", 0x6: "mulr", 0x7: "mulru", 0x8: "div", 0x9: "divu"}.get(lo4)
        return emit(m, R(rn), R(rm)) if m else False

    if maj == 2:
        m = {0xE: "sll", 0xC: "srl", 0x6: "sl1ad3", 0x7: "sl2ad3"}.get(lo4)
        if m is None:
            return False
        if m in ("sl1ad3", "sl2ad3"):
            return emit(m, R(0), R(rn), R(rm))
        return emit(m, R(rn), R(rm))

    if maj == 4:
        op0001 = hw & 3
        udisp = ((hw >> 2) & 0x1F) << 2
        if op0707 == 0:
            if op0001 == 3:
                return emit("lw", R(rn), D(15, udisp))
            if op0001 == 2:
                return emit("sw", R(rn), D(15, udisp))
            if op0001 == 0:
                return emit("add3", R(rn), R(15), I(((hw >> 2) & 0x1F) << 2))
            return False
        op1115 = (hw >> 11) & 0x1F
        if op1115 == 8:
            if op0001 == 3:
                return emit("lw", R(rn), D(13, udisp))
            if op0001 == 2:
                return emit("sw", R(rn), D(13, udisp))
        if op1115 == 9:
            return emit("lbu", R(rn), D(13, hw & 0x7F, 1))
        return False

    if maj == 5:
        return emit("mov", R(rn), I(_sx(hw & 0xFF, 8)))

    if maj == 6:
        op0002 = hw & 7
        imm0307 = (hw >> 3) & 0x1F
        m = {6: "sll", 2: "srl", 3: "sra", 1: "slt3", 5: "sltu3", 7: "sll3"}.get(op0002)
        if m is None:
            return emit("add", R(rn), I(_sx((hw >> 2) & 0x3F, 6)))
        if m in ("slt3", "sltu3", "sll3"):
            return emit(m, R(0), R(rn), I(imm0307))
        return emit(m, R(rn), I(imm0307))

    if maj == 7:
        fixed = {0x7002: "ret", 0x7010: "ei", 0x7000: "di", 0x7012: "reti",
                 0x7062: "sleep", 0x7011: "syncm"}.get(hw)
        if fixed:
            return emit(fixed)
        op0103 = (hw >> 1) & 7
        if op0103 in (4, 5):
            cregidx = (op0000 << 4) | ((hw >> 4) & 0xF)
            return emit("ldc" if op0103 == 5 else "stc", R(rn), R(CR + cregidx))
        if ((hw >> 6) & 0x3FF) == 0x1C0:
            return emit("swi", I((hw >> 4) & 3))
        return False

    if maj == 8:
        op1115 = (hw >> 11) & 0x1F
        udisp = ((hw >> 1) & 0x3F) << 1
        if op1115 == 0x10:
            if op0707 == 0:
                return emit("sb", R(rn), D(13, hw & 0x7F, 1))
            return emit("sh", R(rn), D(13, udisp, 2))
        if op1115 == 0x11:
            if op0707 == 0:
                return emit("lb", R(rn), D(13, hw & 0x7F, 1))
            return emit("lh" if op0000 == 0 else "lhu", R(rn), D(13, udisp, 2))
        return False

    if maj == 9:
        return emit("add3", R(rl), R(rn), R(rm))

    if maj == 0xA:
        tgt = ea + (_sx((hw >> 1) & 0x7F, 7) << 1)
        return emit("bnez" if op0000 else "beqz", R(rn), N(tgt))

    if maj == 0xB:
        tgt = ea + (_sx((hw >> 1) & 0x7FF, 11) << 1)
        return emit("bsr" if op0000 else "bra", N(tgt))

    # ---- 32-bit ------------------------------------------------------------
    if maj == 0xC:
        simm = _sx(ext, 16)
        if lo4 == 0x0:
            return emit("add3", R(rn), R(rm), I(simm))
        if lo4 == 0x1:
            sub = {0x0: "mov", 0x1: "movu", 0x2: "movh"}.get(rm)
            if sub is None:
                return False
            val = (ext << 16) if sub == "movh" else (simm if sub == "mov" else ext)
            return emit(sub, R(rn), I(val))
        three = {0x2: "slt3", 0x3: "sltu3", 0x4: "or3", 0x5: "and3", 0x6: "xor3"}.get(lo4)
        if three:
            return emit(three, R(rn), R(rm), I(simm if three == "slt3" else ext))
        ls = {0x8: ("sb", 1), 0x9: ("sh", 2), 0xA: ("sw", 4), 0xB: ("lbu", 1),
              0xC: ("lb", 1), 0xD: ("lh", 2), 0xE: ("lw", 4), 0xF: ("lhu", 2)}.get(lo4)
        if ls:
            return emit(ls[0], R(rn), D(rm, simm, ls[1]))
        return False

    if maj == 0xD:
        op1115 = (hw >> 11) & 0x1F
        if op1115 == 0x1A:
            return emit("movu", R(rn), I((hw & 0xFF) | (ext << 8)))
        if op1115 == 0x1B:
            imm0410 = (hw >> 4) & 0x7F
            if lo4 == 0x8:
                return emit("jmp", N((ea & 0xF0000000) | (ext << 8) | (imm0410 << 1)))
            if lo4 == 0x9:
                return emit("bsr", N(ea + ((imm0410 << 1) | (ext << 8))))
        return False

    if maj == 0xE:
        if hw == 0xE019:
            return emit("erepeat", N(ea + (_sx(ext, 16) << 1)))
        op0001 = hw & 3
        op0207 = (hw >> 2) & 0x3F
        if (hw & 0xFF) == 0x09:
            return emit("repeat", R(rn), N(ea + (_sx(ext, 16) << 1)))
        if op0001 == 3 and lo4 in (0x3, 0x7, 0xB, 0xF):
            return emit("lw", R(rn), M((ext << 8) | (op0207 << 2)))
        if op0001 == 2 and lo4 in (0x2, 0x6, 0xA, 0xE):
            return emit("sw", R(rn), M((ext << 8) | (op0207 << 2)))
        br = {0x0: "beqi", 0x1: "beq", 0x4: "bnei", 0x5: "bne",
              0x8: "bgei", 0xC: "blti"}.get(lo4)
        if br:
            tgt = ea + (_sx(ext, 16) << 1)
            if br in ("beq", "bne"):
                return emit(br, R(rn), R(rm), N(tgt))
            return emit(br, R(rn), I(rm), N(tgt))
        return False

    if maj == 0xF:
        op0007 = hw & 0xFF
        if op0007 == 0x14:
            return emit("ldcb", R(rn), I(ext))
        if op0007 == 0x04:
            return emit("stcb", R(rn), I(ext))
        if lo4 == 0x1 and ext == 3:
            return emit("abs", R(rn), R(rm))
        return False

    return False


def target_of(ins):
    for op in ins.ops:
        if op.mode == "near":
            return op.addr
    return None


def _succ(ins):
    m = ins.mnem
    nxt = ins.ea + ins.size
    t = target_of(ins)
    if m == "bra" or m == "jmp":
        return [("jump", t)] if t is not None else []
    if m in isa.RET:
        return []
    if m in isa.COND_BRANCH:
        s = [("cond", t)] if t is not None else []
        s.append(("fall", nxt))
        return s
    if m in ("bsr", "jsr"):
        if t is not None:
            return [("call", t), ("fall", nxt)]
        return [("fall", nxt)]
    return [("fall", nxt)]


def decode(image, entries, base=0):
    insns, calls, seen = {}, set(), set()
    work = [e for e in entries if base <= e < base + len(image)]
    while work:
        ea = work.pop()
        if ea in seen or not (base <= ea < base + len(image)):
            continue
        seen.add(ea)
        ins = decode_one(image, ea, base)
        if ins is None:
            continue
        insns[ea] = ins
        for how, tgt in _succ(ins):
            if tgt is None:
                continue
            if how == "call":
                calls.add(tgt)
            work.append(tgt)
    return insns, calls
