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
    __slots__ = ("mode", "reg", "value", "addr", "base_reg", "disp", "width", "name")

    def __init__(self, mode, reg=0, value=0, addr=0, base_reg=0, disp=0, width=4, name=None):
        self.mode = mode
        self.reg = reg
        self.value = value
        self.addr = addr
        self.base_reg = base_reg
        self.disp = disp
        self.width = width
        self.name = name


class SwitchInfo:
    __slots__ = ("jmp_ea", "table_ea", "ncases", "lowcase", "default_ea",
                 "bounds_ea", "idx_kind", "idx_val", "cases", "targets", "setup_eas")

    def __init__(self, jmp_ea, table_ea, ncases, lowcase, default_ea,
                 bounds_ea, idx_kind, idx_val, cases, targets, setup_eas):
        self.jmp_ea = jmp_ea
        self.table_ea = table_ea
        self.ncases = ncases
        self.lowcase = lowcase
        self.default_ea = default_ea
        self.bounds_ea = bounds_ea
        self.idx_kind = idx_kind
        self.idx_val = idx_val
        self.cases = cases
        self.targets = targets
        self.setup_eas = setup_eas


class Insn:
    __slots__ = ("ea", "size", "mnem", "ops", "switch_info")

    def __init__(self, ea):
        self.ea = ea
        self.size = 0
        self.mnem = None
        self.ops = []
        self.switch_info = None

    def __repr__(self):
        return "<Insn %06X %s>" % (self.ea, self.mnem)


CR = 16   # control registers start at reg index 16


def in_bounds(image, ea, base=0, size=2):
    if hasattr(image, "contains"):
        return image.contains(ea, size)
    off = ea - base
    return 0 <= off and off + size <= len(image)


def read_u16(image, ea, base=0):
    if hasattr(image, "get_u16"):
        return image.get_u16(ea)
    off = ea - base
    if off < 0 or off + 2 > len(image):
        return None
    return image[off] | (image[off + 1] << 8)


def read_u32(image, ea, base=0):
    if hasattr(image, "get_u32"):
        return image.get_u32(ea)
    off = ea - base
    if off < 0 or off + 4 > len(image):
        return None
    return (image[off] | (image[off + 1] << 8)
            | (image[off + 2] << 16) | (image[off + 3] << 24))


def decode_one(image, ea, base=0):
    hw = read_u16(image, ea, base)
    if hw is None:
        return None
    size = 2
    ext = None
    if ((hw >> 12) & 0xF) >= 0xC:
        ext = read_u16(image, ea + 2, base)
        if ext is None:
            return None
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
        if hw == 0x0000:
            return emit("nop")
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
        if (hw & 0xFC0F) == 0x100C:
            return emit("ssarb", D(rm, (hw >> 8) & 3, 1))
        if op0815 == 0x10 and lo4 == 0xE:
            return emit("jmp", R(rm))
        if op0815 == 0x10 and lo4 == 0xF:
            return emit("jsr", R(rm))
        if op0815 == 0x18 and lo4 == 0xF:
            return emit("jsrv", R(rm))
        if lo4 == 0xD:
            em = {0x0: "extb", 0x8: "extub", 0x2: "exth", 0xA: "extuh"}.get(rm)
            return emit(em, R(rn)) if em else False
        m = {0x0: "or", 0x1: "and", 0x2: "xor", 0x3: "nor", 0x4: "mul",
             0x5: "mulu", 0x6: "mulr", 0x7: "mulru", 0x8: "div", 0x9: "divu"}.get(lo4)
        return emit(m, R(rn), R(rm)) if m else False

    if maj == 2:
        if (hw & 0xF800) == 0x2000 and lo4 in (0x0, 0x1, 0x2, 0x3):
            bm = {0x0: "bsetm", 0x1: "bclrm", 0x2: "bnotm", 0x3: "btstm"}[lo4]
            return emit(bm, P(rm), I(rn & 7))
        if lo4 == 0x4:
            return emit("tas", R(rn), P(rm))
        if lo4 == 0xF:
            return emit("fsft", R(rn), R(rm))
        m = {0xE: "sll", 0xC: "srl", 0xD: "sra", 0x6: "sl1ad3", 0x7: "sl2ad3"}.get(lo4)
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
                return emit("lw", R(rn & 7), D(13, udisp))
            if op0001 == 2:
                return emit("sw", R(rn & 7), D(13, udisp))
            if op0001 == 0:
                return emit("add3", R(rn & 7), R(13), I(udisp))
        if op1115 == 9:
            return emit("lbu", R(rn & 7), D(13, hw & 0x7F, 1))
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
                 0x7062: "sleep", 0x7011: "syncm", 0x7021: "synccp",
                 0x7022: "halt", 0x7032: "break", 0x7013: "dret",
                 0x7033: "dbreak"}.get(hw)
        if fixed:
            return emit(fixed)
        if (hw & 0xFF0F) == 0x7C04:
            return emit("stcb", R(rn), R(rm))
        if (hw & 0xFF0F) == 0x7D04:
            return emit("ldcb", R(rn), R(rm))
        if (hw & 0xF00F) == 0x7004:
            return emit("cache", I(rn), P(rm))
        if (hw & 0xF00F) == 0x7005:
            return emit("pref", I(rn), P(rm))
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
                return emit("sb", R(rn & 7), D(13, hw & 0x7F, 1))
            return emit("sh", R(rn & 7), D(13, udisp, 2))
        if op1115 == 0x11:
            if op0707 == 0:
                return emit("lb", R(rn & 7), D(13, hw & 0x7F, 1))
            return emit("lh" if op0000 == 0 else "lhu", R(rn & 7), D(13, udisp, 2))
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
                return emit("bsr", N(ea + _sx((imm0410 << 1) | (ext << 8), 24)))
            if lo4 == 0xB:
                return emit("bsrv", N(ea + _sx((imm0410 << 1) | (ext << 8), 24)))
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
        if lo4 == 0x1:
            ext_op = {
                0x0000: "ldz", 0x0002: "ave", 0x0003: "abs",
                0x0004: "min", 0x0005: "max", 0x0006: "minu", 0x0007: "maxu",
                0x0008: "sadd", 0x0009: "saddu", 0x000A: "ssub", 0x000B: "ssubu",
                0x3004: "madd", 0x3005: "maddu", 0x3006: "maddr", 0x3007: "maddru",
            }.get(ext)
            if ext_op:
                return emit(ext_op, R(rn), R(rm))
            if rm == 0 and (ext & 0xFF07) == 0x1000:
                return emit("clip", R(rn), I((ext >> 3) & 0x1F))
            if rm == 0 and (ext & 0xFF07) == 0x1001:
                return emit("clipu", R(rn), I((ext >> 3) & 0x1F))
        return False

    return False


def target_of(ins):
    for op in ins.ops:
        if op.mode == "near":
            return op.addr
    return None


def resolve_switch(image, base, insns, jmp_ea):
    """Detect MeP switch jump-table idioms ending at indirect `jmp` *jmp_ea*."""
    jmp_ins = insns.get(jmp_ea)
    if jmp_ins is None or jmp_ins.mnem != "jmp" or not jmp_ins.ops:
        return None
    if jmp_ins.ops[0].mode != "reg":
        return None
    if jmp_ins.switch_info is not None:
        return jmp_ins.switch_info

    target_reg = jmp_ins.ops[0].reg
    window = [insns[e] for e in sorted(insns) if jmp_ea - 0x80 <= e < jmp_ea]
    if not window:
        return None

    reg = {}
    sp_slot = {}
    last_bounds = None

    for ins in window:
        ea = ins.ea
        m = ins.mnem
        ops = ins.ops
        if m in ("mov", "movu", "movh") and len(ops) == 2 and ops[0].mode == "reg":
            if ops[1].mode == "imm":
                reg[ops[0].reg] = ("const", ops[1].value, frozenset([ea]))
            elif ops[1].mode == "reg":
                prev = reg.get(ops[1].reg, ("var", "reg", ops[1].reg, frozenset()))
                reg[ops[0].reg] = (*prev[:-1], prev[-1] | {ea})
        elif m in ("add3", "or3") and len(ops) == 3 and ops[0].mode == "reg":
            d = ops[0].reg
            if ops[1].mode == "reg" and ops[2].mode == "imm":
                v1 = reg.get(ops[1].reg, ("var", "reg", ops[1].reg, frozenset()))
                if v1[0] == "const":
                    val = ((v1[1] + ops[2].value) & 0xFFFFFFFF
                           if m == "add3" else (v1[1] | ops[2].value))
                    reg[d] = ("const", val, v1[-1] | {ea})
                elif v1[0] == "var" and m == "add3":
                    reg[d] = ("bias", v1[1], v1[2], ops[2].value, v1[-1] | {ea})
                else:
                    reg.pop(d, None)
            elif ops[1].mode == "reg" and ops[2].mode == "reg" and m == "add3":
                v1 = reg.get(ops[1].reg)
                v2 = reg.get(ops[2].reg)
                if v1 and v1[0] == "const" and v2 and v2[0] == "scaled":
                    reg[d] = ("table_ptr", v1[1], v2[1], v1[-1] | v2[-1] | {ea})
                elif v2 and v2[0] == "const" and v1 and v1[0] == "scaled":
                    reg[d] = ("table_ptr", v2[1], v1[1], v1[-1] | v2[-1] | {ea})
                else:
                    reg.pop(d, None)
        elif m == "add" and len(ops) == 2 and ops[0].mode == "reg" and ops[1].mode == "imm":
            r = ops[0].reg
            prev = reg.get(r, ("var", "reg", r, frozenset()))
            if prev[0] == "const":
                reg[r] = ("const", (prev[1] + ops[1].value) & 0xFFFFFFFF, prev[-1] | {ea})
            elif prev[0] == "var":
                reg[r] = ("bias", prev[1], prev[2], ops[1].value, prev[-1] | {ea})
            else:
                reg.pop(r, None)
        elif m == "sltu3" and len(ops) == 3 and ops[0].mode == "reg":
            d = ops[0].reg
            if ops[1].mode == "reg" and ops[2].mode == "reg":
                vmax = reg.get(ops[1].reg)
                vidx = reg.get(ops[2].reg, ("var", "reg", ops[2].reg, frozenset()))
                if vmax and vmax[0] == "const" and vmax[1] <= 256:
                    reg[d] = ("bounds", vmax[1] + 1, vidx, vmax[-1] | vidx[-1] | {ea})
            elif ops[1].mode == "reg" and ops[2].mode == "imm":
                vidx = reg.get(ops[1].reg, ("var", "reg", ops[1].reg, frozenset()))
                if 0 < ops[2].value <= 256:
                    reg[d] = ("bounds_lt", ops[2].value, vidx, vidx[-1] | {ea})
        elif m in ("bnei", "bnez", "beqi", "beqz"):
            r = ops[0].reg
            b = reg.get(r)
            tgt = target_of(ins)
            if b and b[0] == "bounds" and ((m == "bnei" and ops[1].value == 0) or m == "bnez"):
                last_bounds = (b[1], b[2], tgt, ea, b[-1] | {ea})
            elif b and b[0] == "bounds_lt" and ((m == "beqi" and ops[1].value == 0) or m == "beqz"):
                last_bounds = (b[1], b[2], tgt, ea, b[-1] | {ea})
        elif m in ("sll", "sll3"):
            d = ops[0].reg
            src_r = ops[0].reg if m == "sll" else ops[1].reg
            sh_op = ops[1] if m == "sll" else ops[2]
            if sh_op.mode == "imm" and sh_op.value == 2:
                vidx = reg.get(src_r, ("var", "reg", src_r, frozenset()))
                reg[d] = ("scaled", vidx, vidx[-1] | {ea})
            else:
                reg.pop(d, None)
        elif m == "sw" and len(ops) == 2 and ops[0].mode == "reg" and ops[1].mode == "displ":
            if ops[1].base_reg == 15 and ops[0].reg in reg:
                prev = reg[ops[0].reg]
                sp_slot[ops[1].disp] = (*prev[:-1], prev[-1] | {ea})
        elif m == "lw" and len(ops) == 2 and ops[0].mode == "reg":
            d = ops[0].reg
            if ops[1].mode == "displ" and ops[1].base_reg == 15:
                if ops[1].disp in sp_slot:
                    prev = sp_slot[ops[1].disp]
                    reg[d] = (*prev[:-1], prev[-1] | {ea})
                else:
                    reg[d] = ("var", "stack", ops[1].disp, frozenset([ea]))
            elif ops[1].mode == "phrase":
                p = reg.get(ops[1].base_reg)
                if p and p[0] == "table_ptr":
                    reg[d] = ("table_entry", p[1], p[2], p[-1] | {ea})
                else:
                    reg.pop(d, None)
            else:
                reg.pop(d, None)
        elif m in isa.CALL:
            for caller_r in (0, 1, 2, 3, 4):
                reg.pop(caller_r, None)

    te = reg.get(target_reg)
    if not te or te[0] != "table_entry" or last_bounds is None:
        return None

    table_ea, vidx, te_eas = te[1], te[2], te[3]
    ncases, _b_vidx, default_ea, bounds_ea, b_eas = last_bounds
    if ncases <= 0 or ncases > 256:
        return None

    cases = []
    targets = []
    if vidx[0] == "bias":
        idx_kind, idx_val = vidx[1], vidx[2]
        lowcase = (-_sx(vidx[3], 32)) & 0xFFFFFFFF
    elif vidx[0] == "var":
        idx_kind, idx_val = vidx[1], vidx[2]
        lowcase = 0
    else:
        idx_kind, idx_val, lowcase = "reg", target_reg, 0

    for k in range(ncases):
        t = read_u32(image, table_ea + 4 * k, base)
        if t is None or (t & 1) != 0 or not in_bounds(image, t, base):
            return None
        cases.append((lowcase + k, t))
        if t not in targets:
            targets.append(t)

    sw = SwitchInfo(
        jmp_ea=jmp_ea,
        table_ea=table_ea,
        ncases=ncases,
        lowcase=lowcase,
        default_ea=default_ea,
        bounds_ea=bounds_ea,
        idx_kind=idx_kind,
        idx_val=idx_val,
        cases=cases,
        targets=targets,
        setup_eas=frozenset(te_eas | b_eas | {jmp_ea}),
    )
    jmp_ins.switch_info = sw
    return sw


def _succ(ins):
    m = ins.mnem
    nxt = ins.ea + ins.size
    t = target_of(ins)
    if m == "bra" or m == "jmp":
        if ins.switch_info is not None:
            return [("case", ct) for ct in ins.switch_info.targets]
        return [("jump", t)] if t is not None else []
    if m in isa.RET:
        return []
    if m in isa.COND_BRANCH:
        s = [("cond", t)] if t is not None else []
        s.append(("fall", nxt))
        return s
    if m in isa.CALL:
        if t is not None:
            return [("call", t), ("fall", nxt)]
        return [("fall", nxt)]
    if m in ("repeat", "erepeat"):
        s = [("fall", nxt)]
        if t is not None:
            s.append(("loop_end", t))
        return s
    return [("fall", nxt)]


def decode(image, entries, base=0, stop_at=frozenset()):
    insns, calls, seen = {}, set(), set()
    work = [e for e in entries if in_bounds(image, e, base)]
    while True:
        while work:
            ea = work.pop()
            if ea in seen or not in_bounds(image, ea, base):
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
                    if tgt in stop_at:
                        continue
                elif tgt in stop_at:
                    continue
                work.append(tgt)

        new_targets = False
        for ea, ins in list(insns.items()):
            if ins.mnem == "jmp" and ins.ops and ins.ops[0].mode == "reg" and ins.switch_info is None:
                sw = resolve_switch(image, base, insns, ea)
                if sw is not None:
                    for ct in sw.targets:
                        if ct not in seen and ct not in stop_at:
                            work.append(ct)
                            new_targets = True
        if not new_targets:
            break
    return insns, calls

