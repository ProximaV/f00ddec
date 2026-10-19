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
# Under the Toshiba MeP EABI, r5..r12 are callee-saved.
FP = "r8"
CALLEE_SAVED = frozenset(("r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "tp", "gp", "sp", "lp"))


def _sp_off(addr):
    """Return the raw displacement if *addr* is sp / sp+const, else None."""
    if isinstance(addr, ir.Reg) and addr.name == "sp":
        return 0
    if (isinstance(addr, ir.Bin) and addr.op == "+"
            and isinstance(addr.l, ir.Reg) and addr.l.name == "sp"
            and isinstance(addr.r, ir.Const)):
        return addr.r.value
    return None


def _sp_adjust_delta(stmt):
    """If *stmt* is `sp = sp + K` or `sp = sp - K`, return signed delta, else None."""
    if not (isinstance(stmt, ir.Assign) and isinstance(stmt.dst, ir.Reg) and stmt.dst.name == "sp"):
        return None
    if isinstance(stmt.src, ir.Bin) and isinstance(stmt.src.l, ir.Reg) and stmt.src.l.name == "sp":
        if isinstance(stmt.src.r, ir.Const):
            v = stmt.src.r.value
            if stmt.src.op == "+":
                return (v - 0x100000000) if v >= 0x80000000 else v
            if stmt.src.op == "-":
                return -((v - 0x100000000) if v >= 0x80000000 else v)
    return None


def _compute_sp_profile(func):
    """Compute `(frame_size, block_entry_delta)` across *func*.

    Handles both single-step (`add sp, -K`) and two-step (`add sp, -K1` followed
    in the next block by `add3 sp, sp, -K2`) stack allocations so that all
    offsets normalize to a single canonical frame coordinate system `[0 .. frame_size)`.
    """
    entry_delta = {func.entry: 0}
    min_delta = 0
    for b in func.ordered():
        cur = entry_delta.get(b.start, min_delta)
        for s in b.stmts:
            d = _sp_adjust_delta(s)
            if d is not None:
                cur += d
                if cur < min_delta:
                    min_delta = cur
        for _, tgt in b.succ:
            if tgt in func.blocks and tgt not in entry_delta:
                entry_delta[tgt] = cur
    frame_size = -min_delta
    return frame_size, entry_delta


def _canon_off(raw_off, cur_delta, frame_size):
    if raw_off is None:
        return None
    signed_raw = (raw_off - 0x100000000) if raw_off >= 0x80000000 else raw_off
    return (cur_delta + frame_size) + signed_raw


def _saved_slots(func, frame_size, entry_delta):
    """Canonical offsets that hold a callee-saved register or `$lp` save/restore pair."""
    stores, loads = {}, {}
    lp_carriers = set()
    for b in func.ordered():
        cur_delta = entry_delta.get(b.start, -frame_size)
        is_ret_block = (b.term == "ret")
        for s in b.stmts:
            d = _sp_adjust_delta(s)
            if d is not None:
                cur_delta += d
                continue
            if not isinstance(s, ir.Assign):
                continue
            if (isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Reg)
                    and s.src.name == "lp"):
                lp_carriers.add(s.dst.name)
                continue
            if isinstance(s.dst, ir.Mem) and isinstance(s.src, ir.Reg):
                off = _canon_off(_sp_off(s.dst.addr), cur_delta, frame_size)
                if off is not None and 0 <= off < max(frame_size, 1):
                    if s.src.name in lp_carriers or s.src.name == "lp":
                        stores.setdefault(off, set()).add("lp")
                    elif s.src.name in CALLEE_SAVED:
                        stores.setdefault(off, set()).add(s.src.name)
            elif isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Mem):
                off = _canon_off(_sp_off(s.src.addr), cur_delta, frame_size)
                if off is not None and 0 <= off < max(frame_size, 1):
                    if s.dst.name in CALLEE_SAVED:
                        loads.setdefault(off, set()).add(s.dst.name)
                    if is_ret_block and s.dst.name in ("r11", "r1", "r0") and "lp" in stores.get(off, ()):
                        loads.setdefault(off, set()).add("lp")
    saved = {}
    for off, regs in stores.items():
        both = regs & loads.get(off, set())
        if both:
            saved[off] = both
    return saved



def rewrite(func):
    func.locals = {}
    func.stack_args = {}
    frame_size, entry_delta = _compute_sp_profile(func)
    saved = _saved_slots(func, frame_size, entry_delta)

    def slot_name(off, width):
        if frame_size > 0 and off >= frame_size:
            arg_off = off - frame_size
            name = "arg_%X" % arg_off if arg_off else "arg_0"
            func.stack_args[name] = max(func.stack_args.get(name, 1), width)
            return name
        if off < 0:
            off = off & 0xFFFFFFFF
        name = "var_%X" % off if off else "var_0"
        func.locals[name] = max(func.locals.get(name, 1), width)
        return name

    def make_xf(cur_delta):
        def xf(e):
            if isinstance(e, ir.Mem):
                off = _canon_off(_sp_off(e.addr), cur_delta, frame_size)
                if off is not None and off not in saved:
                    return ir.Reg(slot_name(off, e.width))
                addr = xf(e.addr) if isinstance(e.addr, ir.Expr) else e.addr
                return ir.Mem(addr, e.width, e.signed)
            if isinstance(e, ir.Bin):
                off = _canon_off(_sp_off(e), cur_delta, frame_size)
                if off is not None and off not in saved:
                    return ir.Un("&", ir.Reg(slot_name(off, 4)))
                return ir.Bin(e.op, xf(e.l), xf(e.r))
            if isinstance(e, ir.Un):
                return ir.Un(e.op, xf(e.e))
            if isinstance(e, ir.IntrExpr):
                return ir.IntrExpr(e.name, [xf(a) for a in e.args])
            return e
        return xf

    def drop(s, cur_delta, lp_carriers, is_ret_block):
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
        # link register save/restore move: rX = lp or lp = rX
        if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Reg):
            if s.src.name == "lp":
                lp_carriers.add(s.dst.name)
                return True
            if s.dst.name == "lp":
                return True
        # callee-saved / lp spill & restore
        if isinstance(s, ir.Assign):
            if isinstance(s.dst, ir.Mem) and isinstance(s.src, ir.Reg):
                off = _canon_off(_sp_off(s.dst.addr), cur_delta, frame_size)
                if off in saved and (s.src.name in saved[off]
                                     or (s.src.name in lp_carriers and "lp" in saved[off])):
                    return True
            if isinstance(s.dst, ir.Reg) and isinstance(s.src, ir.Mem):
                off = _canon_off(_sp_off(s.src.addr), cur_delta, frame_size)
                if off in saved and (s.dst.name in saved[off]
                                     or (is_ret_block and "lp" in saved[off]
                                         and s.dst.name in ("r11", "r1", "r0"))):
                    return True
        return False

    lp_carriers = set()
    for b in func.ordered():
        cur_delta = entry_delta.get(b.start, -frame_size)
        is_ret_block = (b.term == "ret")
        out = []
        for s in b.stmts:
            d = _sp_adjust_delta(s)
            if d is not None:
                cur_delta += d
            if drop(s, cur_delta, lp_carriers, is_ret_block):
                continue

            xf = make_xf(cur_delta)
            if isinstance(s, ir.Assign):
                s.src = xf(s.src)
                if isinstance(s.dst, ir.Mem):
                    off = _canon_off(_sp_off(s.dst.addr), cur_delta, frame_size)
                    if off is not None and off not in saved:
                        s.dst = ir.Reg(slot_name(off, s.dst.width))
                    else:
                        s.dst = ir.Mem(xf(s.dst.addr) if isinstance(s.dst.addr, ir.Expr) else s.dst.addr,
                                       s.dst.width, s.dst.signed)
            elif isinstance(s, ir.Branch):
                s.cexpr = xf(s.cexpr)
            elif isinstance(s, ir.Switch):
                s.expr = xf(s.expr)
            elif isinstance(s, ir.Intrinsic):
                s.args = [xf(a) for a in s.args]
            elif isinstance(s, ir.Call) and s.expr is not None:
                s.expr = xf(s.expr)
            out.append(s)
        b.stmts = out
    return func


class FrameInfo:
    def __init__(self, locals=None, stack_args=None, hidden_stmts=None, virtual_vars=None, user_renames=None, user_types=None):
        self.locals = locals or {}
        self.stack_args = stack_args or {}
        self.hidden_stmts = hidden_stmts or set()
        self.virtual_vars = virtual_vars or {}
        self.user_renames = user_renames or {}
        self.user_types = user_types or {}


def analyze_frame(func, ida_frame_info=None):
    """Analyze stack frame, rewrite stack accesses, and return FrameInfo."""
    rewrite(func)
    locals_dict = dict(getattr(func, "locals", {}) or {})
    stack_args = dict(getattr(func, "stack_args", {}) or {})

    # If IDA frame info is available, adopt IDA variable names and types
    if ida_frame_info:
        ida_members = getattr(ida_frame_info, "members", {}) or {}
        for off, (name, size, type_str) in ida_members.items():
            if not name or name in (" r", " s", "__return_address"):
                continue
            if off < 0:
                var_name = name or ("var_%X" % abs(off))
                if var_name in locals_dict or not var_name.startswith("var_"):
                    locals_dict[var_name] = max(locals_dict.get(var_name, 1), size)
            else:
                arg_name = name or ("arg_%X" % off)
                if arg_name in stack_args or not arg_name.startswith("arg_"):
                    stack_args[arg_name] = max(stack_args.get(arg_name, 1), size)

    return FrameInfo(locals=locals_dict, stack_args=stack_args)


def local_decls(func):
    """Lines declaring the recovered stack locals, widest first for stability."""
    locs = getattr(func, "locals", None)
    if not locs:
        return []
    ctype = {1: "char", 2: "short", 4: "int"}
    out = []
    for name in sorted(locs, key=lambda n: int(n.split("_")[1], 16) if "_" in n and n.split("_")[1].isalnum() else 0):
        out.append("    %s %s;" % (ctype.get(locs[name], "int"), name))
    return out


