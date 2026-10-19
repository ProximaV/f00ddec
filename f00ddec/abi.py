"""
Calling convention analysis and function signature recovery for Toshiba MeP (PS Vita F00D).

MeP calling conventions:
1. First 4 arguments passed in 32-bit general registers:
   r1 (first), r2 (second), r3 (third), r4 (fourth).
2. Additional arguments (5th+) passed on the stack at entry SP (sp0 + 0, sp0 + 4, ...).
3. Return values returned in r0 (32-bit integer or pointer).
4. Volatile (caller-saved) registers: r0, r1, r2, r3, r4, lp (clobbered across calls).
5. Non-volatile (callee-saved) registers: r5..r12, tp, gp, sp.

This module:
1. Reconstructs function signatures (parameters and return types) using backward liveness analysis.
2. Identifies live-in argument registers (r1..r4) and stack arguments (arg_0, arg_4, ...).
3. Recovers call-site arguments and return value assignments.
4. Supports overriding with user-defined prototypes.
"""

from . import ir

ARG_REGS = ("r1", "r2", "r3", "r4")
CALLER_SAVED = frozenset(("r0", "r1", "r2", "r3", "r4", "lp"))
CALLEE_SAVED = frozenset(("r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "tp", "gp", "sp"))


class Param:
    __slots__ = ("name", "type_str", "location")

    def __init__(self, name, type_str="int", location="r1"):
        self.name = name
        self.type_str = type_str
        self.location = location

    def __repr__(self):
        return f"{self.type_str} {self.name}"


class FunctionSig:
    def __init__(self, name=None, ret_type="void", ret_expr=None, params=None):
        self.name = name
        self.ret_type = ret_type
        self.ret_expr = ret_expr
        self.params = list(params) if params else []

    def format_signature(self, func_name=None):
        name = func_name or self.name or "sub_unknown"
        if self.params:
            pstr = ", ".join(f"{p.type_str} {p.name}" for p in self.params)
        else:
            pstr = "void"
        return f"{self.ret_type} {name}({pstr})"


def _collect_expr_regs(e, out_regs):
    if isinstance(e, ir.Reg):
        out_regs.add(e.name)
    elif isinstance(e, ir.Bin):
        _collect_expr_regs(e.l, out_regs)
        _collect_expr_regs(e.r, out_regs)
    elif isinstance(e, ir.Un):
        _collect_expr_regs(e.e, out_regs)
    elif isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
        _collect_expr_regs(e.addr, out_regs)
    elif isinstance(e, ir.IntrExpr):
        for a in e.args:
            _collect_expr_regs(a, out_regs)


def compute_liveness(func, hidden_stmts=frozenset()):
    """Compute entry live-in registers via standard backwards dataflow analysis."""
    block_gen = {}
    block_kill = {}

    for b in func.blocks.values():
        gen = set()
        kill = set()

        for s in b.stmts:
            if id(s) in hidden_stmts:
                continue

            used = set()
            if isinstance(s, ir.Assign):
                _collect_expr_regs(s.src, used)
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Expr):
                    _collect_expr_regs(s.dst.addr, used)
            elif isinstance(s, ir.Call):
                if s.args:
                    for a in s.args:
                        _collect_expr_regs(a, used)
                if s.expr:
                    _collect_expr_regs(s.expr, used)
            elif isinstance(s, ir.Branch):
                if isinstance(s.cexpr, ir.Expr):
                    _collect_expr_regs(s.cexpr, used)
            elif isinstance(s, ir.Switch) and isinstance(s.expr, ir.Expr):
                _collect_expr_regs(s.expr, used)
            elif isinstance(s, ir.Intrinsic):
                for a in s.args:
                    _collect_expr_regs(a, used)

            # Upward-exposed uses (gen)
            for u in used:
                if u not in kill:
                    gen.add(u)

            # Definitions / clobbers in this statement
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
                kill.add(s.dst.name)
            elif isinstance(s, ir.Call):
                if not getattr(s, "is_tail", False):
                    for r in CALLER_SAVED:
                        kill.add(r)

        block_gen[b.start] = gen
        block_kill[b.start] = kill

    live_in = {b_ea: set() for b_ea in func.blocks}
    changed = True
    ordered = func.ordered()
    while changed:
        changed = False
        for b in reversed(ordered):
            out = set()
            for _, succ_ea in b.succ:
                if succ_ea in live_in:
                    out.update(live_in[succ_ea])
            new_in = block_gen[b.start] | (out - block_kill[b.start])
            if new_in != live_in[b.start]:
                live_in[b.start] = new_in
                changed = True

    return live_in.get(func.entry, set())


def _infer_return_type(func, hidden_stmts=frozenset(), ret_types=None):
    """Determine if func returns a value in r0 via global reaching definitions."""
    ret_types = ret_types or {}
    ret_blocks = [b for b in func.blocks.values() if b.stmts and isinstance(b.stmts[-1], ir.Ret)]
    if not ret_blocks:
        return "void", None

    preds = {b_ea: [] for b_ea in func.blocks}
    for b in func.blocks.values():
        for _, succ_ea in b.succ:
            if succ_ea in preds:
                preds[succ_ea].append(b.start)

    # Reaching definitions for r0
    out_defs = {}
    ordered = func.ordered()
    changed = True
    iterations = 0
    while changed and iterations < 20:
        changed = False
        iterations += 1
        for b in ordered:
            cur = set()
            for p_ea in preds[b.start]:
                cur.update(out_defs.get(p_ea, set()))

            if b.start == func.entry:
                cur.add(("entry", "r0"))

            for s in b.stmts:
                if id(s) in hidden_stmts:
                    continue
                if isinstance(s, ir.Assign):
                    if (isinstance(s.dst, ir.Reg) and s.dst.name == "r0") or (isinstance(s.dst, ir.Var) and s.dst.name == "r0"):
                        cur = {(id(s), s)}
                elif isinstance(s, ir.Call):
                    if getattr(s, "is_tail", False) and ret_types.get(s.target) != "void":
                        cur = {(id(s), s)}
                    else:
                        cur = {("clobber", id(s))}

            if cur != out_defs.get(b.start, set()):
                out_defs[b.start] = cur
                changed = True

    # Now verify all return instructions receive valid r0 definitions
    all_defs = set()
    for rb in ret_blocks:
        cur = set()
        for p_ea in preds[rb.start]:
            cur.update(out_defs.get(p_ea, set()))
        if rb.start == func.entry:
            cur.add(("entry", "r0"))

        for s in rb.stmts[:-1]:
            if id(s) in hidden_stmts:
                continue
            if isinstance(s, ir.Assign):
                if (isinstance(s.dst, ir.Reg) and s.dst.name == "r0") or (isinstance(s.dst, ir.Var) and s.dst.name == "r0"):
                    cur = {(id(s), s)}
            elif isinstance(s, ir.Call):
                if getattr(s, "is_tail", False) and ret_types.get(s.target) != "void":
                    cur = {(id(s), s)}
                else:
                    cur = {("clobber", id(s))}

        if not cur or any(d[0] in ("entry", "clobber") for d in cur):
            return "void", None
        all_defs.update(cur)

    if not all_defs:
        return "void", None

    r0_is_pointer = False
    for item in all_defs:
        if len(item) == 2:
            s = item[1]
            if isinstance(s, ir.Assign):
                if isinstance(s.src, ir.Mem) or (isinstance(s.src, ir.Const) and s.src.value >= 0x800000):
                    r0_is_pointer = True
                    break
            elif isinstance(s, ir.Call) and getattr(s, "is_tail", False):
                if ret_types.get(s.target) == "int *":
                    r0_is_pointer = True
                    break

    return ("int *" if r0_is_pointer else "int"), ir.Reg("r0")


def analyze_calling_convention(func, frame_info=None, user_proto=None, func_name=None, ret_types=None):
    """Recover function signature (parameters, return type) for func."""
    hidden = getattr(frame_info, "hidden_stmts", frozenset()) or frozenset()
    name = func_name or ("sub_%X" % func.entry)

    # 1. Parse user prototype override if present
    if user_proto:
        sig = _parse_proto(user_proto, name)
        if sig:
            return sig

    # 2. Compute live-in argument registers
    live_in = compute_liveness(func, hidden)

    # In C calling convention, find highest argument register index
    max_arg_idx = -1
    for idx, reg in enumerate(ARG_REGS):
        if reg in live_in:
            max_arg_idx = max(max_arg_idx, idx)

    # Check pointer usage for parameter typing
    ptr_params = set()
    for b in func.blocks.values():
        for s in b.stmts:
            if id(s) in hidden:
                continue
            if isinstance(s, ir.Assign):
                if isinstance(s.src, ir.Mem) and isinstance(s.src.addr, ir.Reg):
                    ptr_params.add(s.src.addr.name)
                if isinstance(s.dst, ir.Mem) and isinstance(s.dst.addr, ir.Reg):
                    ptr_params.add(s.dst.addr.name)

    params = []
    if max_arg_idx >= 0:
        for idx in range(max_arg_idx + 1):
            rname = ARG_REGS[idx]
            ptype = "int *" if rname in ptr_params else "int"
            params.append(Param(name=f"a{idx}", type_str=ptype, location=rname))

    # Check for stack-passed arguments (arg_0, arg_4, etc.)
    if frame_info and getattr(frame_info, "stack_args", None):
        for sname, s_offset in sorted(frame_info.stack_args.items(), key=lambda kv: kv[1]):
            ptype = "int *" if sname in ptr_params else "int"
            params.append(Param(name=sname, type_str=ptype, location=f"sp+{s_offset}"))

    # 3. Infer return type
    ret_type, ret_expr = _infer_return_type(func, hidden, ret_types=ret_types)

    return FunctionSig(name=name, ret_type=ret_type, ret_expr=ret_expr, params=params)


def _parse_proto(proto_str, default_name):
    """Parse a simple C function prototype string: 'int foo(int a, void *b)'."""
    try:
        clean = proto_str.strip().rstrip(";")
        if "(" not in clean or ")" not in clean:
            return None
        head, args_part = clean.split("(", 1)
        args_part = args_part.rsplit(")", 1)[0].strip()

        head_tokens = head.strip().split()
        if not head_tokens:
            return None
        fn_name = head_tokens[-1]
        ret_type = " ".join(head_tokens[:-1]) if len(head_tokens) > 1 else "void"

        params = []
        if args_part and args_part != "void":
            for idx, arg_str in enumerate(args_part.split(",")):
                arg_tokens = arg_str.strip().split()
                if not arg_tokens:
                    continue
                if len(arg_tokens) == 1:
                    raw = arg_tokens[0]
                    stars = raw.count("*")
                    pname = raw.replace("*", "") or f"a{idx}"
                    ptype = "int" + (" *" if stars else "")
                else:
                    raw_name = arg_tokens[-1]
                    stars = raw_name.count("*")
                    pname = raw_name.replace("*", "") or f"a{idx}"
                    base_type = " ".join(arg_tokens[:-1])
                    ptype = (base_type + " *") if stars else base_type
                loc = ARG_REGS[idx] if idx < len(ARG_REGS) else f"arg_{idx}"
                params.append(Param(name=pname, type_str=ptype, location=loc))

        ret_expr = ir.Reg("r0") if ret_type != "void" else None
        return FunctionSig(name=fn_name or default_name, ret_type=ret_type, ret_expr=ret_expr, params=params)
    except Exception:
        return None
