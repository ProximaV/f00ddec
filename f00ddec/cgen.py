"""
Pseudo-C back-end for the MeP/F00D decompiler.

Registers print as themselves or virtual variables (v0, v1, a0, ...); memory reads
as ``mem8/mem16/mem32`` (``s8``/``s16`` for sign-extending loads) indexed by an
address expression or symbolic name; conditional branches use the relational expression
the lifter recovered. Out-of-function tail jumps render as ``JUMPOUT(addr)``.
"""

from . import ir
from . import structure as S


_PRECEDENCE = {
    "*": 10, "/": 10, "%": 10,
    "+": 9, "-": 9,
    "<<": 8, ">>": 8,
    "<": 7, "<=": 7, ">": 7, ">=": 7,
    "==": 6, "!=": 6,
    "&": 5,
    "^": 4,
    "|": 3,
    "&&": 2,
    "||": 1,
}


class CodeLines(list):
    """List of generated C lines carrying a parallel line_eas mapping."""
    pass


class _Emit:
    def __init__(self, namer, block_starts=frozenset(), returns_value=False, hidden=frozenset(), user_renames=None, user_types=None):
        self.namer = namer
        self.block_starts = block_starts
        self.returns_value = returns_value
        self.hidden = hidden
        self.user_renames = user_renames or {}
        self.user_types = user_types or {}
        self.used_labels = set()
        self._pending = []

    def expr(self, e, top=True):
        if isinstance(e, ir.Const):
            if getattr(e, "name", None):
                return self.user_renames.get(e.name, e.name)
            v = e.value
            return str(v) if v < 10 else "0x%X" % v
        if isinstance(e, (ir.Reg, ir.Var)):
            return self.user_renames.get(e.name, e.name)
        if isinstance(e, ir.Mem):
            return self._mem(e)
        if isinstance(e, ir.Bin):
            op, r = e.op, e.r
            # render "+ 0xFFFFFFFF" (add #-1) etc. as a subtraction
            if op == "+" and isinstance(r, ir.Const) and r.value >= 0x80000000:
                op, r = "-", ir.Const((0x100000000 - r.value))
            rs = self.expr(r, False)
            s = "%s %s %s" % (self.expr(e.l, False), op, rs)
            return s if top else "(%s)" % s
        if isinstance(e, ir.Un):
            return "%s%s" % (e.op, self.expr(e.e, False))
        if isinstance(e, ir.IntrExpr):
            return "%s(%s)" % (e.name, ", ".join(self.expr(a) for a in e.args)) if e.args else e.name
        return "?"

    def _mem(self, e):
        if getattr(e, "name", None):
            return self.user_renames.get(e.name, e.name)
        pre = {1: "s8" if e.signed else "mem8", 2: "s16" if e.signed else "mem16",
               4: "mem32"}.get(e.width, "mem32")
        if isinstance(e.addr, ir.Expr):
            return "%s[%s]" % (pre, self.expr(e.addr))
        return "%s[0x%X]" % (pre, e.addr)

    def stmt(self, s):
        if isinstance(s, ir.Assign):
            return "%s = %s;" % (self.expr(s.dst), self.expr(s.src))
        if isinstance(s, ir.Call):
            args = ", ".join(self.expr(a) for a in (s.args or []))
            if s.target is not None:
                tgt_name = self.namer.code(s.target)
                tgt_name = self.user_renames.get(tgt_name, tgt_name)
                call_str = "%s(%s)" % (tgt_name, args)
            else:
                call_str = "(*%s)(%s)" % (self.expr(s.expr), args)
            if getattr(s, "is_tail", False):
                if self.returns_value:
                    return "return %s;" % call_str
                else:
                    return "%s;" % call_str
            return "%s;" % call_str
        if isinstance(s, ir.Intrinsic):
            call = "%s(%s);" % (s.name, ", ".join(self.expr(a) for a in s.args))
            return call + ("   /* %s */" % s.note if s.note else "")
        return "/* %s */" % type(s).__name__

    def _ext(self, ea):
        return self.namer.code(ea) if ea is not None else "?"

    def emit(self, nodes, ind):
        pad = "    " * ind
        for n in nodes:
            if isinstance(n, S.SLabel):
                self._pending.append((ind, None, n.ea, n.ea))
            elif isinstance(n, S.SStmt):
                ea = getattr(n.stmt, "ea", None)
                self._pending.append((ind, pad + self.stmt(n.stmt), None, ea))
            elif isinstance(n, S.SRet):
                if self._pending and self._pending[-1][1] and self._pending[-1][1].strip().startswith("return "):
                    continue
                self._pending.append((ind, pad + ("return r0;" if self.returns_value else "return;"), None, None))
            elif isinstance(n, S.SGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    self._pending.append((ind, pad + "goto %s;" % self.namer.label(n.ea), None, n.ea))
                else:
                    self._pending.append((ind, pad + "JUMPOUT(%s);" % self._ext(n.ea), None, n.ea))
            elif isinstance(n, S.SIfGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    tail = "goto %s;" % self.namer.label(n.ea)
                else:
                    tail = "JUMPOUT(%s);" % self._ext(n.ea)
                self._pending.append((ind, pad + "if (%s) %s" % (self.expr(n.cond), tail), None, n.ea))
            elif isinstance(n, S.SBreak):
                self._pending.append((ind, pad + "break;", None, None))
            elif isinstance(n, S.SBreakIf):
                self._pending.append((ind, pad + "if (%s) break;" % self.expr(n.cond), None, None))
            elif isinstance(n, S.SContinue):
                if n.cond is None:
                    self._pending.append((ind, pad + "continue;", None, None))
                else:
                    self._pending.append((ind, pad + "if (%s) continue;" % self.expr(n.cond), None, None))
            elif isinstance(n, S.SIf):
                self._pending.append((ind, pad + "if (%s) {" % self.expr(n.cond), None, None))
                self.emit(n.then, ind + 1)
                if n.els:
                    self._pending.append((ind, pad + "} else {", None, None))
                    self.emit(n.els, ind + 1)
                self._pending.append((ind, pad + "}", None, None))
            elif isinstance(n, S.SWhile):
                self._emit_while(n, ind)
            elif isinstance(n, S.SSwitch):
                self._emit_switch(n, ind)

    def _emit_switch(self, n, ind):
        pad = "    " * ind
        self._pending.append((ind, pad + "switch (%s) {" % self.expr(n.expr), None, None))
        for vals, arm in n.cases:
            for v in vals:
                v_str = str(v) if v < 10 else "0x%X" % v
                self._pending.append((ind, pad + "case %s:" % v_str, None, None))
            self.emit(arm, ind + 1)
        if n.default_body:
            self._pending.append((ind, pad + "default:", None, None))
            self.emit(n.default_body, ind + 1)
        self._pending.append((ind, pad + "}", None, None))

    def _emit_while(self, n, ind):
        pad = "    " * ind
        body = list(n.body)
        tail = None
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is not None:
            tail = body[-1].cond
            body = body[:-1]
        if tail is not None:
            self._pending.append((ind, pad + "do {", None, None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "} while (%s);" % self.expr(tail), None, None))
            return
        # Drop redundant unconditional `continue;` at the end of a while loop
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is None:
            body = body[:-1]
        # Check if the first statement after the loop header label is `if (cond) break;`
        first_idx = None
        for idx, item in enumerate(body):
            if not isinstance(item, S.SLabel):
                first_idx = idx
                break
        if first_idx is not None and isinstance(body[first_idx], S.SBreakIf):
            wcond = S.negate(body[first_idx].cond)
            body = body[:first_idx] + body[first_idx + 1:]
            self._pending.append((ind, pad + "while (%s) {" % self.expr(wcond), None, None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", None, None))
        else:
            self._pending.append((ind, pad + "while (1) {", None, None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", None, None))

    def flush(self):
        out = []
        line_eas = []
        for ind, text, label_ea, ea in self._pending:
            if label_ea is not None:
                if label_ea in self.used_labels:
                    out.append("%s:" % self.namer.label(label_ea))
                    line_eas.append(label_ea)
                continue
            out.append(text)
            line_eas.append(ea)
        return out, line_eas


def generate(func, tree, namer, frame_info=None, sig=None, banner=None, user_renames=None, user_types=None):
    hidden = getattr(frame_info, "hidden_stmts", frozenset()) if frame_info else frozenset()
    u_renames = dict(getattr(frame_info, "user_renames", {}) or {})
    if user_renames:
        u_renames.update(user_renames)
    u_types = dict(getattr(frame_info, "user_types", {}) or {})
    if user_types:
        u_types.update(user_types)

    returns_value = (sig.ret_type != "void") if sig else False
    em = _Emit(namer, block_starts=frozenset(func.blocks), returns_value=returns_value,
               hidden=hidden, user_renames=u_renames, user_types=u_types)
    em.emit(tree, 1)
    body, body_eas = em.flush()

    out = CodeLines()
    if banner:
        out.extend(banner)

    fn_name = namer.code(func.entry)
    fn_name = u_renames.get(fn_name, fn_name)

    if sig is not None:
        ret_t = u_types.get("__return__", sig.ret_type)
        if sig.params:
            param_parts = []
            for p in sig.params:
                p_name = u_renames.get(p.name, p.name)
                p_type = u_types.get(p.name, u_types.get(p_name, p.type_str))
                sep = "" if p_type.endswith("*") else " "
                param_parts.append(f"{p_type}{sep}{p_name}")
            pstr = ", ".join(param_parts)
        else:
            pstr = "void"
        ret_sep = "" if ret_t.endswith("*") else " "
        out.append(f"{ret_t}{ret_sep}{fn_name}({pstr})")
    else:
        out.append(f"void {fn_name}(void)")

    out.append("{")
    decls = []

    # Stack variable declarations
    if frame_info and frame_info.locals:
        def sort_loc(kv):
            name = kv[0]
            if "_" in name and name.split("_")[1].isalnum():
                try:
                    return (0, int(name.split("_")[1], 16))
                except ValueError:
                    pass
            return (1, name)

        for name, size in sorted(frame_info.locals.items(), key=sort_loc):
            eff_name = u_renames.get(name, name)
            default_t = {1: "char", 2: "short", 4: "int"}.get(size, "int")
            tstr = u_types.get(name, u_types.get(eff_name, default_t))
            sep = "" if tstr.endswith("*") else " "
            decls.append(f"    {tstr}{sep}{eff_name};")

    # Virtual variable declarations
    if frame_info and getattr(frame_info, "virtual_vars", None):
        def sort_vvar(kv):
            name = kv[0]
            if name.startswith("v") and name[1:].isdigit():
                return (0, int(name[1:]))
            return (1, name)

        for name, (var, width) in sorted(frame_info.virtual_vars.items(), key=sort_vvar):
            if frame_info.locals and name in frame_info.locals:
                continue
            eff_name = u_renames.get(name, name)
            default_t = "int"
            tstr = u_types.get(name, u_types.get(eff_name, default_t))
            sep = "" if tstr.endswith("*") else " "
            decls.append(f"    {tstr}{sep}{eff_name};")

    if decls:
        out.extend(decls)
        if body:
            out.append("")

    header_count = len(out)
    out.extend(body)
    out.append("}")
    out.line_eas = [None] * header_count + body_eas + [None]
    return out
