"""
Pseudo-C back-end for the MeP/F00D decompiler.

Registers print as themselves (r0..r12/tp/gp/sp and control regs); memory reads
as ``mem8/mem16/mem32`` (``s8``/``s16`` for sign-extending loads) indexed by an
address expression; conditional branches use the relational expression the lifter
recovered.  Out-of-function tail jumps render as ``JUMPOUT(addr)``.
"""

from . import ir
from . import structure as S
from . import recover
from . import frame


class _Emit:
    def __init__(self, namer, block_starts=frozenset(), returns_value=False):
        self.namer = namer
        self.block_starts = block_starts
        self.returns_value = returns_value
        self.used_labels = set()
        self._pending = []

    def expr(self, e, top=True):
        if isinstance(e, ir.Const):
            v = e.value
            return str(v) if v < 10 else "0x%X" % v
        if isinstance(e, ir.Reg):
            return e.name
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
                return "%s(%s);" % (self.namer.code(s.target), args)
            return "(*%s)(%s);" % (self.expr(s.expr), args)
        if isinstance(s, ir.Intrinsic):
            call = "%s(%s);" % (s.name, ", ".join(self.expr(a) for a in s.args))
            return call + ("   /* %s */" % s.note if s.note else "")
        return "/* %s */" % type(s).__name__

    def _ext(self, ea):
        return self.namer.code_names.get(ea) or "0x%X" % ea

    def emit(self, nodes, ind):
        pad = "    " * ind
        for n in nodes:
            if isinstance(n, S.SLabel):
                self._pending.append((ind, None, n.ea))
            elif isinstance(n, S.SStmt):
                self._pending.append((ind, pad + self.stmt(n.stmt), None))
            elif isinstance(n, S.SRet):
                self._pending.append((ind, pad + ("return r0;" if self.returns_value else "return;"), None))
            elif isinstance(n, S.SGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    self._pending.append((ind, pad + "goto %s;" % self.namer.label(n.ea), None))
                else:
                    self._pending.append((ind, pad + "JUMPOUT(%s);" % self._ext(n.ea), None))
            elif isinstance(n, S.SIfGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    tail = "goto %s;" % self.namer.label(n.ea)
                else:
                    tail = "JUMPOUT(%s);" % self._ext(n.ea)
                self._pending.append((ind, pad + "if (%s) %s" % (self.expr(n.cond), tail), None))
            elif isinstance(n, S.SBreak):
                self._pending.append((ind, pad + "break;", None))
            elif isinstance(n, S.SBreakIf):
                self._pending.append((ind, pad + "if (%s) break;" % self.expr(n.cond), None))
            elif isinstance(n, S.SContinue):
                if n.cond is None:
                    self._pending.append((ind, pad + "continue;", None))
                else:
                    self._pending.append((ind, pad + "if (%s) continue;" % self.expr(n.cond), None))
            elif isinstance(n, S.SIf):
                self._pending.append((ind, pad + "if (%s) {" % self.expr(n.cond), None))
                self.emit(n.then, ind + 1)
                if n.els:
                    self._pending.append((ind, pad + "} else {", None))
                    self.emit(n.els, ind + 1)
                self._pending.append((ind, pad + "}", None))
            elif isinstance(n, S.SWhile):
                self._emit_while(n, ind)

    def _emit_while(self, n, ind):
        pad = "    " * ind
        body = list(n.body)
        tail = None
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is not None:
            tail = body[-1].cond
            body = body[:-1]
        if tail is not None:
            self._pending.append((ind, pad + "do {", None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "} while (%s);" % self.expr(tail), None))
        else:
            self._pending.append((ind, pad + "while (1) {", None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", None))

    def flush(self):
        out = []
        for ind, text, label_ea in self._pending:
            if label_ea is not None:
                if label_ea in self.used_labels:
                    out.append("%s:" % self.namer.label(label_ea))
                continue
            out.append(text)
        return out


def generate(func, tree, namer, banner=None):
    sig, _params, returns_value = recover.signature(func, namer.code(func.entry))
    em = _Emit(namer, block_starts=frozenset(func.blocks), returns_value=returns_value)
    em.emit(tree, 1)
    body = em.flush()
    out = list(banner) if banner else []
    out.append(sig)
    out.append("{")
    decls = frame.local_decls(func)
    if decls:
        out.extend(decls)
        out.append("")
    out.extend(body)
    out.append("}")
    return out
