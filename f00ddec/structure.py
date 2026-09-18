"""
Control-flow structuring (shared design with startrekdec/rl78dec).

Recovers if / while / do-while with a correct goto+label fallback.  MeP branches
carry their own condition expression, so ``cond_expr`` just returns it.
"""

from . import ir


class SStmt:
    def __init__(self, stmt): self.stmt = stmt
class SLabel:
    def __init__(self, ea): self.ea = ea
class SGoto:
    def __init__(self, ea): self.ea = ea
class SRet:
    pass
class SIf:
    def __init__(self, cond, then, els): self.cond = cond; self.then = then; self.els = els
class SIfGoto:
    def __init__(self, cond, ea): self.cond = cond; self.ea = ea
class SWhile:
    def __init__(self, body, cond=None, dowhile=False):
        self.body = body; self.cond = cond; self.dowhile = dowhile
class SBreak:
    pass
class SContinue:
    def __init__(self, cond=None): self.cond = cond
class SBreakIf:
    def __init__(self, cond): self.cond = cond


_NEG = {"==": "!=", "!=": "==", ">": "<=", "<": ">=", ">=": "<", "<=": ">"}


def cond_expr(branch):
    return branch.cexpr


def negate(e):
    if isinstance(e, ir.Un) and e.op == "!":
        return e.e
    if isinstance(e, ir.Bin) and e.op in _NEG:
        return ir.Bin(_NEG[e.op], e.l, e.r)
    if isinstance(e, ir.Const):
        return ir.Const(0 if e.value else 1)
    return ir.Un("!", e)


class _Structurer:
    def __init__(self, func):
        self.order = func.ordered()
        self.idx = {b.start: i for i, b in enumerate(self.order)}
        self.blocks = self.order
        self._open = set()

    def run(self):
        return self._emit(0, len(self.blocks), loop=None)

    def _in_range(self, ea, lo, hi):
        i = self.idx.get(ea)
        return i is not None and lo <= i < hi

    def _find_latch(self, header_idx, hi):
        h = self.blocks[header_idx].start
        latch = None
        for j in range(header_idx, hi):
            for _, tgt in self.blocks[j].succ:
                if tgt == h and j >= header_idx:
                    latch = j
        return latch

    def _body_stmts(self, block):
        out = []
        for s in block.stmts:
            if isinstance(s, (ir.Goto, ir.Branch, ir.Ret, ir.Nop)):
                continue
            out.append(SStmt(s))
        return out

    def _branch_of(self, block):
        for s in block.stmts:
            if isinstance(s, ir.Branch):
                return s
        return None

    def _emit(self, lo, hi, loop):
        out = []
        i = lo
        while i < hi:
            b = self.blocks[i]
            out.append(SLabel(b.start))
            latch = None if i in self._open else self._find_latch(i, hi)
            if latch is not None:
                node, nxt = self._emit_loop(i, latch, hi)
                out.append(node)
                i = nxt
                continue
            out.extend(self._body_stmts(b))
            term = b.term
            if term == "ret":
                out.append(SRet()); i += 1; continue
            if term == "goto":
                self._emit_edge(out, b.succ[0][1], lo, hi, loop, i + 1); i += 1; continue
            if term == "branch":
                cond = cond_expr(self._branch_of(b))
                taken = b.succ[0][1]
                fall = b.succ[1][1] if len(b.succ) > 1 else None
                if loop is not None and taken in (loop[0], loop[1]):
                    out.append(SContinue(cond) if taken == loop[0] else SBreakIf(cond))
                    self._fall_after(out, fall, loop, i); i += 1; continue
                ti = self.idx.get(taken)
                if ti is not None and i + 1 <= ti < hi and taken != b.start \
                        and (loop is None or taken not in (loop[0], loop[1])):
                    then = self._emit(i + 1, ti, loop)
                    out.append(SIf(negate(cond), then, None))
                    i = ti; continue
                out.append(SIfGoto(cond, taken))
                self._fall_after(out, fall, loop, i); i += 1; continue
            if b.succ:
                tgt = b.succ[0][1]
                if self.idx.get(tgt) != i + 1:
                    self._emit_edge(out, tgt, lo, hi, loop, i + 1)
            i += 1
        return out

    def _emit_loop(self, hidx, latch, hi):
        loop_lo, loop_hi = hidx, latch + 1
        header = self.blocks[hidx].start
        follow_ea = None
        for k, tgt in self.blocks[latch].succ:
            if not self._in_range(tgt, loop_lo, loop_hi):
                follow_ea = tgt
                break
        self._open.add(hidx)
        body = self._emit(loop_lo, loop_hi, (header, follow_ea))
        self._open.discard(hidx)
        nxt = latch + 1
        if follow_ea is not None and self.idx.get(follow_ea) is not None:
            nxt = self.idx[follow_ea]
        return SWhile(body), nxt

    def _fall_after(self, out, fall, loop, i):
        if fall is None or self.idx.get(fall) == i + 1:
            return
        if loop is not None:
            if fall == loop[0]:
                out.append(SContinue()); return
            if fall == loop[1]:
                out.append(SBreak()); return
        out.append(SGoto(fall))

    def _emit_edge(self, out, tgt, lo, hi, loop, fall_i):
        if loop is not None:
            if tgt == loop[0]:
                out.append(SContinue()); return
            if tgt == loop[1]:
                out.append(SBreak()); return
        if self.idx.get(tgt) == fall_i:
            return
        out.append(SGoto(tgt))


def structure(func):
    return _Structurer(func).run()
