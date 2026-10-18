"""
Call-argument folding: show how parameters are passed at each call site.

The MeP convention puts the first four integer arguments in ``r1``-``r4``
(further ones on the stack).  A compiler loads ``r1``, ``r2`` ... immediately
before the call, so this pass tracks the current value of each argument register
within a basic block and, at a ``Call``, attaches the contiguous ``r1``.. values
as the call's arguments and drops the now-folded ``rN = ...`` set-up statements.

    r1 = 1; r2 = 0x20; r3 = 0; foo();   -->   foo(1, 0x20, 0);

When the callee is one of our own functions its recovered parameter count caps
the list; for library calls (unknown arity) the contiguous run of argument
registers set since the previous call is used.  Stack-passed arguments (5+) are
not recovered.
"""

from . import ir

ARGS = ("r1", "r2", "r3", "r4")


def rewrite(func, arity=None):
    arity = arity or {}
    for b in func.blocks.values():
        argexpr = {}        # reg name -> current value expr
        argstmt = {}        # reg name -> the Assign that set it (to drop if folded)
        out = []
        for s in b.stmts:
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name in ARGS:
                argexpr[s.dst.name] = s.src
                argstmt[s.dst.name] = s
                out.append(s)
                continue
            if isinstance(s, ir.Call):
                run = []
                for a in ARGS:
                    if a in argexpr:
                        run.append(a)
                    else:
                        break
                n = arity.get(s.target)
                if n:
                    run = run[:n]
                s.args = [argexpr[a] for a in run]
                for a in run:
                    st = argstmt.get(a)
                    if st in out:
                        out.remove(st)
                argexpr.clear()
                argstmt.clear()
                out.append(s)
                continue
            out.append(s)
        b.stmts = out
    return func
