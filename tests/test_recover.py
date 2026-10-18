"""
Headless tests for the MeP analysis passes: stack-frame cleanup, parameter /
return-value recovery and call-argument folding.  Hand-built IR, no decoder, no
ROM.

    python tests/test_recover.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f00ddec import cfg, ir, frame, recover, callargs      # noqa: E402


def _func(entry, stmts, term="ret", succ=None):
    f = cfg.Func(entry)
    b = cfg.Block(entry)
    b.stmts = list(stmts)
    b.term = term
    b.succ = succ or []
    f.blocks[entry] = b
    return f


def test_params_and_return():
    # r0 = r1 + r2 ; ret  -> int sub(int r1, int r2), returns a value in r0
    f = _func(0x100, [
        ir.Assign(0x100, ir.Reg("r0"), ir.Bin("+", ir.Reg("r1"), ir.Reg("r2"))),
        ir.Ret(0x104),
    ])
    assert recover.params(f) == ["r1", "r2"], recover.params(f)
    assert recover.returns_value(f) is True
    sig, ps, rv = recover.signature(f, "sub_100")
    assert sig == "int sub_100(int r1, int r2)", sig
    assert rv is True
    print("ok  test_params_and_return")


def test_void_leaf():
    # mem8[0x40] = r1 ; ret  -> r1 written? no: r1 is read (source) before any
    # write, so it is a parameter; nothing lands in r0, so return is void.
    f = _func(0x200, [
        ir.Assign(0x200, ir.Mem(0x40, 1), ir.Reg("r1")),
        ir.Ret(0x204),
    ])
    sig, ps, rv = recover.signature(f, "sub_200")
    assert sig == "void sub_200(int r1)", sig
    assert rv is False
    print("ok  test_void_leaf")


def test_pointer_param():
    # r0 = mem32[r1]  -> r1 is dereferenced, so it is typed as a pointer.
    f = _func(0x300, [
        ir.Assign(0x300, ir.Reg("r0"), ir.Mem(ir.Reg("r1"), 4)),
        ir.Ret(0x304),
    ])
    sig, ps, rv = recover.signature(f, "sub_300")
    assert sig == "int sub_300(int *r1)", sig
    print("ok  test_pointer_param")


def test_frame_cleanup():
    # add sp,#-8   (sp = sp + 0xFFFFFFF8)
    # mem32[sp+4] = r8           ; callee-saved spill
    # mem32[sp]   = r1           ; store to local var_0
    # r0 = mem32[sp]             ; load local var_0
    # r8 = mem32[sp+4]           ; callee-saved restore
    # add sp,#8    (sp = sp + 8)
    # ret
    def slot(off):
        return ir.Reg("sp") if off == 0 else ir.Bin("+", ir.Reg("sp"), ir.Const(off))
    f = _func(0x400, [
        ir.Assign(0x400, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(0xFFFFFFF8))),
        ir.Assign(0x404, ir.Mem(slot(4), 4), ir.Reg("r8")),
        ir.Assign(0x408, ir.Mem(slot(0), 4), ir.Reg("r1")),
        ir.Assign(0x40C, ir.Reg("r0"), ir.Mem(slot(0), 4)),
        ir.Assign(0x410, ir.Reg("r8"), ir.Mem(slot(4), 4)),
        ir.Assign(0x414, ir.Reg("sp"), ir.Bin("+", ir.Reg("sp"), ir.Const(8))),
        ir.Ret(0x418),
    ])
    frame.rewrite(f)
    stmts = f.blocks[0x400].stmts
    # prologue/epilogue + spill gone: only the two local accesses and the ret.
    assert len(stmts) == 3, [type(s).__name__ for s in stmts]
    a0, a1, _ret = stmts
    assert isinstance(a0.dst, ir.Reg) and a0.dst.name == "var_0", a0.dst
    assert isinstance(a1.src, ir.Reg) and a1.src.name == "var_0", a1.src
    assert frame.local_decls(f) == ["    int var_0;"], frame.local_decls(f)
    print("ok  test_frame_cleanup")


def test_callargs_fold():
    # r1 = 1 ; r2 = 0x20 ; foo() ; ret   -> foo(1, 0x20);
    f = _func(0x500, [
        ir.Assign(0x500, ir.Reg("r1"), ir.Const(1)),
        ir.Assign(0x504, ir.Reg("r2"), ir.Const(0x20)),
        ir.Call(0x508, target=0x900),
        ir.Ret(0x50C),
    ])
    callargs.rewrite(f, {})
    stmts = f.blocks[0x500].stmts
    assert len(stmts) == 2, [type(s).__name__ for s in stmts]  # set-ups folded away
    call = stmts[0]
    assert isinstance(call, ir.Call)
    assert [a.value for a in call.args] == [1, 0x20], call.args
    print("ok  test_callargs_fold")


def test_callargs_arity_cap():
    # callee known to take 1 arg: only r1 is folded, r2 set-up stays.
    f = _func(0x600, [
        ir.Assign(0x600, ir.Reg("r1"), ir.Const(7)),
        ir.Assign(0x604, ir.Reg("r2"), ir.Const(8)),
        ir.Call(0x608, target=0x900),
        ir.Ret(0x60C),
    ])
    callargs.rewrite(f, {0x900: 1})
    stmts = f.blocks[0x600].stmts
    call = [s for s in stmts if isinstance(s, ir.Call)][0]
    assert [a.value for a in call.args] == [7], call.args
    # r2 = 8 kept (not consumed)
    assert any(isinstance(s, ir.Assign) and s.dst.name == "r2" for s in stmts)
    print("ok  test_callargs_arity_cap")


if __name__ == "__main__":
    test_params_and_return()
    test_void_leaf()
    test_pointer_param()
    test_frame_cleanup()
    test_callargs_fold()
    test_callargs_arity_cap()
    print("\nall tests passed")
