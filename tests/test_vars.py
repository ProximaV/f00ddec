"""
Tests for high-level virtual variable recovery and register tracing layer (vars.py) in f00ddec.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f00ddec import abi, cfg, frame, ir, vars


def test_vars_loop_induction():
    # CFG:
    # Block 0: r2 = 4; br Block 1
    # Block 1: r2 = r2 - 1; brnz r2, Block 1; ret
    f = cfg.Func(0x1000)
    b0 = cfg.Block(0x1000)
    b0.stmts = [ir.Assign(0x1000, ir.Reg("r2"), ir.Const(4))]
    b0.succ = [("jump", 0x1004)]

    b1 = cfg.Block(0x1004)
    b1.stmts = [
        ir.Assign(0x1004, ir.Reg("r2"), ir.Bin("-", ir.Reg("r2"), ir.Const(1))),
        ir.Branch(0x1008, ir.Bin("!=", ir.Reg("r2"), ir.Const(0)), 0x1004, 0x100C),
        ir.Ret(0x100C),
    ]
    b1.succ = [("cond", 0x1004), ("fall", 0x100C)]

    f.blocks[0x1000] = b0
    f.blocks[0x1004] = b1
    fi = frame.FrameInfo()

    vars.recover_variables(f, None, fi)

    # Both blocks must use the exact same variable (v0)
    assert isinstance(b0.stmts[0].dst, ir.Var)
    var_name = b0.stmts[0].dst.name
    assert var_name.startswith("v"), var_name

    # In loop body, dst and src must match var_name
    assert b1.stmts[0].dst.name == var_name
    assert b1.stmts[0].src.l.name == var_name
    assert b1.stmts[1].cexpr.l.name == var_name

    # Virtual variable must be registered in virtual_vars
    assert var_name in fi.virtual_vars
    print("ok  test_vars_loop_induction")


def test_vars_param_binding():
    # r1 used at entry -> bound to a0
    f = cfg.Func(0x2000)
    b = cfg.Block(0x2000)
    b.stmts = [
        ir.Assign(0x2000, ir.Mem(0x805000, 4), ir.Reg("r1")),
        ir.Ret(0x2004),
    ]
    f.blocks[0x2000] = b
    fi = frame.FrameInfo()

    sig = abi.FunctionSig(name="sub_2000", params=[abi.Param("a0", "int", "r1")])

    vars.recover_variables(f, sig, fi)

    assert b.stmts[0].src.name == "a0", b.stmts[0].src
    # Parameter a0 should NOT be registered as a local variable declaration
    assert "a0" not in fi.virtual_vars
    print("ok  test_vars_param_binding")


def test_vars_copy_propagation():
    # r2 = r1; r3 = r2 + 1; mem32[0x805000] = r3; ret
    f = cfg.Func(0x3000)
    b = cfg.Block(0x3000)
    b.stmts = [
        ir.Assign(0x3000, ir.Reg("r2"), ir.Reg("r1")),
        ir.Assign(0x3004, ir.Reg("r3"), ir.Bin("+", ir.Reg("r2"), ir.Const(1))),
        ir.Assign(0x3008, ir.Mem(0x805000, 4), ir.Reg("r3")),
        ir.Ret(0x300C),
    ]
    f.blocks[0x3000] = b
    fi = frame.FrameInfo()
    sig = abi.FunctionSig(name="sub_3000", params=[abi.Param("a0", "int", "r1")])

    vars.recover_variables(f, sig, fi)

    # Copy r2 = a0 should be propagated so r3 computation uses a0
    last_assign = [s for s in b.stmts if isinstance(s, ir.Assign)][-1]
    assert _has_var(last_assign.src, "a0")
    print("ok  test_vars_copy_propagation")


def test_vars_single_use_inlining():
    # v0 = a0 + 4; mem32[v0] = 99
    # v0 should be inlined into mem32[a0 + 4] = 99
    f = cfg.Func(0x4000)
    b = cfg.Block(0x4000)
    b.stmts = [
        ir.Assign(0x4000, ir.Reg("r2"), ir.Bin("+", ir.Reg("r1"), ir.Const(4))),
        ir.Assign(0x4004, ir.Mem(ir.Reg("r2"), 4), ir.Const(99)),
        ir.Ret(0x4008),
    ]
    f.blocks[0x4000] = b
    fi = frame.FrameInfo()
    sig = abi.FunctionSig(name="sub_4000", params=[abi.Param("a0", "int", "r1")])

    vars.recover_variables(f, sig, fi)

    store_stmt = [s for s in b.stmts if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Mem)][0]
    assert isinstance(store_stmt.dst.addr, ir.Bin)
    assert store_stmt.dst.addr.op == "+"
    assert store_stmt.dst.addr.l.name == "a0"
    assert store_stmt.dst.addr.r.value == 4
    print("ok  test_vars_single_use_inlining")


def _has_var(expr, var_name):
    if isinstance(expr, (ir.Var, ir.Reg)) and expr.name == var_name:
        return True
    if isinstance(expr, ir.Bin):
        return _has_var(expr.l, var_name) or _has_var(expr.r, var_name)
    if isinstance(expr, ir.Un):
        return _has_var(expr.e, var_name)
    return False


if __name__ == "__main__":
    test_vars_loop_induction()
    test_vars_param_binding()
    test_vars_copy_propagation()
    test_vars_single_use_inlining()
    print("\nall vars tests passed")
