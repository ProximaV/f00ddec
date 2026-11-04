"""
Tests for calling convention and signature recovery (abi.py) in f00ddec.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f00ddec import abi, cfg, ir


def test_abi_params_and_return():
    # r0 = r1 + r2; ret
    f = cfg.Func(0x100)
    b = cfg.Block(0x100)
    b.stmts = [
        ir.Assign(0x100, ir.Reg("r0"), ir.Bin("+", ir.Reg("r1"), ir.Reg("r2"))),
        ir.Ret(0x104),
    ]
    f.blocks[0x100] = b

    sig = abi.analyze_calling_convention(f)
    assert sig.ret_type == "int", sig.ret_type
    assert len(sig.params) == 2, sig.params
    assert sig.params[0].name == "a0" and sig.params[0].location == "r1"
    assert sig.params[1].name == "a1" and sig.params[1].location == "r2"
    assert sig.format_signature("test_func") == "int test_func(int a0, int a1)"
    print("ok  test_abi_params_and_return")


def test_abi_void_leaf():
    # mem32[0x805000] = r1; ret
    f = cfg.Func(0x200)
    b = cfg.Block(0x200)
    b.stmts = [
        ir.Assign(0x200, ir.Mem(0x805000, 4), ir.Reg("r1")),
        ir.Ret(0x204),
    ]
    f.blocks[0x200] = b

    sig = abi.analyze_calling_convention(f)
    assert sig.ret_type == "void", sig.ret_type
    assert len(sig.params) == 1, sig.params
    assert sig.format_signature("test_leaf") == "void test_leaf(int a0)"
    print("ok  test_abi_void_leaf")


def test_abi_user_proto():
    f = cfg.Func(0x300)
    b = cfg.Block(0x300)
    b.stmts = [ir.Ret(0x300)]
    f.blocks[0x300] = b

    sig = abi.analyze_calling_convention(f, user_proto="int my_custom(void *ctx, int len)")
    assert sig.ret_type == "int"
    assert len(sig.params) == 2
    assert sig.params[0].name == "ctx" and sig.params[0].type_str == "void *"
    assert sig.params[1].name == "len" and sig.params[1].type_str == "int"
def test_abi_caller_consensus():
    # Function with no apparent live-in registers in body, but caller consensus indicates r1 and r2 are passed
    f = cfg.Func(0x400)
    b = cfg.Block(0x400)
    b.stmts = [ir.Ret(0x400)]
    f.blocks[0x400] = b

    consensus = {"r1": True, "r2": True}
    sig = abi.analyze_calling_convention(f, caller_consensus=consensus)
    assert len(sig.params) == 2, sig.params
    assert sig.params[0].location == "r1"
    assert sig.params[1].location == "r2"
    assert sig.format_signature("sub_400") == "void sub_400(int a0, int a1)"
    print("ok  test_abi_caller_consensus")


def test_abi_tail_call_propagation():
    # sub_1000:
    #   tail_call sub_2000(r1, r2, 10, 0x801D36)
    #   ret
    f = cfg.Func(0x1000)
    b = cfg.Block(0x1000)
    c = ir.Call(0x1008, target=0x2000, is_tail=True)
    c.args = [ir.Reg("r1"), ir.Reg("r2"), ir.Const(10), ir.Const(0x801D36)]
    b.stmts = [c, ir.Ret(0x100C)]
    f.blocks[0x1000] = b

    # When ret_types maps 0x2000 -> "int"
    sig = abi.analyze_calling_convention(f, ret_types={0x2000: "int"})
    assert sig.ret_type == "int", sig.ret_type
    assert len(sig.params) == 2, sig.params
    assert sig.params[0].location == "r1"
    assert sig.params[1].location == "r2"
    assert sig.format_signature("sub_1000") == "int sub_1000(int a0, int a1)"
    print("ok  test_abi_tail_call_propagation")


if __name__ == "__main__":
    test_abi_params_and_return()
    test_abi_void_leaf()
    test_abi_user_proto()
    test_abi_caller_consensus()
    test_abi_tail_call_propagation()
    print("\nall abi tests passed")
