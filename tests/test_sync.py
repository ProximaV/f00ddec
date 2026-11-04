"""
Headless tests for disassembly <-> pseudocode line selection syncing and
instruction mapping in f00ddec.

    python tests/test_sync.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f00ddec import cfg, ir, cgen, callargs, structure, names, decoder, decompile_image, frame, abi  # noqa: E402


def _make_insn(ea, mnem):
    ins = decoder.Insn(ea)
    ins.mnem = mnem
    ins.size = 2
    return ins


def test_inlined_call_args_sync():
    # Block at 0x100:
    # 0x100: mov r1, #10
    # 0x102: mov r2, #20
    # 0x104: jsr 0x500
    # 0x106: ret
    f = cfg.Func(0x100)
    b = cfg.Block(0x100)
    for ea, mnem in [(0x100, "mov"), (0x102, "mov"), (0x104, "jsr"), (0x106, "ret")]:
        b.insns.append(_make_insn(ea, mnem))
    b.stmts = [
        ir.Assign(0x100, ir.Reg("r1"), ir.Const(10)),
        ir.Assign(0x102, ir.Reg("r2"), ir.Const(20)),
        ir.Call(0x104, target=0x500),
        ir.Ret(0x106),
    ]
    b.term = "ret"
    f.blocks[0x100] = b

    callargs.rewrite(f, {0x500: 2})
    tree = structure.structure(f)
    namer = names.Namer()
    lines = cgen.generate(f, tree, namer)

    assert hasattr(lines, "line_to_eas")
    assert hasattr(lines, "ea_to_line")

    # Find the line containing "sub_500(10, 20);"
    call_line = None
    for idx, text in enumerate(lines):
        if "sub_500" in text:
            call_line = idx
            break

    assert call_line is not None, lines

    # Both argument setups (0x100, 0x102) and the call (0x104) must map to call_line!
    assert lines.ea_to_line[0x100] == call_line, (lines.ea_to_line[0x100], call_line)
    assert lines.ea_to_line[0x102] == call_line, (lines.ea_to_line[0x102], call_line)
    assert lines.ea_to_line[0x104] == call_line, (lines.ea_to_line[0x104], call_line)

    # In reverse: selecting call_line must highlight all 3 instructions!
    eas = lines.line_to_eas[call_line]
    assert 0x100 in eas, eas
    assert 0x102 in eas, eas
    assert 0x104 in eas, eas
    print("ok  test_inlined_call_args_sync")


def test_tail_call_sync():
    # sub_801E76 style tail call:
    # 0x801E76: mov r3, #0xA
    # 0x801E78: movu r4, #0x801D36
    # 0x801E7C: jmp sub_801DFC
    f = cfg.Func(0x801E76)
    b = cfg.Block(0x801E76)
    for ea, mnem in [(0x801E76, "mov"), (0x801E78, "movu"), (0x801E7C, "jmp")]:
        b.insns.append(_make_insn(ea, mnem))
    b.stmts = [
        ir.Assign(0x801E76, ir.Reg("r3"), ir.Const(0xA)),
        ir.Assign(0x801E78, ir.Reg("r4"), ir.Const(0x801D36)),
        ir.Call(0x801E7C, target=0x801DFC, is_tail=True),
        ir.Ret(0x801E7C),
    ]
    b.term = "ret"
    f.blocks[0x801E76] = b

    callargs.rewrite(f, {0x801DFC: 4})
    tree = structure.structure(f)
    namer = names.Namer()
    lines = cgen.generate(f, tree, namer)

    # Find the line containing "sub_801DFC"
    tail_line = None
    for idx, text in enumerate(lines):
        if "sub_801DFC" in text:
            tail_line = idx
            break

    assert tail_line is not None, lines

    # Selecting 0x801E76, 0x801E78, or 0x801E7C in disassembly maps to tail_line
    assert lines.ea_to_line[0x801E76] == tail_line
    assert lines.ea_to_line[0x801E78] == tail_line
    assert lines.ea_to_line[0x801E7C] == tail_line

    # Reverse: selecting tail_line returns all 3 instruction addresses
    eas = lines.line_to_eas[tail_line]
    assert 0x801E76 in eas and 0x801E78 in eas and 0x801E7C in eas
    print("ok  test_tail_call_sync")


def test_dense_instruction_completion():
    # Ensure instructions that do not emit standalone C lines (like NOPs or spills)
    # still map to the nearest valid statement in that block.
    f = cfg.Func(0x300)
    b = cfg.Block(0x300)
    # 0x300: nop
    # 0x302: mov r0, #42
    # 0x304: ret
    for ea, mnem in [(0x300, "nop"), (0x302, "mov"), (0x304, "ret")]:
        b.insns.append(_make_insn(ea, mnem))
    b.stmts = [
        ir.Assign(0x302, ir.Reg("r0"), ir.Const(42)),
        ir.Ret(0x304),
    ]
    b.term = "ret"
    f.blocks[0x300] = b

    tree = structure.structure(f)
    namer = names.Namer()
    lines = cgen.generate(f, tree, namer)

    # Every single instruction in b.insns MUST be present in ea_to_line
    for ins in b.insns:
        assert ins.ea in lines.ea_to_line, f"Instruction at 0x{ins.ea:X} missing from ea_to_line"

    # Selecting 0x300 (nop) resolves to a valid line number in the decompiler
    nop_line = lines.ea_to_line[0x300]
    assert 0 <= nop_line < len(lines)
    print("ok  test_dense_instruction_completion")


def test_full_pipeline_sync():
    # End-to-end decompile of a loop program
    # mov r1, #5 ; L: add r1, #-1 ; bnez r1, L ; ret
    code = [0x05, 0x51, 0xFC, 0x61, 0xFF, 0xA1, 0x02, 0x70]
    prog = decompile_image(bytes(code), entries=[0], base=0)
    fn = prog.funcs[0]

    assert hasattr(fn, "ea_to_line")
    assert hasattr(fn, "line_to_eas")

    # All instruction addresses (0, 2, 4, 6) must be present in ea_to_line
    for ea in [0, 2, 4, 6]:
        assert ea in fn.ea_to_line, f"Address 0x{ea:X} not mapped in ea_to_line"
        lineno = fn.ea_to_line[ea]
        assert 0 <= lineno < len(fn.lines)
        assert ea in fn.line_to_eas[lineno]
    print("ok  test_full_pipeline_sync")


def test_hexrays_memory_deref():
    # Verify Hex-Rays style pointer dereferencing (*(_DWORD*), *(_WORD*), *(_BYTE*), *(char*), *(short*))
    f = cfg.Func(0x500)
    b = cfg.Block(0x500)
    b.stmts = [
        # *(_DWORD *)0xE0000010 = 0xFFFFFFFF;
        ir.Assign(0x500, ir.Mem(0xE0000010, 4), ir.Const(0xFFFFFFFF)),
        # v1 = *(_DWORD *)v0;
        ir.Assign(0x504, ir.Var("v1"), ir.Mem(ir.Var("v0"), 4)),
        # v2 = *(short *)v0;
        ir.Assign(0x508, ir.Var("v2"), ir.Mem(ir.Var("v0"), 2, signed=True)),
        # v3 = *(_WORD *)v0;
        ir.Assign(0x50C, ir.Var("v3"), ir.Mem(ir.Var("v0"), 2, signed=False)),
        # v4 = *(char *)(v1 + 4);
        ir.Assign(0x510, ir.Var("v4"), ir.Mem(ir.Bin("+", ir.Var("v1"), ir.Const(4)), 1, signed=True)),
        # *(_BYTE *)v0 = v4;
        ir.Assign(0x514, ir.Mem(ir.Var("v0"), 1, signed=False), ir.Var("v4")),
        # Named global variable: canary = 0x12345678;
        ir.Assign(0x518, ir.Mem(0x8078E8, 4), ir.Const(0x12345678)),
        ir.Ret(0x51C),
    ]
    b.term = "ret"
    f.blocks[0x500] = b

    tree = structure.structure(f)
    namer = names.Namer(code_names={0x8078E8: "canary"})
    user_types = {"p_int": "int *"}
    lines = cgen.generate(f, tree, namer, user_types=user_types)
    text = "\n".join(lines)

    assert "*(_DWORD *)0xE0000010 = 0xFFFFFFFF;" in text, text
    assert "v1 = *(_DWORD *)v0;" in text, text
    assert "v2 = *(short *)v0;" in text, text
    assert "v3 = *(_WORD *)v0;" in text, text
    assert "v4 = *(char *)(v1 + 4);" in text, text
    assert "*(_BYTE *)v0 = v4;" in text, text
    assert "canary = 0x12345678;" in text, text
    print("ok  test_hexrays_memory_deref")


def test_string_literal_rendering():
    # Verify ASCII string literal notation in calls and assignments
    f = cfg.Func(0x600)
    b = cfg.Block(0x600)
    b.stmts = [
        # Call with string literal argument: sub_8010F2("%08x %08x\n", 0x1B, arg_0, r4);
        ir.Call(0x600, target=0x8010F2, args=[
            ir.Const(0x807504, name="a08x08x_2"),
            ir.Const(0x1B),
            ir.Var("arg_0"),
            ir.Reg("r4"),
        ]),
        ir.Ret(0x604),
    ]
    b.term = "ret"
    f.blocks[0x600] = b

    tree = structure.structure(f)
    namer = names.Namer(
        code_names={0x8010F2: "sub_8010F2"},
        strings={0x807504: "%08x %08x\n"}
    )
    lines = cgen.generate(f, tree, namer)
    text = "\n".join(lines)

    assert 'sub_8010F2("%08x %08x\\n", 0x1B, arg_0, r4);' in text, text
    print("ok  test_string_literal_rendering")


def test_interactive_cgen():
    f = cfg.Func(0x700)
    b = cfg.Block(0x700)
    b.stmts = [
        ir.Assign(0x700, ir.Var("v0"), ir.Const(0x41)),
        ir.Assign(0x704, ir.Var("v1"), ir.Const(0xFFFFFFFF)),
        ir.Assign(0x708, ir.Var("v2"), ir.Const(0x801000)),
        ir.Ret(0x70C),
    ]
    b.term = "ret"
    f.blocks[0x700] = b

    tree = structure.structure(f)
    namer = names.Namer(code_names={0x801000: "g_buffer"})

    user_comments = {0x700: "Initialize v0 with character"}
    user_numforms = {
        (0x700, "0x41"): "char",
        (0x704, "0xffffffff"): "invsign",
        (0x708, "0x801000"): "offset",
    }
    lines = cgen.generate(f, tree, namer, user_comments=user_comments, user_numforms=user_numforms)
    text = "\n".join(lines)

    assert "v0 = 'A';  // Initialize v0 with character" in text, text
    assert "v1 = -1;" in text, text
    assert "v2 = g_buffer;" in text, text

    # Test bitwise negate and decimal
    user_numforms_2 = {
        (0x700, "0x41"): "dec",
        (0x704, "0xffffffff"): "bnot",
    }
    lines2 = cgen.generate(f, tree, namer, user_numforms=user_numforms_2)
    text2 = "\n".join(lines2)
    assert "v0 = 65;" in text2, text2
    assert "v1 = ~0;" in text2, text2

    # Test if-condition inversion and branch swap
    f_if = cfg.Func(0x800)
    cond = ir.Bin("==", ir.Var("v0"), ir.Const(0))
    s_then = [structure.SStmt(ir.Assign(0x804, ir.Var("out"), ir.Const(1)))]
    s_else = [structure.SStmt(ir.Assign(0x808, ir.Var("out"), ir.Const(2)))]
    s_if = structure.SIf(cond, s_then, s_else, ea=0x800)
    tree_if = [s_if, structure.SStmt(ir.Ret(0x80C))]

    # Normal emit: if (v0 == 0) { out = 1; } else { out = 2; }
    lines_norm = cgen.generate(f_if, tree_if, namer)
    text_norm = "\n".join(lines_norm)
    assert "if (v0 == 0)" in text_norm
    assert "out = 1;" in text_norm

    # Inverted emit: if (v0 != 0) { out = 2; } else { out = 1; }
    user_iflags = {0x800}
    lines_inv = cgen.generate(f_if, tree_if, namer, user_iflags=user_iflags)
    text_inv = "\n".join(lines_inv)
    assert "if (v0 != 0)" in text_inv
    inv_lines = [l.strip() for l in lines_inv if l.strip()]
    idx_if = [i for i, l in enumerate(inv_lines) if l.startswith("if (v0 != 0)")][0]
    assert "out = 2;" in inv_lines[idx_if + 1]

    # Test show_casts=False
    f_mem = cfg.Func(0x900)
    b_mem = cfg.Block(0x900)
    b_mem.stmts = [
        ir.Assign(0x900, ir.Var("v0"), ir.Mem(ir.Var("ptr"), 4)),
        ir.Ret(0x904),
    ]
    b_mem.term = "ret"
    f_mem.blocks[0x900] = b_mem
    tree_mem = structure.structure(f_mem)

    lines_casts_on = cgen.generate(f_mem, tree_mem, namer, show_casts=True)
    assert "*(_DWORD *)ptr" in "\n".join(lines_casts_on)

    lines_casts_off = cgen.generate(f_mem, tree_mem, namer, show_casts=False)
    assert "*ptr" in "\n".join(lines_casts_off)
    print("ok  test_interactive_cgen")


if __name__ == "__main__":
    test_inlined_call_args_sync()
    test_tail_call_sync()
    test_dense_instruction_completion()
    test_full_pipeline_sync()
    test_hexrays_memory_deref()
    test_string_literal_rendering()
    test_interactive_cgen()
    print("\nall sync tests passed")
