"""
Headless tests for the MeP decoder and decompiler pipeline.  No IDA, no ROM.

    python tests/test_pipeline.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f00ddec import decoder, decompile_image        # noqa: E402


def _img(b, size=0x100):
    a = bytearray(size)
    a[:len(b)] = bytes(b)
    return a


def test_decode_fields():
    # mov r1, #5   (maj 5)  bytes 05 51
    ins = decoder.decode_one(_img([0x05, 0x51]), 0)
    assert ins.mnem == "mov" and ins.size == 2
    assert ins.ops[0].mode == "reg" and ins.ops[0].reg == 1
    assert ins.ops[1].mode == "imm" and ins.ops[1].value == 5

    # ret  (0x7002) bytes 02 70
    ins = decoder.decode_one(_img([0x02, 0x70]), 0)
    assert ins.mnem == "ret" and ins.size == 2

    # mov r2, #0x1234  (32-bit, maj C, lo4=1, rm=0)  bytes 01 C2 34 12
    ins = decoder.decode_one(_img([0x01, 0xC2, 0x34, 0x12]), 0)
    assert ins.mnem == "mov" and ins.size == 4
    assert ins.ops[0].reg == 2 and ins.ops[1].value == 0x1234

    # lw r0, (r1)  (maj 0, lo4=E)  bytes 1E 00
    ins = decoder.decode_one(_img([0x1E, 0x00]), 0)
    assert ins.mnem == "lw" and ins.ops[1].mode == "phrase" and ins.ops[1].base_reg == 1

    # 32-bit length rule: top nibble >= 0xC
    assert decoder.decode_one(_img([0x00, 0xC0, 0, 0]), 0).size == 4
    assert decoder.decode_one(_img([0x00, 0x50]), 0).size == 2
    # nop (0x0000)
    ins = decoder.decode_one(_img([0x00, 0x00]), 0)
    assert ins.mnem == "nop" and ins.size == 2

    # jmp r3 (0x103E -> bytes 3E 10) must be reg mode (not phrase) and mnem "jmp"
    ins = decoder.decode_one(_img([0x3E, 0x10]), 0)
    assert ins.mnem == "jmp" and ins.ops[0].mode == "reg" and ins.ops[0].reg == 3

    # jmp r11 (0x10BE -> bytes BE 10) must decode as "jmp r11", not unconditional "ret"
    ins = decoder.decode_one(_img([0xBE, 0x10]), 0)
    assert ins.mnem == "jmp" and ins.ops[0].mode == "reg" and ins.ops[0].reg == 11

    # bsr24 with negative displacement: 0xD809FFFF at PC=0x800210 -> disp=-0x100 -> target 0x800110
    ins = decoder.decode_one(_img([0x09, 0xD8, 0xFF, 0xFF]), 0x800210, base=0x800210)
    assert ins.mnem == "bsr" and ins.ops[0].addr == 0x800110, hex(ins.ops[0].addr)

    # tp-relative lbu with bit 3 of rn set (maj 4, op1115=9, rn=0xB -> r3, imm7=7)
    # hw = 0x4B87 -> bytes 87 4B -> lbu r3, 7(tp)
    ins = decoder.decode_one(_img([0x87, 0x4B]), 0)
    assert ins.mnem == "lbu" and ins.ops[0].reg == 3, ins.ops[0]
    assert ins.ops[1].base_reg == 13 and ins.ops[1].disp == 7

    # maj 8 lhu with bit 3 of rn set (op1115=0x11, rn=0xA -> r2, op0707=1, op0000=1)
    # hw = 0x8A85 -> bytes 85 8A -> lhu r2, 4(tp)
    ins = decoder.decode_one(_img([0x85, 0x8A]), 0)
    assert ins.mnem == "lhu" and ins.ops[0].reg == 2 and ins.ops[1].disp == 4
    print("ok  test_decode_fields")


def test_all_first_words():
    for hw in range(0, 0x10000, 1):
        b = [hw & 0xFF, (hw >> 8) & 0xFF, 0, 0]
        decoder.decode_one(_img(b), 0)   # must never raise
    print("ok  test_all_first_words")


def test_loop_structuring():
    # mov r1,#5 ; L: add r1,#-1 ; bnez r1,L ; ret
    #   05 51 | FC 61 | FF A1 | 02 70
    prog = decompile_image(_img([0x05, 0x51, 0xFC, 0x61, 0xFF, 0xA1, 0x02, 0x70]),
                           entries=[0], base=0)
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert ("v0 = 5;" in text or "r1 = 5;" in text), text
    assert "do {" in text and ("while (v0 != 0)" in text or "while (r1 != 0)" in text), text
    assert text.count("{") == text.count("}"), text
    print("ok  test_loop_structuring")


def test_repeat_hardware_loop():
    # 0x00: mov r2, #4          (04 52)
    # 0x02: mov r0, #0          (00 50)
    # 0x04: repeat r2, 0x08     (09 E2 02 00)  -> rpb=0x08, rpe=0x08, delay-slot=0x0A
    # 0x08: add r0, #1          (04 60)        <- rpe
    # 0x0A: add r1, #4          (10 61)        <- rpe + 2 (last insn of loop body)
    # 0x0C: ret                 (02 70)
    code = [
        0x04, 0x52,
        0x00, 0x50,
        0x09, 0xE2, 0x02, 0x00,
        0x04, 0x60,
        0x10, 0x61,
        0x02, 0x70,
    ]
    prog = decompile_image(_img(code), entries=[0], base=0)
    text = "\n".join(prog.funcs[0].lines)
    assert "do {" in text or "for (" in text, text
    assert ("+ 4" in text or "+ 1" in text), text
    print("ok  test_repeat_hardware_loop")


def test_switch_jump_table():
    # Build a small Pattern A switch at 0x00 with jump table at 0x40:
    # 0x00: mov r0, #2          (02 50)
    # 0x02: sltu3 r0, r0, r1    (13 00)
    # 0x04: bnei r0, #0, 0x1e   (04 E0 0D 00) -> disp = (0x1e - 0x04) >> 1 = 0x0D
    # 0x08: movu r2, #0x40      (40 D2 00 00) -> imm24 = 0x000040
    # 0x0c: sll r1, #2          (16 61)       -> maj 6: sll r1, #2 (hw = 0x6116)
    # 0x0e: add3 r1, r2, r1     (11 92)       -> maj 9: rl=1, rn=2, rm=1 (hw = 0x9211)
    # 0x10: lw r1, (r1)         (1E 01)
    # 0x12: jmp r1              (1E 10)
    # 0x14: mov r0, #10         (0A 50) ; ret (02 70)  <- case 0
    # 0x18: mov r0, #20         (14 50) ; ret (02 70)  <- case 1
    # 0x1c: mov r0, #30         (1E 50) ; ret (02 70)  <- case 2
    # 0x20: ret                 (02 70)                <- default
    img = _img([], size=0x80)
    code = [
        0x02, 0x50,
        0x13, 0x00,
        0x04, 0xE0, 0x0D, 0x00,
        0x40, 0xD2, 0x00, 0x00,
        0x16, 0x61,
        0x11, 0x92,
        0x1E, 0x01,
        0x1E, 0x10,
        0x0A, 0x50, 0x02, 0x70,
        0x14, 0x50, 0x02, 0x70,
        0x1E, 0x50, 0x02, 0x70,
        0x02, 0x70,
    ]
    img[:len(code)] = bytes(code)
    # Jump table at 0x40: [0x14, 0x18, 0x1C]
    for idx, target in enumerate([0x14, 0x18, 0x1C]):
        off = 0x40 + idx * 4
        img[off:off + 4] = target.to_bytes(4, "little")

    prog = decompile_image(img, entries=[0], base=0)
    text = "\n".join(prog.funcs[0].lines)
    assert ("switch (" in text), text
    assert "case 0:" in text and "case 1:" in text and "case 2:" in text, text
    print("ok  test_switch_jump_table")


if __name__ == "__main__":
    test_decode_fields()
    test_all_first_words()
    test_loop_structuring()
    test_repeat_hardware_loop()
    test_switch_jump_table()
    print("\nall tests passed")
