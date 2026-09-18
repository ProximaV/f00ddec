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
    assert "r1 = 5;" in text, text
    assert "do {" in text and "while (r1 != 0)" in text, text
    assert text.count("{") == text.count("}"), text
    print("ok  test_loop_structuring\n")
    print(text)


if __name__ == "__main__":
    test_decode_fields()
    test_all_first_words()
    test_loop_structuring()
    print("\nall tests passed")
