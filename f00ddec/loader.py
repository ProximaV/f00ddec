"""
Image loading and entry discovery for MeP/F00D firmware.

F00D dumps are raw and position-dependent: the reset instruction at offset 0 is a
32-bit ``jmp code24`` whose absolute target reveals the link base (e.g. secure
kernel -> 0x800000, second loader -> 0x40000).  The vector table that follows is a
list of ``jmp``s, which seed the decoder along with every discovered call.
"""

from . import decoder

VECTOR_TABLE_SIZE = 0x100


def load(path):
    with open(path, "rb") as fp:
        return bytearray(fp.read())


def detect_base(image):
    """Infer the link base from the reset jmp target (aligned down to 4 KiB)."""
    ins = decoder.decode_one(image, 0, base=0)
    if ins is not None and ins.mnem == "jmp":
        t = decoder.target_of(ins)
        if t:
            return t & ~0xFFF, t          # (base, reset entry)
    return 0, 0


def vector_entries(image, base):
    """Reset entry plus every jmp target in the vector table."""
    entries = []
    seen = set()
    for off in range(0, min(VECTOR_TABLE_SIZE, len(image) - 3), 4):
        ins = decoder.decode_one(image, base + off, base=base)
        if ins is not None and ins.mnem == "jmp":
            t = decoder.target_of(ins)
            if t is not None and base <= t < base + len(image) and t not in seen:
                seen.add(t)
                entries.append(t)
    return entries
