"""
Toshiba MeP instruction-set description (the CPU inside the PS Vita's "F00D"
security processor).

Little-endian, mixed 16/32-bit instructions: a word is 32-bit iff the top nibble
of its first halfword (bits 12-15) is >= 0xC, otherwise 16-bit.  This module is
the single source of truth for register names and control-flow classification;
the decoder in :mod:`f00ddec.decoder` and lifter in :mod:`f00ddec.lifter` follow
xyzz's Ghidra SLEIGH (``ghidra-mep/mep.sinc``), itself derived from the CGEN MeP
core description.
"""

# general registers, index 0..15
REG = ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
       "r8", "r9", "r10", "r11", "r12", "tp", "gp", "sp")

# control registers, index 0..31 (Creg addr = idx*4 + 0x2000)
CREG = ("pc", "lp", "sar", "res03", "rpb", "rpe", "rpc", "hi",
        "lo", "res09", "res10", "res11", "mb0", "me0", "mb1", "me1",
        "psw", "id", "tmp", "epc", "exc", "cfg", "res22", "npc",
        "dbg", "depc", "opt", "rcfg", "ccfg", "res29", "res30", "res31")


def reg(i):
    return REG[i & 0xF]


def creg(i):
    return CREG[i & 0x1F]


def is_32bit(hw0):
    return ((hw0 >> 12) & 0xF) >= 0xC


# --- control-flow classification -------------------------------------------

COND_BRANCH = frozenset(("beq", "bne", "bnez", "beqz", "bnei", "beqi",
                         "blti", "bgei"))
CALL = frozenset(("bsr", "jsr"))
RET = frozenset(("ret", "reti"))
# unconditional intra-procedural transfers
UNCOND = frozenset(("bra", "jmp"))
STOP = frozenset(("bra", "jmp", "ret", "reti"))
