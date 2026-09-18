"""
f00ddec -- a decompiler for the PS Vita "F00D" security processor, a
little-endian Toshiba MeP core.

Mirrors zecoxao's spudec and the Kirk/Spock (startrekdec) and RL78 (rl78dec)
tools: an IDA processor module is used purely as a decoder; the standalone
package re-implements that decoder so the whole pipeline runs headless on a raw
F00D dump.

    decoder -> lifter -> cfg -> opt -> structure -> cgen
"""

from . import decoder, cfg, opt, structure, cgen, loader
from .names import Namer

__version__ = "0.1.0"

BANNER = [
    "/*",
    " * Decompiled by f00ddec -- PS Vita F00D (Toshiba MeP, little-endian).",
    " * r0..r12/tp/gp/sp are the machine registers; mem8/mem16/mem32 index data",
    " * memory (s8/s16 = sign-extending loads).  Unmodelled opcodes are printed",
    " * as pseudo-calls; cross-function tail jumps as JUMPOUT().",
    " */",
    "",
]


class Function:
    def __init__(self, entry, name, func, tree, lines):
        self.entry = entry
        self.name = name
        self.cfg = func
        self.tree = tree
        self.lines = lines


class Program:
    def __init__(self, image, base, insns, funcs, namer):
        self.image = image
        self.base = base
        self.insns = insns
        self.funcs = funcs
        self.namer = namer

    def listing(self, banner=True):
        out = list(BANNER) if banner else []
        for entry in sorted(self.funcs):
            out.extend(self.funcs[entry].lines)
            out.append("")
        return "\n".join(out)


def decompile_image(image, entries, base=0, code_names=None):
    insns, calls = decoder.decode(image, entries=entries, base=base)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = Namer(code_names=code_names)
    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        tree = structure.structure(f)
        out[entry] = Function(entry, namer.code(entry), f, tree,
                              cgen.generate(f, tree, namer))
    return Program(image, base, insns, out, namer)


def decompile_file(path, base=None, extra_entries=(), **kw):
    image = loader.load(path)
    det_base, reset = loader.detect_base(image)
    if base is None:
        base = det_base
    entries = list(loader.vector_entries(image, base))
    if reset:
        entries.append(reset)
    entries += list(extra_entries)
    return decompile_image(image, entries=entries, base=base, **kw)
