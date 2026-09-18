"""
IDA integration for f00ddec.  Runs inside IDA on a database opened with a MeP
processor module (the bundled ``mepf00d`` Python module, or IDA's native ``mep``).
Reads the flash bytes from the database, uses IDA's function boundaries as entry
points, and reuses IDA's names.  IDA is imported lazily.
"""

from . import decoder, cfg, opt, structure, cgen
from .names import Namer
from . import Program, Function, BANNER  # noqa: F401


class IdaNamer(Namer):
    def __init__(self):
        super().__init__()
        import ida_name
        self._n = ida_name

    def code(self, ea):
        if ea is None:
            return "?"
        return self._n.get_name(ea) or super().code(ea)

    def label(self, ea):
        return self._n.get_name(ea) or super().label(ea)


def _image():
    import ida_bytes, ida_segment
    lo = None
    hi = 0
    seg = ida_segment.get_first_seg()
    while seg is not None:
        lo = seg.start_ea if lo is None else min(lo, seg.start_ea)
        hi = max(hi, seg.end_ea)
        seg = ida_segment.get_next_seg(seg.start_ea)
    if lo is None:
        return None, 0
    data = ida_bytes.get_bytes(lo, hi - lo) or b""
    return bytearray(data), lo


def _entries():
    import idautils
    return sorted(idautils.Functions())


def decompile_program():
    image, base = _image()
    if image is None:
        raise RuntimeError("f00ddec: no segments")
    entries = _entries() or [base]
    insns, calls = decoder.decode(image, entries=entries, base=base)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = IdaNamer()
    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        tree = structure.structure(f)
        out[entry] = Function(entry, namer.code(entry), f, tree, cgen.generate(f, tree, namer))
    return Program(image, base, insns, out, namer)


def decompile_one(ea):
    import ida_funcs
    f = ida_funcs.get_func(ea)
    entry = f.start_ea if f is not None else ea
    image, base = _image()
    entset = set(_entries()) | {entry}
    insns, _ = decoder.decode(image, entries=[entry] + _entries(), base=base)
    func = cfg.build_func(insns, entry, entset)
    if func is None:
        raise RuntimeError("f00ddec: nothing decoded at 0x%X" % entry)
    namer = IdaNamer()
    opt.optimize(func)
    tree = structure.structure(func)
    return Function(entry, namer.code(entry), func, tree, cgen.generate(func, tree, namer, banner=BANNER))
