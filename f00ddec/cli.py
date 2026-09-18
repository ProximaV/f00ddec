"""
Headless CLI:

    python -m f00ddec secure_kernel.bin              # base auto-detected from reset jmp
    python -m f00ddec secure_kernel.bin -o out.c
    python -m f00ddec dump.bin --base 0x800000 --entry 0x800100
    python -m f00ddec dump.bin --func 0x80030A

No IDA required.
"""

import argparse
import sys

from . import decompile_file


def _int(s):
    return int(s, 0)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(prog="f00ddec",
                                 description="Decompile PS Vita F00D (Toshiba MeP) firmware to pseudo-C.")
    ap.add_argument("rom", help="raw MeP/F00D flash dump")
    ap.add_argument("-o", "--out", help="write listing to this file (default: stdout)")
    ap.add_argument("--base", type=_int, default=None, help="link base (default: auto from reset jmp)")
    ap.add_argument("--entry", type=_int, action="append", default=None, help="extra entry point (repeatable)")
    ap.add_argument("--func", type=_int, default=None, help="only emit the function at this address")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args(argv)

    prog = decompile_file(args.rom, base=args.base,
                          extra_entries=tuple(args.entry) if args.entry else ())

    if args.func is not None:
        f = prog.funcs.get(args.func)
        if f is None:
            ap.error("no function decoded at 0x%X (try --entry 0x%X)" % (args.func, args.func))
        text = "\n".join(f.lines)
    else:
        text = prog.listing(banner=not args.no_banner)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fp:
            fp.write(text + "\n")
        print("f00ddec: base 0x%X, %d functions -> %s" % (prog.base, len(prog.funcs), args.out), file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
