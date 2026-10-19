"""
IDA plugin entry point for f00ddec, the PS Vita F00D (Toshiba MeP) decompiler.

Install by copying this file *and* the ``f00ddec`` package directory together
into IDA's user plugin directory (``%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\``).
Open the dump with a MeP processor module (the bundled ``mepf00d`` Python module,
or IDA's native ``mep``):

    Ctrl-Shift-S   decompile the function under the cursor
    Ctrl-F5        decompile every function in the database
"""

import os
import sys
import time
import traceback

import ida_idaapi
import ida_idp
import ida_kernwin
import ida_funcs

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

HOTKEY_ONE = "Ctrl-Shift-S"
HOTKEY_ALL = "Ctrl-F5"
_views = []
_hotkeys = []


def _is_mep():
    try:
        return ida_idp.get_idp_name().lower().startswith("mep")
    except Exception:
        return False


def _run_one():
    from f00ddec import ida_bridge, view
    if not _is_mep():
        ida_kernwin.warning("f00ddec: this database is not MeP.\n"
                            "Open it with a MeP processor module (mepf00d or native mep).")
        return
    ea = ida_kernwin.get_screen_ea()
    if ida_funcs.get_func(ea) is None:
        ida_kernwin.warning("f00ddec: no function at 0x%X (press 'P')." % ea)
        return
    try:
        fn = ida_bridge.decompile_one(ea)
    except Exception:
        ida_kernwin.warning("f00ddec failed:\n\n%s" % traceback.format_exc())
        return
    v = view.show(fn)
    if v is not None:
        _views.append(v)
    print("f00ddec: %s -> %d blocks" % (fn.name, len(fn.cfg.blocks)))


def _run_all():
    from f00ddec import ida_bridge, view
    import ida_nalt
    if not _is_mep():
        ida_kernwin.warning("f00ddec: this database is not MeP.")
        return
    ida_kernwin.show_wait_box("f00ddec: decompiling all functions...")
    t0 = time.time()
    try:
        prog = ida_bridge.decompile_program()
    except Exception:
        ida_kernwin.hide_wait_box()
        ida_kernwin.warning("f00ddec: decompile all failed:\n\n%s" % traceback.format_exc())
        return
    finally:
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass
    lines = prog.listing().splitlines()
    print("f00ddec: %d functions in %.1fs" % (len(prog.funcs), time.time() - t0))
    default = os.path.splitext(ida_nalt.get_input_file_path() or "f00d")[0] + ".c"
    path = ida_kernwin.ask_file(True, default, "Save the decompiled listing")
    if path:
        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(lines) + "\n")
            print("f00ddec: wrote %d lines to %s" % (len(lines), path))
        except Exception as exc:
            ida_kernwin.warning("f00ddec: could not write %s:\n%s" % (path, exc))
    v = view.show_listing("f00ddec - all functions", lines)
    if v is not None:
        _views.append(v)


class F00dDecPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "PS Vita F00D (Toshiba MeP) decompiler: lifter + structuring + pseudo-C"
    help = "%s decompiles the current function, %s decompiles everything." % (HOTKEY_ONE, HOTKEY_ALL)
    wanted_name = "F00D decompiler (f00ddec)"
    wanted_hotkey = HOTKEY_ONE

    def init(self):
        if not _is_mep():
            return ida_idaapi.PLUGIN_SKIP
        ctx = ida_kernwin.add_hotkey(HOTKEY_ALL, _run_all)
        if ctx is not None:
            _hotkeys.append(ctx)
        print("f00ddec: loaded -- %s = this function, %s = decompile all" % (HOTKEY_ONE, HOTKEY_ALL))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _run_one()

    def term(self):
        try:
            from f00ddec import view
            view.cleanup()
        except Exception:
            pass
        for ctx in _hotkeys:
            try:
                ida_kernwin.del_hotkey(ctx)
            except Exception:
                pass
        del _hotkeys[:]
        del _views[:]


def PLUGIN_ENTRY():
    return F00dDecPlugin()
