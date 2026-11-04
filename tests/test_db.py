"""
Tests for persistence layer (db.py) in f00ddec.
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f00ddec import db


def test_db_renames():
    func_ea = 0x800100
    db.clear_func_data(func_ea)

    db.set_var_rename(func_ea, "v0", "counter")
    data = db.get_func_data(func_ea)
    assert data["renames"].get("v0") == "counter"

    # Renaming again updates canonical key
    db.set_var_rename(func_ea, "counter", "new_counter")
    data = db.get_func_data(func_ea)
    assert data["renames"].get("v0") == "new_counter"

    # Clearing rename
    db.set_var_rename(func_ea, "new_counter", "")
    data = db.get_func_data(func_ea)
    assert "v0" not in data["renames"]
    print("ok  test_db_renames")


def test_db_types_and_proto():
    func_ea = 0x800200
    db.clear_func_data(func_ea)

    db.set_var_type(func_ea, "v1", "uint32_t *")
    db.set_func_proto(func_ea, "int sub_800200(void *ctx)")

    data = db.get_func_data(func_ea)
    assert data["types"].get("v1") == "uint32_t *"
    assert data["proto"] == "int sub_800200(void *ctx)"
    print("ok  test_db_types_and_proto")


def test_db_sync_preference():
    db.set_sync_enabled(True)
    assert db.get_sync_enabled() is True
    db.set_sync_enabled(False)
    assert db.get_sync_enabled() is False
    db.set_sync_enabled(True)
    print("ok  test_db_sync_preference")


def test_db_locators_and_window_state():
    func_ea = 0x800300
    db.clear_func_data(func_ea)

    # Locators
    db.set_var_locator(func_ea, "r1@0x800310", name="buf_len", type_str="size_t", flags=1)
    loc = db.get_var_locator(func_ea, "r1@0x800310")
    assert loc["name"] == "buf_len"
    assert loc["type"] == "size_t"
    assert loc["flags"] == 1

    # Statement comments & numforms
    db.set_statement_cmt(func_ea, 0x800314, "hardware init trigger")
    assert db.get_statement_cmt(func_ea, 0x800314) == "hardware init trigger"

    db.set_numform(func_ea, 0x800314, 0, "hex")
    assert db.get_numform(func_ea, 0x800314, 0) == "hex"

    # Iflags
    inv = db.toggle_iflag(func_ea, 0x800320)
    assert inv is True
    assert db.is_iflag_inverted(func_ea, 0x800320) is True
    inv = db.toggle_iflag(func_ea, 0x800320)
    assert inv is False
    assert db.is_iflag_inverted(func_ea, 0x800320) is False

    # Window state
    db.save_window_state(True, func_ea, lineno=10, col=2)
    ws = db.load_window_state()
    assert ws.get("is_open") is True
    assert ws.get("func_ea") == func_ea
    assert ws.get("lineno") == 10
    assert ws.get("col") == 2

    print("ok  test_db_locators_and_window_state")


def test_decompiler_plugin_registration():
    for mod_name in ["ida_idaapi", "ida_idp", "ida_kernwin", "ida_funcs", "ida_lines"]:
        if mod_name not in sys.modules:
            m = types.ModuleType(mod_name)
            if mod_name == "ida_idaapi":
                m.plugin_t = object
                m.PLUGIN_PROC = 0x0008
                m.PLUGIN_KEEP = 2
                m.PLUGIN_SKIP = 0
                m.BADADDR = 0xFFFFFFFF
            elif mod_name == "ida_kernwin":
                m.action_handler_t = object
                m.action_desc_t = lambda *a, **kw: None
                m.register_action = lambda *a, **kw: True
                m.unregister_action = lambda *a, **kw: True
                m.attach_action_to_menu = lambda *a, **kw: True
                m.add_hotkey = lambda *a, **kw: None
                m.del_hotkey = lambda *a, **kw: None
                m.SETMENU_APP = 0
            elif mod_name == "ida_idp":
                m.get_idp_name = lambda: "mep"
            sys.modules[mod_name] = m

    import f00ddec_plugin

    assert f00ddec_plugin.HOTKEY_DECOMPILE == "F5"
    assert f00ddec_plugin.ACTION_DECOMPILE == "f00ddec:decompile"

    plugin = f00ddec_plugin.PLUGIN_ENTRY()
    assert plugin.flags == sys.modules["ida_idaapi"].PLUGIN_PROC
    assert plugin.comment == "This is a decompilation plugin."
    assert plugin.wanted_hotkey == "F5"
    assert "F5" in plugin.help

    print("ok  test_decompiler_plugin_registration")


if __name__ == "__main__":
    test_db_renames()
    test_db_types_and_proto()
    test_db_sync_preference()
    test_db_locators_and_window_state()
    test_decompiler_plugin_registration()
    print("\nall db tests passed")
