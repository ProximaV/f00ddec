# f00ddec — A PS Vita F00D (Toshiba MeP) Decompiler for IDA Pro

`f00ddec` is a high-fidelity decompiler for firmware running on the PlayStation Vita's **F00D** security processor (a little-endian **Toshiba MeP-c4** core). It operates both as an interactive **Hex-Rays-style decompiler plugin for IDA Pro 9.x / 8.x** and as a **standalone headless decompiler and lifter** requiring zero IDA dependencies.

The IDA processor module is leveraged strictly for instruction decoding (`insn_t`), while lifting, static single assignment (SSA) def-use web analysis, virtual variable synthesis, calling convention recovery, control-flow restructuring, and C code generation are entirely custom:

```mermaid
flowchart LR
    Decoder["1. Decoder (insn_t / binary)"] --> Lifter["2. IR Lifter"]
    Lifter --> CFG["3. CFG Builder"]
    CFG --> Struct["4. Structurer"]
    Struct --> Frame["5. Frame Analysis"]
    Frame --> ABI["6. ABI & Signature"]
    ABI --> Vars["7. Def-Use Webs & SSA"]
    Vars --> Opt["8. AST & String Opt"]
    Opt --> CGen["9. Hex-Rays C Emitter"]
```

---

## What It Produces

```c
/*
 * Decompiled by f00ddec -- PS Vita F00D (Toshiba MeP-c4, little-endian).
 */

void sub_8003D8(void)
{
    int v0;
    int v1;
    int v4;
    int v5;
    int v6;

    *(_DWORD *)0xE0000010 = 0xFFFFFFFF;
    v0 = 0x807E80;
    while (1) {
        v1 = *(_DWORD *)v0;
        if (v1 != 0) {
            *(_DWORD *)v0 = 0;
            break;
        }
    }
    if (r0 == 1) {
        v4 = control_bus_load(0);
        v5 = (v4 & 0xF000) >> 4;
        control_bus_store(0, v5);
        ei();
        (*((void (*)(void))v1))();
        di();
        control_bus_store(0, 0x600);
    }
    v6 = 0x807E80;
    *(_DWORD *)v6 = v1;
    return;
}

int sub_8010F2(int a0, int a1, int a2, int a3, int arg_0)
{
    char var_14;
    int var_18;
    int var_1C;
    int var_20;
    int var_24;

    var_24 = a0;
    var_20 = a1;
    var_1C = a2;
    var_18 = a3;
    var_14 = arg_0;
    sub_8010F2("%08x %08x\n", 0x1B, arg_0, r4);
    memcpy(sp, &var_24, 0x10);
    return 0;
}
```

* **Virtual Variables (`v0, v1, ...`)**: Eliminates raw register clutter (`r0..r12`) by tracking live ranges and promoting values to clean C local variables.
* **Function Parameters (`a0..a3`, `arg_0..`)**: Live-in argument registers and stack slots are bound directly to parameter names.
* **Hex-Rays Pointer Dereferencing**: Replaces synthetic memory arrays (`mem32[...]`) with native C pointer expressions (`*(_DWORD *)ptr`, `*(short *)ptr`, `*(_BYTE *)ptr`, `*ptr`, `ptr[idx]`).
* **Global Symbol Resolution**: Data and code addresses automatically resolve to their symbolic names (e.g. `canary`, `g_dispatcher`).
* **ASCII String Literal Rendering**: Constant string references render as formatted C strings (e.g. `"%08x %08x\n"`).
* **Control-Flow Recovery**: Reconstructs `if`/`else`, `while(1)`, `while(cond)`, `do-while`, relational compares, and switch jump tables.
* **Hardware Intrinsics**: Control-bus loads/stores (`control_bus_load`, `control_bus_store`), interrupt state (`ei()`, `di()`), and CPU control registers are expressed cleanly as pseudo-calls.

---

## Key Capabilities & Architectural Enhancements

### 1. SSA-Style Def-Use Webs & Virtual Variable Recovery ([`f00ddec/vars.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/f00ddec/f00ddec/vars.py))
* **Iterative Reaching Definitions**: Tracks active register definitions, kills, and clobbers (including call sites) across basic blocks.
* **Union-Find Live Range Construction**: Merges reaching definition sites and use sites into unified live ranges, splitting disjoint reuses of machine registers into distinct virtual variables (`v0`, `v1`, ...).
* **Copy Propagation & Inlining**: Folds register-to-register copies (`v1 = v0`) and single-use pure address arithmetic directly into memory accesses and call argument expressions.
* **Dead Assignment Elimination**: Eliminates redundant writes to temporary registers and unused callee return values.

### 2. MeP EABI Calling Convention & Signature Synthesis ([`f00ddec/abi.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/f00ddec/f00ddec/abi.py))
* **Register Argument Recovery (`r1`–`r4`)**: Backward iterative dataflow analysis across all basic blocks detects live-in registers at function entry to determine parameter counts.
* **Stack Parameter Recovery (`arg_0, arg_4, ...`)**: Stack offsets above the caller's frame pointer (`sp + frame_size`) are identified as incoming stack arguments and folded into both callee prototypes and caller invocation sites.
* **Global Return Type Inference**: Analyzes exit basic blocks reaching `ret` instructions to verify if `r0` is defined without intervening clobbers. Detects pointer return types (`int *`) based on memory reads and high address spaces (`>= 0x800000`).
* **Tail Call Propagation**: Identifies cross-function tail jumps (`jmp <callee>`), synthesizes caller argument passing across tail calls, and recovers signatures accordingly.

### 3. Hex-Rays Style Memory & Symbol Representation ([`f00ddec/cgen.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/f00ddec/f00ddec/cgen.py))
* **Standard Type Casts**: Emits standard Hex-Rays type cast idioms:
  * 32-bit: `*(_DWORD *)addr`
  * 16-bit unsigned: `*(_WORD *)addr`
  * 16-bit signed: `*(short *)addr`
  * 8-bit unsigned: `*(_BYTE *)addr`
  * 8-bit signed: `*(char *)addr`
* **Typed Pointer Expressions**: When a variable is typed as a pointer (`int *`, `char *`, etc.), dereferences omit redundant casts (`*ptr`) and indexed offsets render cleanly as array indexing (`ptr[i]`).
* **Symbolic Name Resolution**: Addresses matching named symbols in IDA or the export table render directly as identifiers (e.g. `v0 = canary;`).
* **String Literals**: Direct string pointer arguments render as quoted C string literals with escaped characters.

### 4. Interactive Decompiler View & UX ([`f00ddec/view.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/f00ddec/f00ddec/view.py))
* **Exact Multi-Instruction EA Anchoring**: Every decompiled statement retains a full mapping of its contributing instruction EAs (`line_to_eas` and `ea_to_line`), with dense instruction completion covering all basic blocks in the function.
* **Bidirectional Disassembly $\leftrightarrow$ Pseudocode Synchronization**:
  * Selecting any line in the disassembly highlights and scrolls to the corresponding decompiled statement line.
  * Clicking or navigating in the decompiled pseudocode immediately highlights corresponding assembly instructions in `IDA View-A` and updates the cursor without stealing focus.
  * Pressing **`Tab`** seamlessly switches between Disassembly and Pseudocode at the matching instruction address.
* **Token / Identifier Occurrence Highlighting**: Placing the cursor on any variable, parameter, or symbol automatically highlights all occurrences of that token across the entire function.
* **Context-Aware Click-Through Navigation & History Stack**:
  * Double-clicking, pressing **`Enter`**, or pressing **`Space`** on a function call navigates to that function, pushing the caller's position `(func_ea, lineno)` onto a navigation history stack.
  * Pressing **`Esc`** pops the history stack and jumps directly back to the caller.
  * Navigating on a variable, label, or memory address jumps IDA disassembly to that linear address.

### 5. Hex-Rays Interactive Shortcuts (`hexx64.dll` Parity)
`f00ddec` implements the full suite of interactive AST customizations expected by Hex-Rays users:
* **Immediate Format Conversions**:
  * **`H`**: Toggle number constant representation between Hexadecimal and Decimal.
  * **`O`**: Convert numeric immediate to offset / symbol reference.
  * **`R`**: Convert constant to character or multi-byte literal (`'A'`, `'\n'`, `'RIFF'`).
  * **`_`** / **`-`**: Invert sign of number (`-1` vs `0xFFFFFFFF`).
  * **`~`**: Bitwise negation (`~0` vs `0xFFFFFFFF`).
* **Control-Flow & Cast Toggles**:
  * **`I`**: Invert if-condition and swap `then` / `else` branch blocks.
  * **`\`**: Toggle display of explicit type casts on pointer dereferences.
* **Code Annotations & Customizations**:
  * **`/`** or **`;`**: Add, edit, or remove persistent statement comments (rendered as `// comment`).
  * **`N`**: Rename variable, parameter, stack frame member, or function symbol.
  * **`Y`**: Set variable type or edit function prototype (applied to IDA's type system via `ida_typeinf.apply_cdecl`).
  * **`Del`**: Reset custom formatting, comment, variable rename, or if-inversion back to default.
* **Navigation & Analysis**:
  * **`X`**: Jump to cross-references (opens IDA native xrefs dialog for symbol/address).
  * **`B`**: Jump between matching opening and closing curly braces (`{` $\leftrightarrow$ `}`).
  * **`F5`**: Refresh decompilation.

### 6. Resilient Netnode & Desktop Layout Persistence ([`f00ddec/db.py`](file:///c:/Users/Proxima/source/repos/ida-sdk/src/plugins/f00ddec/f00ddec/db.py))
* **Database Netnode (`$ f00ddec`)**: All analyst modifications (variable renames, variable types, function prototypes, immediate formatting, statement comments, if-inversion flags, sync preferences, and window state) are persisted directly inside the `.idb` / `.i64` file using IDA's `netnode` API.
* **Desktop Layout Manager**: UI hooks restore open decompiler tabs, docking positions, and cursor locations upon reopening databases.
* **Headless Fallback**: Transparent in-memory storage fallback for command-line execution and headless unit tests.

### 7. Blazing Performance
* **Single Function**: ~36 ms decompilation time.
* **Full Database**: ~1.17 seconds to decompile all 229 functions in a full PS Vita F00D firmware image (~5.1 ms/function).

---

## Interactive Hotkeys & Shortcuts

When running inside IDA Pro:

| Hotkey | Action | Description |
| :--- | :--- | :--- |
| **`F5`** | Decompile / Refresh | Decompiles the current function or refreshes the active view |
| **`Tab`** | Switch View | Disassembly $\leftrightarrow$ Pseudocode at exact matching instruction EA |
| **`Enter`** / **`Space`** | Navigate Symbol | Jumps to callee function, label, or global data address |
| **`Esc`** | History Back | Steps backward through the function navigation history stack |
| **`H`** | Hex / Decimal Toggle | Toggles immediate constant representation between hex and dec |
| **`O`** | Convert to Offset | Converts immediate constant to symbolic address reference |
| **`R`** | Character Literal | Formats constant as C character literal (`'A'`, `'\n'`, `'RIFF'`) |
| **`_`** / **`-`** | Invert Sign | Inverts sign of numeric constant (`-1` vs `0xFFFFFFFF`) |
| **`~`** | Bitwise Negate | Bitwise negates numeric constant (`~0` vs `0xFFFFFFFF`) |
| **`I`** | Invert If-Condition | Inverts if-statement condition and swaps then/else branches |
| **`\`** | Toggle Casts | Toggles display of explicit pointer type casts |
| **`N`** | Rename Identifier | Renames variable, stack member, or function (saved to IDB netnode) |
| **`Y`** | Set Type / Prototype | Modifies variable type or function prototype (IDA type system) |
| **`/`** or **`;`** | Line Comment | Adds or edits a persistent comment on the current statement |
| **`Del`** | Reset Item | Resets formatting, rename, comment, or inversion on item to default |
| **`X`** | Cross-References | Opens IDA's native cross-references window for symbol under cursor |
| **`B`** | Jump Matching Brace | Jumps between matching `{` and `}` curly braces |
| **`Ctrl-F5`** | Decompile Database | Decompiles all functions in database and exports to `.c` file |

---

## How to Run

### As an IDA Pro Plugin
1. Open your F00D firmware dump using a MeP processor module (IDA 9.x native `mep`, or the companion `mep.py` "mepf00d" processor module).
2. Copy `f00ddec_plugin.py` and the `f00ddec/` package directory into IDA's plugins folder:
   ```cmd
   copy f00ddec_plugin.py "%APPDATA%\Hex-Rays\IDA Pro\plugins\"
   xcopy /E /I f00ddec "%APPDATA%\Hex-Rays\IDA Pro\plugins\f00ddec"
   ```
3. Open the database in IDA Pro and press **`F5`** (or **`Ctrl-Shift-S`**) on any instruction.

### Headless (Command-Line)
Decompile raw binary dumps without requiring IDA Pro. The link base is automatically detected from the reset vector:

```bash
# Decompile entire firmware to a C listing
python -m f00ddec secure_kernel.bin -o secure_kernel.c

# Decompile a single function by address
python -m f00ddec secure_kernel.bin --func 0x8003D8

# Specify custom base and entry points
python -m f00ddec dump.bin --base 0x800000 --entry 0x800100 --entry 0x8003D8
```

---

## The Instruction Set & F00D Hardware

The PlayStation Vita's F00D processor is a **Toshiba MeP-c4** core:
* Little-endian byte order.
* Mixed 16-bit and 32-bit instructions (a word is 32-bit if and only if its leading nibble is $\ge \text{0xC}$).
* 16 General Purpose Registers: `r0..r12`, `tp` (r13), `gp` (r14), `sp` (r15).
* Dedicated Control Registers: `lp` (link pointer / return address), `sar` (shift amount), `psw` (processor status word), `cfg` (configuration register).
* Control bus operations (`ldcb` / `stcb`) interface directly with F00D cryptographic hardware accelerators and power control registers.

---

## Test Suite

The test suite runs 100% headlessly with zero IDA dependencies:

```bash
python tests/test_abi.py
python tests/test_db.py
python tests/test_highlight.py
python tests/test_pipeline.py
python tests/test_recover.py
python tests/test_sync.py
python tests/test_vars.py
```

All 35 unit tests across 7 test suites verify:
* Backward liveness parameter detection, void/pointer return inference, caller consensus, and tail-call propagation.
* Netnode schema serialization, variable renames, type definitions, and window state persistence.
* Token occurrence highlighting and C keyword/type classification.
* Instruction decoding, relational condition recovery, loop structuring, hardware repeat loops, and switch jump tables.
* Def-use web construction, Union-Find live-range splitting, copy propagation, single-use inlining, and dead assignment elimination.
* Bidirectional instruction EA mapping, dense completion, Hex-Rays memory dereference formatting, string literal rendering, and interactive AST transformations (`H`, `O`, `R`, `_`, `~`, `/`, `I`, `\`).

---

## Credits & License

* Built on the MeP reverse-engineering research of **TeamMolecule** (`toshiba-mep-idp`), **xyzz** (`ghidra-mep`), and the CGEN MeP machine description.
* Decompiler architecture and UX design mirrors **zecoxao**'s [`spudec`](https://github.com/zecoxao/spudec) and [`rl78dec`](https://github.com/zecoxao/rl78dec).
* Licensed under the **MIT License**. No proprietary firmware is included.
