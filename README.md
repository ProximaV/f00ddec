# f00ddec — a PS Vita F00D (Toshiba MeP) decompiler

`f00ddec` decompiles firmware for the PlayStation Vita's **F00D** security
processor — a little-endian **Toshiba MeP** core — to readable pseudo-C. It is
the MeP analogue of [`spudec`](https://github.com/zecoxao/spudec) and the
Kirk/Spock [`startrekdec`](https://github.com/zecoxao/startrekdec) /
[`rl78dec`](https://github.com/zecoxao/rl78dec): an IDA processor module is used
purely as a *decoder*, and lifting, control-flow recovery and code generation are
ours.

```
decoder → lifter → cfg → opt → frame → abi → cgen
```

## What it produces

```c
void sub_80030A(void)              // an F00D syscall/exception handler
{
    tmp = sp;
    sp = 0x807E80;                 // movh+add3 folded into one constant
    mem32[0x807E80] = r0;
    r0 = lp;
    sub_802686(); sub_8026C6(); sub_8003A0();
    r5 = r0; r1 = r0;
    sub_8027D0(); r6 = r0;
    r7 = control_bus_load(0);       // ldcb  -- F00D hardware register
    r7 = r7 & 0xF000; r7 = r7 >> 4;
    control_bus_store(0, r7);       // stcb
    ei();
    r1 = r5;
    (*mem32[r6])();                 // jsr (r6) -- indirect call
    di();
    control_bus_store(0, 0x600);
    ... register save/restore ...
    return;
}
```

Registers print as themselves (`r0..r12`, `tp`, `gp`, `sp`, and control registers
`lp`/`sar`/`psw`/`cfg`/…); memory reads as `mem8`/`mem16`/`mem32` (`s8`/`s16` for
sign-extending loads); MeP compare-and-branch folds into relational `if`s; the
`movh`+`or3`/`add3` address idiom folds to a single constant; loops become
`while`/`do-while`; cross-function tail jumps render as `JUMPOUT(addr)`.

### Stack frame and calling convention recovery

The MeP EABI passes the first four integer arguments in `r1`–`r4` (the rest on
the stack), returns a value in `r0`, uses `r8` as the frame pointer and `sp`
(= r15) as the stack pointer, with the return address in the `lp` control
register. `f00ddec` uses that to clean the output up towards Hex-Rays:

* **Suppresses prologue & epilogue boilerplate**: the stack allocation
  (`add sp,#-N` / `add sp,#N`), the frame-pointer setup (`r8 = sp`) and
  callee-saved register save/restore pairs (`mem32[sp+off] = rX` … `rX =
  mem32[sp+off]`) are filtered out.
* **Resolves stack variables**: a slot `mem[sp+off]` becomes a local `var_off`
  (typed `char`/`short`/`int` by access width) declared at the head of the body;
  a stack address `sp + off` passed to a callee becomes `&var_off`.
* **Infers function signatures**: backward liveness over `r1`–`r4` recovers the
  argument count and a `r0` definition reaching a `ret` recovers the return type,
  so a function reads `int sub_X(int r1, int *r2)` instead of `void sub_X(void)`,
  with `return r0;`. A parameter dereferenced as a memory base is typed `int *`.
* **Folds call-site arguments**: the `r1 = …; r2 = …; foo();` set-up run collapses
  into `foo(r1, r2)`, capped by the callee's own recovered parameter count.

This is a lightweight structural recovery, not full Hex-Rays variable coalescing.

## Two ways to run it

**Headless (no IDA)** — a raw F00D flash dump; the link base is auto-detected
from the reset `jmp`:

```
python -m f00ddec secure_kernel.bin -o secure_kernel.c
python -m f00ddec secure_kernel.bin --func 0x80030A
python -m f00ddec dump.bin --base 0x800000 --entry 0x800100
```

**As an IDA plugin** — open the dump with a MeP processor module (the companion
`mep.py` "mepf00d" module, or IDA 9.x's native `mep`), then drop
`f00ddec_plugin.py` **and** the `f00ddec/` package into
`%APPDATA%\Hex-Rays\IDA Pro\plugins\`:

| Hotkey | Action |
| --- | --- |
| `Ctrl-Shift-S` | decompile the function under the cursor |
| `Ctrl-F5` | decompile the whole database (and offer to save it) |

The viewer is theme-highlighted and double-click navigates. Inside IDA the output
reuses whatever names you have applied.

## The instruction set

Toshiba MeP core: little-endian, mixed 16/32-bit instructions (a word is 32-bit
iff its top nibble is ≥ 0xC), 16 GPRs (`r0..r12`, `tp`, `gp`, `sp`) plus control
registers. The decoder and lifter follow xyzz's Ghidra SLEIGH
([`ghidra-mep`](https://github.com/xyzz/ghidra-mep), `mep.sinc`); the same logic
is validated in the companion IDA 9.4 processor module. Control-register access,
control-bus (`ldcb`/`stcb`), multiply/divide (`hi:lo`), and CPU-control
instructions that do not map cleanly onto C are printed honestly as pseudo-calls.

## Limitations

* Coprocessor / VLIW (IVC2 etc.) instructions are not modelled (F00D uses the
  core ISA); unknown opcodes print as `<mnem>(...) /* unmodelled */`.
* Entry discovery follows the reset/interrupt vectors and direct calls; indirect
  calls (`jsr (rn)`, jump tables) need seeding with `--entry`.
* Stack-frame recovery is structural (no overlapping-slot coalescing); `hi`/`lo`,
  `sra` and rotates remain intrinsics. Stack-passed arguments (5th+) aren't folded.

## Tests

```
python tests/test_pipeline.py
python tests/test_recover.py
python tests/test_highlight.py
```

Hand-assembled, so they need neither IDA nor a firmware dump: they check decoder
field extraction, that every first word decodes without raising, loop recovery,
stack-frame and boilerplate suppression, parameter/return and pointer-parameter
recovery, call-argument folding, and the token highlighter.

## Credits

Built on the MeP reverse-engineering of TeamMolecule (toshiba-mep-idp), xyzz
(ghidra-mep) and the CGEN MeP description. Decompiler design mirrors zecoxao's
`spudec`. MIT licensed. No firmware is included.
