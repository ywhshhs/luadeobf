# STATUS — current task, what's working, what's being fixed

_Updated: end of build session (levels 6-10 just added)_

## ✅ DONE and verified

| Item | Status |
|---|---|
| luadeob framework (8 passes, 12 profiles, learn mode, JSON reports) | ✅ working |
| Full Roblox sandbox env (game/services/Instance/datatypes/Enum/executor globals) | ✅ working |
| Killable worker subprocess (wall-timeout = hard kill, survives pcall-loop bombs) | ✅ working (kills at exactly wall seconds) |
| Luau→Lua5.5 compat (+=, continue→goto+label, goto-as-identifier, string interp, if-expr→and/or) | ✅ working for tested cases |
| Clyde 17-layer chain full peel incl. real remote fetch | ✅ 12s |
| FlowAuth loader (message.txt) → 680KB Luraph v15 payload captured | ✅ 4s |
| Luraph detection 1.0 on all 5 upstream repo samples | ✅ |
| Samples L1-L5 | ✅ all print + all recovered by deobf |
| L7 (4-layer chain: arith-array → running-key XOR → reverse+add → final) | ✅ prints; deobf peels it |
| sandbox print/warn capture (samples.printed in report) | ✅ |
| XOR key hunt with alnum-ratio tiebreak ranking | ✅ |

## 🔧 CURRENT TASK (in progress, not finished)

**Levels 6, 8, 9, 10 samples don't run yet** — 4 open bugs:

### L6 — `')' expected (to close '(' at ...)` (compile, line ~12)
- Diagnosis: the `esc()`-based `print({esc('nope')})` line was fixed (double-quote
  bug), but the compile error persists at the flattened state-machine loop.
- Likely: the `continue` inside the `elseif` state branch + the compat's
  continue→goto+label rewrite interacting with the state loop's `end` chain —
  the label gets inserted before the wrong `end` (the `_rewrite_continue`
  scan-window = 20k chars, block-tracking counts `if/for/while/do/repeat/{`
  opens; the flattened loop's elseif-chain may confuse the depth counter).
- Next step: reproduce minimal (flattened loop + continue in elseif branch),
  fix `_rewrite_continue` block tracking, or sidestep in the sample.

### L8 — `')' expected near ','` (compile, line 12 — the if-expr line)
- Diagnosis: FIXED the root cause in `_scan_expr` (backtick strings now
  skipped; depth-0 newline is a stop) and `term=None` now REJECTS the rewrite
  (was: accepted with consumed=val_end → partial rewrite across segments →
  `((9*9>9) and (string.rep())"!",0)` corruption).
- The last patch to `_luau_compat` FAILED TO APPLY (AssertionError — the
  `elif term in stop_c or term is None:` block text didn't match exactly).
  **The fix is written, just needs to be applied.** Look for the
  `# term=None (else-expr ran to EOF) is accepted as-is` comment block in
  luadeob/sandbox.py inside `_try_one_ifexpr` and replace it with a rejecting
  branch (term in stop_c → accept; term None/unexpected → return None).

### L9 — `bad argument #1 to 'byte' (string expected)` (runtime, outer VM)
- Diagnosis: the outer VM's LOADK decode `string.byte(s,j)` gets a non-string
  — either `R[b]` in APPEND picks an empty reg (prog built as
  `[(3,1)] + [(1,2,i+1),(2,1,2)]...` — APPEND is `{acc}..R[a]..R[b]` with
  a=1,b=2 — but reg 2 holds the DECODED piece only after LOADK... the acc
  chain may be mis-ordered), or a pool index decrypts wrong.
- Next step: simplify outer prog to explicit `LOADK → APPEND(acc, reg)` pairs
  with the acc in a FIXED reg (e.g. reg 9), debug decrypt positions.

### L10 — `sandbox instruction budget exceeded` (infinite loop)
- Diagnosis: ops encode now uses `inv[v] ^ pk(...)` (VM decodes with `sbox`)
  which is correct, constants decode `sbox[enc ^ pk(j)] ^ k` — BUT the
  constant encoding used `pk(j + 1)` (1-indexed) while the decode uses `pk(j)`
  → **off-by-one key mismatch on constants** → garbage chars (harmless), AND
  the real loop-killer: if any op decrypts wrong (check `inv` vs `sbox`
  direction!) the pc never advances → infinite loop → budget kill.
- Next step: align constant decode to `pk(j + 1)`; verify op decode
  direction; if still looping, add a debug print of the first 3 decoded ops
  and compare with the assembled program.

## Known framework limitations (by design / documented)

1. **Luraph v15 `else …;end;elseif` dialect** — no Lua 5.5 parser accepts it;
   those layers are captured + statically analyzed but not executed. Full
   execution needs a real Luau runtime (see upstream Deobfuscator-Luraph-V15:
   luau.exe + IPC REPL).
2. lupa is Lua 5.5 — Luau-only syntax needs the compat layer (handled:
   `+=`, `continue`, `goto`-as-id, string interp, if-exprs; NOT handled:
   elseif-after-else, type annotations).
3. Sandbox `Wait()` on signals returns immediately (won't hang, but
   event-driven scripts won't replay real timing).
4. `vm_static` opcode semantics are the recovered Lua 5.1-style handler set
   (Clyde-shape); other VM dialects need their own handler maps.

## Next steps after the 4 fixes

- Regenerate + verify levels 6-10 print, then run each through
  `python3 -m luadeob obf_samples/levelN.lua --json` and record what recovers
  at difficulty 6-10 (vm_static should light up on L10's `A+i*B+i²*C` chain).
- Add the `dispatch` pass opcode-trace wiring (currently the trace summary is
  only populated when the dispatch pass itself runs the sandbox).
