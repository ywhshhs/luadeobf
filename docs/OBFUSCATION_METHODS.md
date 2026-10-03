# Obfuscation Methods — key notes (what we learnt)

Notes distilled from reverse-engineering real obfuscated Roblox scripts
(Clyde Protection, Luraph v15, FlowAuth loader, custom VM obfuscators) and
building luadeob. Format: technique → how it works → how to defeat it.

---

## 1. String-layer obfuscation

### Escaped literals (`\ddd`, `\xNN`, `\u{...}`)
- Whole strings replaced with escape sequences; often mixed styles per byte
  and combined with `string.char(...)` chains.
- Defeat: safe lexer (never rewrite inside strings/comments), decode with the
  real escape grammar (`\ddd` is up to 3 digits, `\z` skips whitespace),
  rewrite only when the decoded form has LESS escape noise and is printable.

### string.char chains
- `string.char(72,101,...)` with constant args; args may be arithmetic
  expressions (`string.char(65+121)`).
- Defeat: Lua-semantics expression evaluator (`^`=power, `/`=float, `%`=real)
  → fold to a literal.

### XOR tables
- `{n1,n2,...}` byte array + fixed key, decoded at runtime in a loop.
- Defeat (static): brute-force all 256 keys, score printability, then rank
  ties by alnum-ratio (short arrays have many full-score false positives —
  a 23-byte array had 24 keys at score 1.0; alnum ranking put the true key
  first).
- Defeat (dynamic): run it — the decoder loop reveals the plaintext via the
  print hook.

### Running-key XOR (start + step)
- `local a=172 ... o[i]=string.char(byte(s,i)~(a&255)) a=a+161` — key stream
  is position-dependent (a + i*step).
- Defeat: replicate the stream (start/step are in the code); or the generic
  form: for a byte array, for each (start, step) candidate... rarely needed —
  the constants are visible.

### Polynomial position keys (Clyde-style)
- `op = k[m] ^ (A + m*B + m²*C) & 0xFF` — used for BOTH opcode streams and
  constant tables. Detection regex: `\d+\+m\*\d+\+m\*m\*\d+`.
- Defeat: extract A/B/C from the source, decrypt statically; or run the VM
  (the decrypt happens in-flight — capture the loadstring payload).

### SBOX substitution
- Random 256-byte permutation table; encode = `sbox[byte ^ key]`, decode =
  `inv[...]` — but obfuscators sometimes ship ONLY the forward sbox and
  decode with it (meaning encode used the inverse). Watch the direction:
  if encode used `sbox[v]`, decode must use `inv[sbox[v]]`... no — decode
  with the OTHER table than encode used. Symmetric bugs (using sbox for both)
  → garbage → infinite dispatch loops.
- Defeat: build `inv` from the shipped table, match encode/decode directions.

### Base64 blobs
- `base64` blob + hand-written Lua b64 decoder (padding-free, index-map).
- Defeat: detect long b64-looking literals (≥40 chars, decode-validate);
  padding: our Lua decoder outputs 3 bytes per 4 chars — b64 with `=`
  padding needs proper tail handling or pre-padded payloads (len%3==0).

### String interpolation (Luau-only)
- `` `text {expr} more` `` — plain Lua can't parse AT ALL. Compat: split into
  literal/expr parts, rebuild as `"text " .. tostring(expr) .. " more"`.
  Balanced-brace + string-aware scan needed inside `{...}`.

## 2. Control-flow obfuscation

### Layered loadstring chains
- `loadstring(payload)()` recursively; payload may be escaped/XOR'd/b64'd;
  HttpGet remote layers on top. Real loaders (FlowAuth) add checksum gates
  (Adler-32), transport fallbacks (HttpGet + request + IP fallback + retry
  variants), and size checks (`expected=680955`).
- Defeat: sandboxed recursive peel with capture of EVERY loadstring/HttpGet/
  writefile/queue_on_teleport; dedupe by sha256 (two separate domains:
  seen-run vs seen-capture — conflating them skips queued layers!).
- Concatenated chunks: loaders glue multiple `return(function(...)...)(...)`
  chunks into one file — split at line-start `return(` markers, greedy-merge
  until each piece compiles.

### Flattened dispatch loops (VM obfuscators)
- `while true do local op = ARR[PC]; if op<=N then ... end end` (fetch-array
  shape) or Luraph v15's direct `while true do if b<=7 then...` (if-tree on
  the opcode var). Handlers flattened; original while/for/if structures
  destroyed.
- Defeat: handler resolution through the if-tree per opcode value (upstream
  vmmap.py does this via luau-ast); regex detection works on single-line AND
  multiline (make the regex `\s+`-tolerant — beautify splits lines first!).

### Anti-tamper traps
- `checkcaller()` checks, `debug.info` type probes (Clyde compares debug.info
  against numbers — a STRING debug stub aborts the payload decrypt),
  getfenv/environment probes (Luraph fingerprints the utf8 table KEY SET —
  graphemes/nfcnormalize/nfdnormalize must exist), self-checksums with
  `LPH_CRASH()` spin loops.
- Defeat: real debug table (no stub), checkcaller→false, complete env; traps
  that STILL fire: run in a killable subprocess and capture what happened
  before the crash.

### Opaque predicates
- Functions that always return a known value but computed oddly
  (`y==y`, `(x*7+3)%100` chains). Used to gate junk branches.
- Defeat: constant-fold + run; junk branches reveal themselves in trace.

### Compound-assignment / continue / goto-as-identifier (Luau dialect)
- Real Luau emits `x += y`, `continue`, and uses `goto` as an IDENTIFIER
  (Luau has no goto). Lua 5.5 can't parse any of it.
- Defeat (compat layer, string/comment-aware, applied on compile-failure):
  `x += y` → `x = x + (y)`; `continue` → `goto <label>` + `::label::` before
  the block's `end` (scan in slice-relative space!); `goto`-as-id →
  `["goto"]` (member) / `goto_` (bare/funcdef); if-exprs → balance-preserving
  and/or form.

### If-expressions (Luau-only)
- `x = if c then a else b` — no trailing `end`; NESTED ones + Luraph's
  dialect where if-exprs DO take a trailing `;end`. The else-value's extent
  is the hard part (statement boundary vs the IIFE's own call parens vs the
  enclosing `)`).
- Defeat: depth/string/backtick-aware scan; STOP at depth-0 `;,)]}` and
  newline; REJECT term=None (over-consumption across segments corrupts:
  `((cond) and (string.rep())"!",0)`); process NESTED if-exprs innermost-first
  (last match in source order); for Luraph's `;end` dialect, recurse into
  branch values and consume the inner's trailing `;end`.

## 3. Environment/sandbox gotchas (hard-won)

1. `bit32.bxor/band/bor` MUST be variadic — a 2-arg shim corrupts in-flight
   opcode decryption → garbage payloads.
2. NEVER stub `debug` — Clyde's anti-tamper type-checks debug.info.
3. sethook timeouts: use countdown + wall-clock (a periodic-error hook kills
   legitimate long VM decrypts); hostile scripts pcall-catch hook errors →
   the real guarantee is a KILLABLE SUBPROCESS worker.
4. lupa can't iterate Lua tables inside Lua→Python callbacks → pure-Lua JSON.
5. Strings with bytes ≥128 can't cross into Python (lupa decodes UTF-8) →
   Lua-side SANITIZE (escape as \ddd text) on every capture bridge.
6. Payloads must be captured BEFORE anti-tamper checks fire (loadstring hook
   runs before the check in Clyde's flow).
7. Dedupe payloads by sha256 but keep run-queue and capture-queue separate.
8. Byte escaping for generators: latin-1 (never let Python UTF-8-encode
   U+0080-U+00FF chars → `\194\138` double-encoding).
9. rkey() called twice in a generator = encode≠decode keys (classic bug).
10. Checksum gates in loaders: replicate the exact algorithm (Adler-32 with
    the loader's loop shape) or just run through — the gate only gates.

## 4. What recovers at which difficulty (our 10 samples)

| Level | Scheme | Recovered by |
|---|---|---|
| 1 | escaped strings + arith soup | strings pass (static) |
| 2 | XOR table + junk gates | xor hunt (static) + sandbox print |
| 3 | escaped loadstring layer + checksum | peel (2 layers) |
| 4 | base64(XOR) → escaped → final (3 layers) | peel (3 layers, 2 payloads) |
| 5 | register VM, encrypted pool + poly opcodes | sandbox run + print capture |
| 6 | flattened state machine + poly cipher | IN PROGRESS (see STATUS.md) |
| 7 | 4-layer chain, mixed schemes | peel ✅ |
| 8 | Luau dialect abuse | IN PROGRESS (one compat patch unapplied) |
| 9 | VM-in-VM | IN PROGRESS |
| 10 | SBOX + poly + anti-tamper VM | IN PROGRESS |
