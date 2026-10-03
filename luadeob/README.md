# luadeob — versatile Luau/Lua deobfuscator (Python)

Pluggable, profile-driven deobfuscation framework for Roblox Luau scripts.
Built to be **molded** to any obfuscation and **driven by AI agents** (CLI with
JSON output + Python API + learning mode).

```
┌──────────────┐   ┌─────────────────────────────────────────────┐
│ fingerprint  │──▶│ pass pipeline (strings → fold → beautify →  │
│ (what is it?)│   │ peel → xor → dispatch → rename → vm_static) │
└──────────────┘   └─────────────────────────────────────────────┘
                            │            │
                     JSON report    deobfuscated.lua
```

## Quick start (CLI)

```bash
python3 -m luadeob script.lua                      # auto-detect + auto passes
python3 -m luadeob script.lua --json               # agent mode: full JSON report
python3 -m luadeob script.lua --profile luraph     # tuned for Luraph v14/v15
python3 -m luadeob loader.lua --fetch -o out/      # REAL network fetch + layer peel
python3 -m luadeob script.lua --learn --learn-to profile.json   # mold a profile
python3 -m luadeob script.lua --profile-file profile.json       # use molded profile
python3 -m luadeob --list-passes | --list-profiles
python3 -m luadeob - < script.lua --json           # stdin
```

Every run prints/writes: fingerprint (obfuscator + confidence + techniques),
layer chain (peel depth), captured payloads/URLs/file-writes/teleports,
per-pass stats, name suggestions, warnings — all in the JSON report.

## The full Roblox environment (sandbox)

The `peel` pass executes scripts inside a **complete offline Roblox executor
environment** (Lua 5.5 via lupa) — nothing needs a Roblox client:

- **DataModel**: `game`, `game:GetService(...)`, `workspace`, PlaceId/JobId,
  `game:HttpGet/PostAsync` (captured; really fetched only with `--fetch`)
- **Services with real behavior**: Players (+LocalPlayer with Character/
  Humanoid/HumanoidRootPart), RunService (Heartbeat/RenderStepped signals),
  UserInputService, HttpService (JSONEncode/JSONDecode/GetAsync), TweenService
  (Create→tween stub), TeleportService, MarketplaceService (GetProductInfo),
  Stats (ServerStatsItem), ReplicatedStorage/CoreGui/StarterGui/… (auto-vivify)
- **Instance model**: `Instance.new`, auto-vivifying children
  (`ws.Part.Weld.C0` works), WaitForChild/FindFirstChild/IsA/GetAttribute/…
- **Datatypes with real math**: Vector3/Vector2 (Magnitude/Unit/Dot/Cross/
  Lerp), CFrame (lookAt/Angles/fromMatrix, full 3×3 matrix `__mul`,
  PointToWorldSpace), Color3 (RGB/HSV), UDim/UDim2, TweenInfo, NumberRange/
  Sequence, ColorSequence, Rect, Ray, Random, BrickColor, Font, Region3
- **Enum** — auto-vivifying (`Enum.KeyCode.RightControl.Name`)
- **Executor globals**: getgenv/getfenv, request/http_request/syn.request,
  writefile/readfile/isfile/listfiles (virtual FS), queue_on_teleport,
  firetouchinterest/fireclickdetector, hookfunction/hookmetamethod,
  newcclosure/clonefunction, checkcaller, identifyexecutor, setclipboard,
  getconnections, gethui, crypt.base64, websocket
- **Luau stdlib**: variadic bit32 (incl. countlz/countrz/byteswap), table.create
  /find/clear/freeze/move, string.split, string.pack/unpack, utf8 (incl.
  graphemes/nfcnormalize/nfdnormalize — Luraph fingerprints the key set!),
  math.clamp/round/sign/noise, task.spawn/defer/delay/wait, tick

**Hard-gotchas encoded in the sandbox** (learned the hard way):
- `bit32.bxor/band/bor` MUST be variadic — a 2-arg shim corrupts in-flight
  opcode decryption in VM obfuscators → garbage payloads
- do NOT stub `debug` — Clyde's anti-tamper type-checks `debug.info`
- timeouts use a countdown+wall-clock `debug.sethook`, but hostile scripts can
  pcall-catch hook errors — so `peel` runs each layer in a **killable worker
  subprocess** (`luadeob.worker`); deadline is a hard kill, and segfaults
  can't take the host down
- lupa can't iterate Lua tables inside Lua→Python callbacks → JSONEncode is
  pure Lua

## Passes

| pass | what it does |
|---|---|
| `strings` | decode `\xNN`, `\ddd`, `\u{...}` escapes and `string.char(...)` chains → readable literals (string/comment aware) |
| `fold` | constant-fold numeric arithmetic (Lua semantics: `^`=power), string concatenation, redundant parens |
| `beautify` | reindent minified one-liners (header-aware state machine: `local function f(x)`, `for…do`, `repeat/until`); restores the Luraph glued header |
| `peel` | sandboxed recursive layer peeling: captures loadstring payloads, HttpGet bodies (with `--fetch`: real), writefile contents, teleports, queue_on_teleport chunks |
| `xor` | XOR-key hunt on byte-array literals (brute force 0–255, printability-scored; report-only) |
| `dispatch` | find VM dispatch loops (`while true do local op=ARR[PC]` and Luraph v15's direct `if op<=N` shape), count handler branches |
| `rename` | Roblox-API name inference for mangled vars (`_1` ← `GetService("Players")` → `players`); report-only unless `rename.apply` |
| `vm_static` | static VM analysis: auto-detect opcode-decrypt coefficients (`52+m*211+m^2*189` Clyde-style), decrypt opcode stream, Lua 5.1-style disassembly |

## Profiles (molding to a specific obfuscation)

Built-in: `auto`, `full`, `safe`, `strings-only`, `static-only`,
`dynamic-only`, `clyde`, `luraph`, `luraph-aggressive`, `ironbrew`, `moonsec`,
`loader`.

**Mold your own** — `--learn` fingerprints a script and emits a starting
profile; edit it and pass `--profile-file`:

```json
{
  "name": "myobf",
  "description": "custom VM obfuscator, big constant tables",
  "passes": ["strings", "fold", "beautify", "peel", "dispatch", "vm_static"],
  "options": {
    "peel.max_depth": 32,
    "peel.wall_timeout": 8,
    "peel.total_deadline": 60,
    "peel.fetch_real": false,
    "vm_static.opcode_coeffs": [52, 211, 189],
    "strings.min_length": 4,
    "rename.apply": false
  }
}
```

Option keys are `<pass>.<option>`; unprefixed keys apply globally.

## Python API (for agents)

```python
from luadeob import deobfuscate, fingerprint, get_profile

report = deobfuscate(source, profile="luraph")
print(report.summary())          # human-readable
data = report.to_dict()          # JSON-serializable
clean_source = report.final_source

# sandbox directly (full Roblox env):
from luadeob.sandbox import Sandbox
sb = Sandbox(fetch_real=False, wall_timeout=8)
ok, err = sb.run(source)
caps = sb.drain()                # payloads / urls / writes / notes
result = sb.run_isolated(src)    # killable subprocess (hostile scripts)
```

## Luau→Lua compat layer

Lua 5.5 (lupa) can't parse all Luau. On compile failure the sandbox applies a
conservative, string/comment-aware transform and retries:
`+= -= *= /= %= ^=` → expansion; `continue` → `goto`+label; `goto`-as-
identifier → rename / `["goto"]`; string interpolation `` `x{y}z` `` → concat;
if-expressions (`= if c then a else b`, incl. nested/Luraph `;end` dialect) →
balance-preserving `and/or` form (NOTE: `c and v or e` returns `e` when `v` is
falsy — parse-level fidelity, not semantic-exact).

Known limit: Luraph v15's dialect also emits `else …;end; elseif` chains that
no Lua 5.5 parser accepts; those layers are captured + statically analyzed
(dispatch/beautify work on text) but not executed.

## Extending

Subclass `luadeob.core.Pass` (implement `detect()` → 0..1 and `run(ctx)`),
append to `luadeob.passes.ALL`. The pipeline never lets a pass crash the run.
