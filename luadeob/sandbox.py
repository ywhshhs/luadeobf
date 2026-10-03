"""luadeob sandbox — lupa-based Lua/Luau execution sandbox with a full Roblox
environment (see rbxenv.py) and a structured capture system.

Agent-facing API:
    sb = Sandbox(fetch_real=False, fs_root=None, instr_budget=3e8)
    sb.run(source)                 -> (ok: bool, error: str|None)
    sb.drain()                     -> dict of everything captured so far
    sb.vfs_dump(dir)               -> write captured writefile() files to disk
Captures: loadstring payloads, HTTP (urls/bodies), file writes, teleports,
clipboard, genv writes, handler/task errors, dispatch traces.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import uuid

from .rbxenv import VirtualFS, real_fetch

try:
    import lupa
    HAVE_LUPA = True
except ImportError:      # lupa is optional: static-only passes work without it
    HAVE_LUPA = False

DEFAULT_INSTR_BUDGET = 1_000_000_000   # instruction countdown
DEFAULT_WALL_TIMEOUT = 8.0             # seconds per run (hard cap)


class Sandbox:
    def __init__(self, fetch_real=False, fs_root=None, instr_budget=DEFAULT_INSTR_BUDGET,
                 wall_timeout=DEFAULT_WALL_TIMEOUT):
        self.fetch_real = bool(fetch_real)
        self.fs = VirtualFS(fs_root)
        self.instr_budget = instr_budget
        self.wall_timeout = wall_timeout
        if not HAVE_LUPA:
            raise RuntimeError("lupa is not installed — dynamic passes unavailable (pip install lupa)")
        self.rt = lupa.LuaRuntime(unpack_returned_tuples=True)
        self._captures = {
            "payloads": [],   # {src, chunk, depth}
            "urls": [],       # {url, kind, body}
            "writes": [],     # {path, size}
            "notes": [],      # {kind, value}
            "errors": [],
        }
        self._depth = 0
        self._url_cache = {}
        self._setup()

    # ------------------------------------------------------------------ setup
    def _setup(self):
        rt, G = self.rt, self.rt.globals()
        G["PYLOAD"] = self._cap_payload
        G["PYHTTP"] = self._cap_http
        G["PYWRITE"] = self._cap_write
        G["PYNOTE"] = self._cap_note
        G["PYDISP"] = self._cap_disp
        G["PYJSON"] = self._pyjson
        G["PYGUID"] = lambda b=False: str(uuid.uuid4()).upper() if b else str(uuid.uuid4())
        G["PYB64"] = self._pyb64
        G["HTTP_FETCH_REAL"] = self.fetch_real
        G["VFS"] = self.fs
        G["real_fetch"] = real_fetch
        self.rt.execute(_STD())

    # ------------------------------------------------------------- capture cb
    def _cap_payload(self, src, chunk=None):
        if isinstance(src, (str, bytes)) and len(src) > 0:
            self._captures["payloads"].append({"src": src, "chunk": str(chunk or ""), "depth": self._depth})
        return True

    def _cap_http(self, url, kind="http", body=None):
        entry = {"url": str(url), "kind": str(kind), "body": body}
        self._captures["urls"].append(entry)
        if self.fetch_real and isinstance(url, str) and url.startswith(("http://", "https://")):
            # dedupe: a script can hammer the same URL dozens of times
            if url in self._url_cache:
                fetched = self._url_cache[url]
            else:
                fetched = real_fetch(url)
                self._url_cache[url] = fetched
            entry["fetched_size"] = len(fetched)
            entry["fetched_body"] = fetched
            return fetched
        return "return 'luadeob sandbox mock'"

    def _cap_write(self, path, content):
        size = len(content) if isinstance(content, (str, bytes)) else 0
        self._captures["writes"].append({"path": str(path), "size": size})
        return True

    def _cap_note(self, kind, value=None):
        self._captures["notes"].append({"kind": str(kind), "value": _to_str(value)})
        return True

    def _cap_disp(self, vmid, op, pc):
        tr = self._captures.setdefault("dispatch", {})
        key = str(vmid)
        d = tr.setdefault(key, {"ops": {}, "total": 0})
        d["ops"][str(op)] = d["ops"].get(str(op), 0) + 1
        d["total"] += 1
        return True

    def _pyjson(self, obj, encode):
        try:
            if encode:
                return json.dumps(_lua_to_py(obj), ensure_ascii=False)
            return json.loads(obj)
        except Exception as e:  # noqa: BLE001
            return {"__json_error": str(e)}

    @staticmethod
    def _pyb64(s, encode):
        try:
            if encode:
                return base64.b64encode(s.encode() if isinstance(s, str) else s).decode()
            return base64.b64decode(s).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return ""

    # -------------------------------------------------------------------- run
    def run(self, source, chunkname="luadeob"):
        """Execute a Lua/Luau chunk in the sandbox. Returns (ok, error).
        Handles CONCATENATED chunks (layered loaders glue multiple
        `return(function(...)...)(...)` chunks into one file): each chunk is
        detected and run sequentially."""
        chunks = _split_chunks(source)
        if len(chunks) > 1:
            ok_all, last_err = True, None
            for i, chunk in enumerate(chunks):
                ok, err = self._run_one(chunk, f"{chunkname}#{i + 1}")
                ok_all &= ok
                last_err = err or last_err
            return ok_all, last_err
        return self._run_one(source, chunkname)

    def _run_one(self, source, chunkname):
        G = self.rt.globals()
        G["LUADEOB_SRC"] = source
        G["LUADEOB_CHUNK"] = chunkname
        hook = ""
        if self.instr_budget or self.wall_timeout:
            # countdown + wall-clock hook: errors only when the TOTAL budget is
            # exhausted OR the wall deadline passes. (a periodic-error hook
            # would kill legitimate long VM decrypts)
            step = 100_000
            budget = self.instr_budget or 2 ** 62
            hook = ("local okh = pcall(function() local remaining = %d "
                    "local deadline = os.clock() + %s "
                    "debug.sethook(function() remaining = remaining - %d "
                    "if remaining <= 0 then error('luadeob: sandbox instruction "
                    "budget exceeded') end "
                    "if os.clock() > deadline then error('luadeob: sandbox wall "
                    "timeout') end end, '', %d) end)"
                    % (budget, repr(float(self.wall_timeout or 1e9)), step, step))
        script = f"""
{hook}
local ok, err = pcall(function()
  local f, cerr = load(LUADEOB_SRC, LUADEOB_CHUNK)
  if not f then error('compile: ' .. tostring(cerr), 0) end
  f()
end)
pcall(function() debug.sethook() end)
if not ok then PYNOTE('runtime_error', tostring(err)) end
return ok, err
"""
        try:
            ok, err = self.rt.execute(script)
            if not ok and err and "compile:" in str(err):
                # Luau-only syntax (+=, continue, ...): transform + retry once
                compat = _luau_compat(source)
                if compat != source:
                    G["LUADEOB_SRC"] = compat
                    ok, err = self.rt.execute(script)
            return bool(ok), None if ok else str(err)
        except Exception as e:  # noqa: BLE001
            return False, str(e)

    def run_payload(self, src, depth=0):
        """Run a captured payload as the next layer (records depth)."""
        self._depth = depth
        return self.run(src, chunkname=f"layer{depth}")

    def run_isolated(self, src, depth=0, wall_timeout=None):
        """Run in a KILLABLE subprocess (survives pcall-loop hangs, recursion
        bombs and segfaults). Returns dict: ok/err/urls/writes/notes/payloads.
        Payloads land in a temp dir as .lua files."""
        import subprocess
        import tempfile

        wall = wall_timeout or self.wall_timeout
        tmpdir = tempfile.mkdtemp(prefix="luadeob_run_")
        cmd = [sys.executable, "-m", "luadeob.worker",
               "--instr", str(self.instr_budget), "--wall", str(wall),
               "--tmpdir", tmpdir, "--depth", str(depth)]
        if self.fetch_real:
            cmd.append("--fetch")
        if self.fs.root:
            cmd += ["--fs-root", self.fs.root]
        proc = None
        try:
            proc = subprocess.run(cmd, input=src.encode("utf-8", "replace"),
                                  capture_output=True, timeout=wall + 2)
        except subprocess.TimeoutExpired:
            if proc is not None:
                proc.kill()
            return {"ok": False, "err": f"wall timeout ({wall}s): worker killed",
                    "urls": [], "writes": [], "notes": [], "payloads": [],
                    "teleports": [], "queued_on_teleport": [], "clipboard": [],
                    "tmpdir": tmpdir}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "err": f"worker spawn failed: {e}", "urls": [],
                    "writes": [], "notes": [], "payloads": [], "teleports": [],
                    "queued_on_teleport": [], "clipboard": [], "tmpdir": tmpdir}
        result = {"tmpdir": tmpdir, "urls": [], "writes": [], "notes": [],
                  "payloads": [], "teleports": [], "queued_on_teleport": [],
                  "clipboard": [], "ok": False, "err": "no worker output"}
        if proc.stdout:
            try:
                out = json.loads(proc.stdout.decode("utf-8", "replace").strip().splitlines()[-1])
                result.update(out)
            except Exception as e:  # noqa: BLE001
                result["err"] = f"worker output parse failed: {e}"
        if proc.stderr:
            err_txt = proc.stderr.decode("utf-8", "replace")[-500:]
            if err_txt.strip() and not result["ok"]:
                result["err"] = (result.get("err") or "") + " | stderr: " + err_txt
        return result

    # ----------------------------------------------------------------- drain
    def drain(self):
        """Return all captures (and reset accumulators except vfs)."""
        caps = self._captures
        self._captures = {"payloads": [], "urls": [], "writes": [], "notes": [], "errors": []}
        out = {
            "payloads": [{"src": p["src"], "chunk": p["chunk"], "depth": p["depth"],
                          "size": len(p["src"]), "sha256": _sha(p["src"])} for p in caps["payloads"]],
            "urls": [{"url": u["url"], "kind": u["kind"], "fetched": u.get("fetched_size"),
                      "fetched_body": u.get("fetched_body")} for u in caps["urls"]],
            "writes": caps["writes"],
            "notes": caps["notes"],
            "dispatch": self._captures.pop("dispatch", {}) if "dispatch" in self._captures else caps.get("dispatch", {}),
        }
        # summarize notes for the report
        out["teleports"] = [n["value"] for n in caps["notes"] if n["kind"] == "teleport"]
        out["clipboard"] = [n["value"] for n in caps["notes"] if n["kind"] == "clipboard"]
        out["queued_on_teleport"] = [n["value"] for n in caps["notes"] if n["kind"] == "teleport_queue"]
        out["runtime_errors"] = [n["value"] for n in caps["notes"] if n["kind"] == "runtime_error"]
        out["handler_errors"] = [n["value"] for n in caps["notes"] if n["kind"] == "task_error"]
        out["prop_writes"] = [n["value"] for n in caps["notes"] if n["kind"] == "prop"]
        return out

    # ------------------------------------------------------------------- vfs
    def vfs_dump(self, outdir):
        """Write captured writefile() contents to disk; returns list of paths."""
        os.makedirs(outdir, exist_ok=True)
        paths = []
        for path, content in self.fs.writes.items():
            safe = path.replace("\\", "_").replace("/", "_").replace("..", "_")
            if not safe:
                safe = "_root"
            full = os.path.join(outdir, "fs", safe)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(full, mode) as f:
                f.write(content)
            paths.append(full)
        return paths


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

_CHUNK_MARKER = re.compile(r"(?m)^(?:return\s*\(|return\s*\{|local init = \(function|return\(\{)")


def _split_chunks(src):
    """Split concatenated top-level chunks at line-start `return(` markers,
    greedy-merging until every piece compiles (falls back to raw pieces)."""
    markers = [m.start() for m in _CHUNK_MARKER.finditer(src)]
    if len(markers) <= 1:
        return [src]
    pieces = []
    for i, s in enumerate(markers):
        e = markers[i + 1] if i + 1 < len(markers) else len(src)
        pieces.append(src[s:e].strip("\n"))
    # greedy merge for pieces that don't compile alone
    import lupa
    rt = lupa.LuaRuntime()
    loader = rt.eval('function(s) local g = load(s); return g ~= nil end')
    merged = [pieces[0]]
    for p in pieces[1:]:
        if loader(merged[-1]):
            merged.append(p)
        else:
            merged[-1] = merged[-1] + "\n" + p
    return merged


def _sha(text):
    import hashlib
    if isinstance(text, str):
        text = text.encode("utf-8", "replace")
    return hashlib.sha256(text).hexdigest()[:16]


def _to_str(v):
    if v is None:
        return None
    if isinstance(v, str):
        return v[:2000]
    try:
        return str(v)[:2000]
    except Exception:  # noqa: BLE001
        return None


def _is_lua_table(obj):
    return HAVE_LUPA and type(obj).__name__.endswith("LuaTable")


def _lua_to_py(obj):
    """Convert a Lua table (lupa._LuaTable) to Python recursively."""
    if not _is_lua_table(obj):
        return obj
    out = {}
    for k, v in obj.items():
        out[str(k)] = _lua_to_py(v)
    # listify if all-numeric keys 1..n
    if out and all(k.isdigit() for k in out):
        items = [(int(k), v) for k, v in out.items()]
        items.sort()
        return [v for _, v in items]
    return out


def _STD():
    """Concatenate the Lua environment sources."""
    from . import rbxenv
    return (rbxenv._DATATYPES_LUA + "\n" + rbxenv._STDLIB_LUA + "\n"
            + rbxenv._ENV_LUA + "\n" + _GLUE_LUA)


# Glue: install the dispatch-trace hook used by the dispatch pass, and finish
# the service/global wiring that needs everything above defined.
_GLUE_LUA = r"""
-- globals that obfuscated scripts commonly read at load time
getgenv().game = game
getgenv().workspace = workspace
getgenv().script = script
getgenv().Instance = Instance
getgenv().Enum = Enum
getgenv().Vector3 = Vector3
getgenv().Vector2 = Vector2
getgenv().CFrame = CFrame
getgenv().Color3 = Color3
getgenv().UDim = UDim
getgenv().UDim2 = UDim2
getgenv().TweenInfo = TweenInfo
getgenv().NumberRange = NumberRange
getgenv().NumberSequence = NumberSequence
getgenv().ColorSequence = ColorSequence
getgenv().task = task
getgenv().Players = Players
getgenv().RunService = RunService
getgenv().HttpService = HttpService
getgenv().TweenService = TweenService
getgenv().ReplicatedStorage = ReplicatedStorage
getgenv().StarterGui = StarterGui
getgenv().CoreGui = CoreGui
getgenv(). Lighting = Lighting
getgenv().MarketplaceService = MarketplaceService
getgenv().TeleportService = TeleportService
getgenv().Stats = Stats
getgenv().UserInputService = UserInputService
getgenv().bit32 = bit32
getgenv().websocket = websocket
getgenv().request = request
getgenv().syn = syn
getgenv().http = http
getgenv().crypt = crypt
getgenv().loadstring = loadstring
getgenv().writefile = writefile
getgenv().readfile = readfile
getgenv().isfile = isfile
getgenv().identifyexecutor = identifyexecutor
getgenv().checkcaller = checkcaller
getgenv().queue_on_teleport = queue_on_teleport
getgenv().setclipboard = setclipboard
getgenv().getconnections = getconnections
getgenv().firetouchinterest = firetouchinterest
getgenv().fireclickdetector = fireclickdetector
getgenv().hookfunction = hookfunction
getgenv().hookmetamethod = hookmetamethod
getgenv().newcclosure = newcclosure
getgenv().getrawmetatable = getrawmetatable
getgenv().setreadonly = setreadonly
getgenv().iscclosure = iscclosure
getgenv().islclosure = islclosure
getgenv().clonefunction = clonefunction
getgenv().gethui = gethui
"""


# ----------------------------------------------------------------------------
# Luau -> Lua 5.5 compatibility transform (fallback, applied on compile error)
# ----------------------------------------------------------------------------

import re as _re2

_COMPOUND_OPS = ("+", "-", "*", "/", "%", "^", "..")


_BACKTICK_WARNED = False


def _rewrite_interp(text):
    """Luau string interpolation `text {expr} more` -> "text " .. tostring(expr) .. " more"."""
    if "`" not in text:
        return text, 0
    out = []
    i, n = 0, len(text)
    count = 0
    while i < n:
        c = text[i]
        if c == '`':
            j = i + 1
            parts = []          # ('lit', s) | ('expr', s)
            buf = []
            closed = False
            while j < n:
                if text[j] == '\\' and j + 1 < n:
                    buf.append(text[j:j + 2]); j += 2; continue
                if text[j] == '`':
                    closed = True
                    break
                if text[j] == '{':
                    depth, k = 1, j + 1
                    while k < n and depth:
                        if text[k] == '{':
                            depth += 1
                        elif text[k] == '}':
                            depth -= 1
                        elif text[k] in '"\'':
                            q = text[k]; k += 1
                            while k < n and text[k] != q:
                                k += 2 if text[k] == '\\' else 1
                        k += 1
                    if buf:
                        parts.append(('lit', ''.join(buf))); buf = []
                    if depth == 0:
                        parts.append(('expr', text[j + 1:k - 1]))
                        j = k
                    else:
                        j = k
                    continue
                buf.append(text[j]); j += 1
            if not closed:  # unterminated: leave verbatim
                out.append(text[i:j] if j < n else text[i:])
                i = j + 1 if j < n else n
                continue
            if buf:
                parts.append(('lit', ''.join(buf)))
            lua_parts = []
            for kind, t2 in parts:
                if kind == 'lit':
                    esc = t2.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                    lua_parts.append('"%s"' % esc)
                else:
                    lua_parts.append('tostring(%s)' % t2)
            out.append('(' + ' .. '.join(lua_parts) + ')' if lua_parts else '""')
            count += 1
            i = j + 1
            continue
        out.append(c)
        i += 1
    return ''.join(out), count


_EXPR_IF_AHEAD = _re2.compile(r"(?<=[=(,{\[])\s*if\b|(?<=\breturn\s)if\b")
_BLOCK_OPEN = {"function", "if", "for", "while", "do", "repeat"}
_BLOCK_CLOSE = {"end", "until"}
_SCAN_TERMINATOR_WORDS = {"then", "elseif", "else", "end", "do", "until", "and", "or", "in"}


def _scan_expr(text, i, stop_words=(), stop_chars=()):
    """Scan a Lua expression from i. Depth/string aware; block keywords adjust
    depth so `function() end` inside an expression doesn't confuse terminators.
    Returns (end_index, terminator_found_or_None)."""
    n = len(text)
    depth = 0
    while i < n:
        c = text[i]
        if c in '"\'':
            q = c
            i += 1
            while i < n and text[i] != q:
                i += 2 if text[i] == '\\' else 1
            i += 1
            continue
        if c == '`':
            # Luau string interpolation literal: skip to the matching backtick
            i += 1
            while i < n and text[i] != '`':
                i += 2 if text[i] == '\\' else 1
            i += 1
            continue
        if text.startswith('[[', i) or text.startswith('[=', i):
            from . import luatokens as _lt
            e = _lt._longstring_end(text, i)
            if e is not None:
                i = e
                continue
        if c in '({[':
            depth += 1
            i += 1
            continue
        if c in ')}]':
            if depth == 0:
                return i, c if c in stop_chars else None
            depth -= 1
            i += 1
            continue
        if depth == 0 and c in stop_chars:
            return i, c
        if depth == 0 and c == "\n":
            return i, "\n"
        if text.startswith('--', i):
            j = text.find('\n', i)
            i = n if j == -1 else j
            continue
        m = _re2.match(r'[A-Za-z_]\w*', text[i:])
        if m:
            w = m.group(0)
            if depth == 0 and w in stop_words:
                return i, w
            if w in _BLOCK_OPEN:
                depth += 1
            elif w in _BLOCK_CLOSE:
                depth -= 1
            i += len(w)
            continue
        i += 1
    return n, None


def _rewrite_ifexpr(text):
    """Luau if-expressions (no trailing `end`):
        `x = if C1 then A elseif C2 then B else C`
      -> `x = (function() if C1 then return A elseif C2 then return B else return C end)()`
    NESTED if-exprs are handled innermost-first (last match in source order),
    so an outer rewrite never swallows an inner one's `end`."""
    total = 0
    while total < 2000:
        matches = list(_EXPR_IF_AHEAD.finditer(text))
        if not matches:
            break
        progressed = False
        for m in reversed(matches):
            if_at = text.index("if", m.start())
            result = _try_one_ifexpr(text, if_at)
            if result is None:
                continue  # this one doesn't parse (yet); try an inner/other one
            text, n = result
            total += n
            progressed = True
            break
        if not progressed:
            break
    return text, total


def _try_one_ifexpr(text, if_at, consume_trailing_end=False):
    """Rewrite one if-expression at if_at to an and/or chain.
    consume_trailing_end=True (used when the if-expr is itself a branch value
    of an outer if-expr, Luraph dialect): the trailing `;end` that closed THIS
    if-expr is consumed so it doesn't strand inside the outer rewrite.
    Values that are themselves if-exprs are rewritten recursively."""
    cond_end, t1 = _scan_expr(text, if_at + 2, stop_words={"then"})
    if t1 != "then":
        return None
    cond = text[if_at + 2:cond_end].strip()
    stop_w = {"elseif", "else", "end", "do", "then", "until"}
    stop_c = (";", ",", ")", "]", "}")
    val_end, term = _scan_expr(text, cond_end + 4, stop_w, stop_c)
    branches = [(cond, text[cond_end + 4:val_end].strip())]
    els = None
    guard = 0
    while term == "elseif" and guard < 100:
        guard += 1
        c2_end, t2 = _scan_expr(text, val_end + 6, stop_words={"then"})
        if t2 != "then":
            return None
        v_end, term = _scan_expr(text, c2_end + 4, stop_w, stop_c)
        branches.append((text[val_end + 6:c2_end].strip(), text[c2_end + 4:v_end].strip()))
        val_end = v_end
    if term == "else":
        else_end, _t3 = _scan_expr(text, val_end + 4, stop_w, stop_c)
        els = text[val_end + 4:else_end].strip()
        consumed = else_end
    elif term in stop_c or term is None or term == "end":
        # statement boundary / enclosing end / EOF: value already scanned
        consumed = val_end
        els = None
        if term == "end" and not consume_trailing_end:
            pass  # `end` belongs to an enclosing block and stays in place
    else:
        return None
    if consume_trailing_end and consumed < len(text):
        m2 = _re2.match(r"\s*;\s*end\b", text[consumed:])
        if m2:
            consumed += m2.end()
    # recurse: branch values that are themselves if-exprs (Luraph: `else if C then V2 ... ;end`)
    for bi, (c2, v2) in enumerate(branches):
        if v2.startswith("if "):
            sub = _try_one_ifexpr(v2, 0, consume_trailing_end=True)
            if sub is not None:
                branches[bi] = (c2, sub[0])
    if els and els.startswith("if "):
        sub = _try_one_ifexpr(els, 0, consume_trailing_end=True)
        if sub is not None:
            els = sub[0]
    # and/or form: balance-preserving (adds NO `end` tokens, so the enclosing
    # block structure stays exactly in place). Semantics note: `c and v or e`
    # returns e when v is falsy — acceptable for sandbox-parse purposes.
    chain = f"(({branches[0][0]}) and ({branches[0][1]})"
    depth_extra = 0
    for c2, v2 in branches[1:]:
        chain += f" or (({c2}) and ({v2})"
        depth_extra += 1
    if els is not None:
        chain += f" or ({els})"
    chain += ")" * (1 + depth_extra)
    return text[:if_at] + chain + text[consumed:], 1


def _luau_compat(src):
    """Bridge the two Luau-only constructs obfuscated scripts actually use:
    1. compound assignment  x += y   ->  x = x + (y)
    2. `continue` statement ->  goto <label> + ::<label>:: before block end
    Conservative: string/comment segments are left verbatim (via luatokens)."""
    from . import luatokens as T
    toks = list(T.segments(src))
    parts = []
    changed = False
    for kind, a, b in toks:
        if kind != "code":
            parts.append(src[a:b])
            continue
        text = src[a:b]
        text, n0 = _rewrite_interp(text)
        text, n5 = _rewrite_ifexpr(text)
        text, n1 = _rewrite_compound(text)
        text, n2 = _rewrite_continue(text)
        # `goto` is a Lua 5.5 keyword but a valid IDENTIFIER in Luau
        # (function X.goto(...), X.goto(...), local goto = ...). Detect by the
        # following char: keyword-goto is followed by a label identifier.
        text, nf = _RE_GOTO_FUNCDEF.subn(r"\1goto_", text)
        text, nm = _RE_GOTO_MEMBER.subn('["goto"]', text)
        text, ni = _RE_GOTO_IDENT.subn("goto_", text)
        n3 = nf + nm + ni
        if n0 or n1 or n2 or n3 or n5:
            changed = True
        parts.append(text)
    if not changed:
        return src
    return "".join(parts)


_IDENT_TAIL = _re2.compile(r"[\w\.\[\]\(\)\"']+\s*")


def _rewrite_compound(text):
    """Rewrite `LHS op= RHS` -> `LHS = LHS op (RHS)`. RHS scanning is
    string/depth aware via _scan_expr (stops at `;`, statement boundaries,
    or depth-0 closers like `,`/`)` that belong to the enclosing context)."""
    count = 0
    out = []
    i = 0
    n = len(text)
    pat = _re2.compile(r"([\w\]\)\"'])(\s*)(\+|-|\*|/|%|\^|\.\.)(=)(?![~=<>])")
    while i < n:
        m = pat.search(text, i)
        if not m:
            out.append(text[i:])
            break
        lhs_end = m.start() + 1  # include the LHS's last char
        # expand LHS backwards: identifier chars, dots, brackets (balanced), quotes.
        # depth starts at 1 when the matched LHS char is a closer (it is one half
        # of a bracket pair; the loop below must consume its opener).
        j = m.start()
        depth = 1 if m.group(1) in ')]}' else 0
        while j > 0:
            ch = text[j - 1]
            if ch in ')]}':
                depth += 1
                j -= 1
            elif ch in '([{':
                if depth == 0:
                    break
                depth -= 1
                j -= 1
            elif depth > 0 or ch.isalnum() or ch in '._\"\'':
                j -= 1
            else:
                break
        lhs = text[j:m.start() + 1].strip()
        op = m.group(3)
        # find RHS end (after the `op=`)
        rhs_start = m.end()
        rhs_end, _term = _scan_expr(text, rhs_start,
                                    stop_words={'end', 'then', 'do', 'else',
                                                'elseif', 'until', 'and', 'or'},
                                    stop_chars=(';',))
        # `and`/`or` at depth 0 are PART of the expression; _scan_expr stops at
        # them only if listed — we listed them, so re-extend: simplest is to not
        # stop there. Redo without and/or:
        rhs_end, _term = _scan_expr(text, rhs_start,
                                    stop_words={'end', 'then', 'do', 'else',
                                                'elseif', 'until'},
                                    stop_chars=(';',))
        if rhs_end <= rhs_start:
            out.append(text[i:m.end()])
            i = m.end()
            continue
        rhs = text[rhs_start:rhs_end].strip()
        out.append(text[i:j])
        out.append(f"{lhs} = {lhs} {op} ({rhs})")
        count += 1
        i = rhs_end
    return ''.join(out), count


_CONT_WORD = _re2.compile(r"(?<![\w.])continue(?![\w.])")


def _rewrite_continue(text):
    """`continue` -> `goto <label>` + ::<label>:: before the enclosing block end.
    All scanning is done in slice-relative space to avoid offset bugs."""
    count = 0
    matches = list(_CONT_WORD.finditer(text))
    if not matches:
        return text, 0
    for m in reversed(matches):
        tail = text[m.end(): m.end() + 20_000]  # window: block end is nearby
        depth = 0
        insert_rel = None              # offset in `tail` to insert label before
        for _kind, a, b in _token_words(tail):
            w = tail[a:b]
            if w in ("function", "if", "for", "while", "do", "repeat", "{"):
                depth += 1
            elif w in ("end", "until", "}"):
                if depth == 0:
                    insert_rel = a
                    break
                depth -= 1
        label = f"luadeob_cont{m.start()}"
        head = text[:m.start()] + f"goto {label}"
        if insert_rel is None:
            text = head + tail
        else:
            text = head + tail[:insert_rel] + f" ::{label}:: " + tail[insert_rel:]
        count += 1
    return text, count


_WORD = _re2.compile(r"\w+|\{")


def _token_words(text):
    """Yield (kind, start, end) of words/block tokens in text (no strings)."""
    for m in _WORD.finditer(text):
        yield ("word", m.start(), m.end())


# keyword-goto is always followed by a label identifier; identifier-goto is not.
# member access X.goto(...) must become X["goto"](...) (goto is a Lua keyword).
_RE_GOTO_FUNCDEF = _re2.compile(r"(function\s+(?:[\w.]+\.)?)goto(?!\s*\w)")
_RE_GOTO_MEMBER = _re2.compile(r"\.\s*goto(?!\s*\w)")
_RE_GOTO_IDENT = _re2.compile(r"(?<![\w.\"\'\[])goto(?!\s*\w)")
