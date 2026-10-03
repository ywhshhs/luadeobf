"""luadeob passes — registry of all deobfuscation passes.

Import order matters for the pipeline: strings/fold/beautify are cheap static
passes; peel/dispatch run the sandbox; vm_static/xor are specialized analysis.
"""

import os as _os
import re
import shutil as _shutil
import time as _time

from ..core import Pass


# ----------------------------------------------------------------------------
# strings — decode escaped string literals & string.char() chains
# ----------------------------------------------------------------------------

class StringsPass(Pass):
    name = "strings"
    help = "decode \\xNN/\\ddd/\\u{...} escapes and string.char(...) chains to readable literals"

    def detect(self, ctx):
        fp = ctx.report.fingerprint.get("escapes", {})
        e = fp.get("hex", 0) + fp.get("dec", 0)
        src = ctx.source
        extra = src.count("string.char(") + src.count(".char(")
        return min(1.0, (e + extra * 4) / 40.0)

    def run(self, ctx):
        from .. import luatokens as T
        import re

        src = ctx.source
        min_len = int(self.opt(ctx, "min_length", 4))
        max_len = int(self.opt(ctx, "max_length", 4096))
        out, pos, count, samples = [], 0, 0, []

        for kind, a, b in T.segments(src):
            if a > pos:
                out.append(src[pos:a])
            if kind == "string" and (b - a) >= 2:
                raw = src[a:b]
                try:
                    decoded = T.decode_lua_string(raw)
                except Exception:  # noqa: BLE001
                    decoded = None
                escapes = raw.count("\\")
                if (decoded is not None and min_len <= len(decoded) <= max_len
                        and escapes >= 3 and T.is_mostly_printable(decoded, 0.9)):
                    newlit = T.escape_lua_string(decoded)
                    # only rewrite when it reduces escape noise
                    if newlit.count("\\") < escapes:
                        out.append(newlit)
                        pos = b
                        count += 1
                        if len(samples) < 10:
                            samples.append(raw[:48] + " -> " + decoded[:48])
                        continue
            out.append(src[a:b])
            pos = b
        out.append(src[pos:])
        ctx.source = "".join(out)

        # string.char(72, 101, ...) chains -> literals
        sc_count = self._fold_string_char(ctx)

        ctx.report.strings_decoded += count + sc_count
        ctx.report.add_pass(self.name, applied=True, changed=count + sc_count > 0,
                            stats={"escapes_decoded": count, "string_char_decoded": sc_count},
                            notes=[f"{s}" for s in samples])

    def _fold_string_char(self, ctx):
        """Rewrite string.char(<numeric args>) -> literal. Args may be arithmetic
        expressions, evaluated with Lua semantics."""
        from .. import luatokens as T
        import re
        src = ctx.source
        pat = re.compile(r"\bstring\.char\s*\(([^()]{0,2000}?)\)")
        out, pos, count = [], 0, 0
        for m in pat.finditer(src):
            a, b = m.span()
            # skip matches inside strings/comments
            if not _in_code(src, a):
                continue
            args = _split_args(m.group(1))
            if not args or len(args) > 256:
                continue
            vals = []
            okall = True
            for arg in args:
                v = T.eval_lua_number_expr(arg.strip())
                if v is None or not isinstance(v, (int, float)):
                    okall = False
                    break
                vals.append(int(v) & 0xFF)
            if not okall:
                continue
            text = "".join(chr(v) for v in vals)
            if not T.is_mostly_printable(text, 0.85):
                continue
            out.append(src[pos:a])
            out.append(T.escape_lua_string(text))
            pos = b
            count += 1
        out.append(src[pos:])
        if count:
            ctx.source = "".join(out)
        return count


def _in_code(src, pos):
    from .. import luatokens as T
    for kind, a, b in T.segments(src):
        if kind == "code" and a <= pos < b:
            return True
        if a > pos:
            return False
    return False


def _split_args(s):
    args, depth, cur = [], 0, []
    for ch in s:
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur and "".join(cur).strip():
        args.append("".join(cur))
    return args


# ----------------------------------------------------------------------------
# fold — constant folding (numbers, string concat, redundant parens)
# ----------------------------------------------------------------------------

class FoldPass(Pass):
    name = "fold"
    help = "constant-fold numeric arithmetic, string concatenation, redundant parens"

    def detect(self, ctx):
        src = ctx.source
        import re
        pat = re.compile(r"\(\s*\d+\s*[+\-*/%^]\s*[^()\s][^()]{0,60}?\)")
        hits = len(pat.findall(src[:200_000])) + src.count('".."') + len(
            re.findall(r'"\s*\.\.\s*"', src[:100_000]))
        return min(1.0, hits / 30.0)

    def run(self, ctx):
        import re
        from .. import luatokens as T
        n_num = self._fold_numbers(ctx)
        n_str = self._fold_concat(ctx)
        n_par = self._fold_parens(ctx)
        ctx.report.add_pass(self.name, applied=True, changed=(n_num + n_str + n_par) > 0,
                            stats={"numeric": n_num, "concat": n_str, "parens": n_par})

    def _fold_numbers(self, ctx):
        """Fold (numeric expr) -> number, in code regions only."""
        from .. import luatokens as T
        import re
        src = ctx.source
        pat = re.compile(r"\(([\d.\[\]xXa-fA-F+\-*/%^ ][^()]{0,120}?)\)")
        out, pos, count = [], 0, 0
        for m in pat.finditer(src):
            a, b = m.span()
            inner = m.group(1)
            if not any(op in inner for op in "+-*/%^"):
                continue
            if not _in_code(src, a):
                continue
            v = T.eval_lua_number_expr(inner)
            if v is None or isinstance(v, float) and not v.is_integer():
                continue
            out.append(src[pos:a])
            out.append(T.lua_number_fmt(v))
            pos = b
            count += 1
        out.append(src[pos:])
        if count:
            ctx.source = "".join(out)
        return count

    def _fold_concat(self, ctx):
        """Fold "a".."b".."c" -> "abc" (literals only, code regions)."""
        from .. import luatokens as T
        import re
        src = ctx.source
        pat = re.compile(r'((?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')\s*(?:\.\.\s*(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')\s*)+)')
        out, pos, count = [], 0, 0
        for m in pat.finditer(src):
            a, b = m.span()
            if not _in_code(src, a):
                continue
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', m.group(1))
            try:
                text = "".join(T.decode_lua_string('"' + (p[0] or p[1]) + '"') for p in parts)
            except Exception:  # noqa: BLE001
                continue
            if not T.is_mostly_printable(text, 0.9):
                continue
            out.append(src[pos:a])
            out.append(T.escape_lua_string(text))
            pos = b
            count += 1
        out.append(src[pos:])
        if count:
            ctx.source = "".join(out)
        return count

    def _fold_parens(self, ctx):
        """Collapse ((x)) -> (x) when x has no varargs (safe truncation-wise)."""
        import re
        src = ctx.source
        pat = re.compile(r"\(\s*\(([^()]{0,300}?)\)\s*\)")
        out, pos, count = [], 0, 0
        for m in pat.finditer(src):
            a, b = m.span()
            if "..." in m.group(1) or not _in_code(src, a):
                continue
            out.append(src[pos:a])
            out.append("(" + m.group(1) + ")")
            pos = b
            count += 1
        out.append(src[pos:])
        if count:
            ctx.source = "".join(out)
        return count


# ----------------------------------------------------------------------------
# beautify — reindent minified/one-line code
# ----------------------------------------------------------------------------

class BeautifyPass(Pass):
    name = "beautify"
    help = "reindent minified Lua/Luau (statement-per-line, proper block indentation)"

    def detect(self, ctx):
        src = ctx.source
        if not src:
            return 0.0
        lines = src.count("\n") + 1
        if len(src) > 4000 and lines < 10:
            return 1.0
        avg = len(src) / max(lines, 1)
        if avg > 400:
            return 0.8
        if avg > 160:
            return 0.5
        return 0.1

    def run(self, ctx):
        from .beautify_impl import beautify
        new = beautify(ctx.source)
        changed = new != ctx.source
        if changed:
            ctx.source = new
        ctx.report.add_pass(self.name, applied=True, changed=changed,
                            stats={"lines": new.count("\n") + 1})


# ----------------------------------------------------------------------------
# peel — dynamic sandboxed layer peeling (full Roblox env)
# ----------------------------------------------------------------------------

class PeelPass(Pass):
    name = "peel"
    help = "run the script in the sandboxed Roblox env; capture loadstring payloads, HttpGet urls, file writes, teleports; recursively peel layers"

    def detect(self, ctx):
        import lupa  # noqa: F401
        fp = ctx.report.fingerprint
        tech = fp.get("techniques", {})
        score = 0.3
        if "loadstring_chain" in tech:
            score += 0.4
        if "http_loader" in tech or "webhook" in tech:
            score += 0.3
        return min(1.0, score)

    def run(self, ctx):
        from ..sandbox import Sandbox
        max_depth = int(self.opt(ctx, "max_depth", 16))
        fetch_real = bool(self.opt(ctx, "fetch_real", False))
        timeout_budget = int(self.opt(ctx, "instr_budget", 1_000_000_000))
        wall = float(self.opt(ctx, "wall_timeout", 8.0))
        deadline = float(self.opt(ctx, "total_deadline", 60.0))  # whole-peel cap
        t0 = _time.time()

        sb = Sandbox(fetch_real=fetch_real, instr_budget=timeout_budget, wall_timeout=wall)
        rep = ctx.report
        queue = [(0, ctx.source)]
        seen_run = set()      # sources already executed in the sandbox
        seen_capture = set()  # payloads already queued for execution
        tmpdirs = []

        while queue:
            depth, src = queue.pop(0)
            key = rep.sha(src)
            if key in seen_run or depth > max_depth:
                continue
            if _time.time() - t0 > deadline:
                rep.warn(f"peel: total deadline ({deadline}s) reached, "
                         f"{len(queue)} queued layers skipped")
                break
            seen_run.add(key)
            caps = sb.run_isolated(src, depth=depth)
            tmpdirs.append(caps.get("tmpdir"))
            ok, err = caps["ok"], caps["err"]
            rep.layers.append({"depth": depth, "kind": "input" if depth == 0 else "layer",
                               "size": len(src), "sha256": key,
                               "tag": "clean" if ok else "error", "note": (err or "")[:200]})
            ctx.state.setdefault("layers", []).append(src)

            for p in caps["payloads"]:
                psrc = ""
                try:
                    if _os.path.isfile(p["path"]):
                        with open(p["path"], "r", encoding="utf-8", errors="replace") as fh:
                            psrc = fh.read()
                except OSError:
                    pass
                pkey = p["sha256"] or rep.sha(psrc)
                if pkey not in seen_capture and pkey not in seen_run:
                    seen_capture.add(pkey)
                    rep.payloads.append({"depth": depth + 1, "size": p["size"],
                                         "sha256": pkey, "chunk": p["chunk"],
                                         "tag": _classify(psrc)})
                    queue.append((depth + 1, psrc))
            for u in caps["urls"]:
                rep.urls.append({"url": u["url"], "kind": u["kind"], "fetched": u.get("fetched")})
                body = u.get("fetched_body")
                if body and u.get("fetched"):
                    bkey = rep.sha(body)
                    if bkey not in seen_capture and bkey not in seen_run:
                        seen_capture.add(bkey)
                        rep.payloads.append({"depth": depth + 1, "size": len(body),
                                             "sha256": bkey, "chunk": "HttpGet:" + u["url"][:40],
                                             "tag": _classify(body)})
                        queue.append((depth + 1, body))
            for w in caps["writes"]:
                rep.files_written[w.get("orig", w["path"])] = w["size"]
                ctx.state.setdefault("written_files", {})[w.get("orig", w["path"])] = w["path"]
            for n in caps.get("notes", []):
                if n.get("kind") in ("runtime_error", "task_error"):
                    rep.warnings.append(f"sandbox@{depth}: {str(n.get('value'))[:150]}")
                elif n.get("kind") == "teleport":
                    rep.warnings.append(f"teleport -> {n.get('value')}")
                elif n.get("kind") == "print":
                    v = str(n.get("value"))[:300]
                    bucket = rep.samples.setdefault("printed", [])
                    if v not in bucket:
                        bucket.append(v)
                elif n.get("kind") == "warn":
                    v = "[warn] " + str(n.get("value"))[:300]
                    bucket = rep.samples.setdefault("printed", [])
                    if v not in bucket:
                        bucket.append(v)
            for q in caps["queued_on_teleport"]:
                rep.payloads.append({"depth": depth, "size": len(q or ""), "sha256": rep.sha(q or ""),
                                     "chunk": "queue_on_teleport", "tag": "queued"})
                if q and rep.sha(q) not in seen_capture:
                    seen_capture.add(rep.sha(q))
                    queue.append((depth + 1, q))

        # write artifacts
        outdir = ctx.opt("out_dir")
        if outdir:
            _os.makedirs(outdir, exist_ok=True)
            for i, src in enumerate(ctx.state.get("layers", [])):
                path = _os.path.join(outdir, f"layer{i}.lua")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(src)
                rep.outputs[f"layer{i}"] = path
            for orig, tmppath in ctx.state.get("written_files", {}).items():
                if _os.path.isfile(tmppath):
                    dst = _os.path.join(outdir, "fs_" + _os.path.basename(tmppath))
                    _shutil.copyfile(tmppath, dst)
                    rep.outputs["fs:" + str(orig)] = dst

        # keep the captured payload files for agents (first 3 tmpdirs)
        ctx.state["sandbox"] = sb
        ctx.state["peel_tmpdirs"] = tmpdirs[:3]
        ctx.report.add_pass(self.name, applied=True, changed=len(rep.payloads) > 0,
                            stats={"layers": len(rep.layers),
                                   "payloads": len(rep.payloads),
                                   "urls": len(rep.urls),
                                   "writes": len(rep.files_written)})


def _classify(src):
    if not isinstance(src, str):
        return "binary"
    head = src[:4000]
    if "This file was protected using Luraph" in head:
        return "luraph"
    if re.search(r"52\+m\*211\+m\^?2?\^?\*?189|_0j\(\d+\*54\+65", head):
        return "clyde"
    if re.search(r"while true do\s*(?:local\s+)?\w+\s*=\s*\w+\[\w+\]", head):
        return "vm-dispatch"
    if src.count("\n") >= 5:
        return "clean-looking"
    return "obfuscated-looking"


# ----------------------------------------------------------------------------
# xor — byte-array XOR key hunt (report-only by default)
# ----------------------------------------------------------------------------

class XorPass(Pass):
    name = "xor"
    help = "hunt XOR keys for byte-array literals (e.g. {n1,n2,...} decoded with key K); reports candidates"

    def detect(self, ctx):
        import re
        src = ctx.source
        arrays = re.findall(r"\{(?:\s*\d{1,3}\s*,){11,}(?:\s*\d{1,3}\s*)\}", src[:500_000])
        return min(1.0, len(arrays) / 3.0)

    def run(self, ctx):
        import re
        src = ctx.source
        results = []
        for m in re.finditer(r"\{((?:\s*\d{1,3}\s*,){11,}(?:\s*\d{1,3}\s*))\}", src[:500_000]):
            nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
            if len(nums) < 12 or not all(0 <= v <= 255 for v in nums):
                continue
            best_key, best_score = None, 0.0
            tied = []
            for key in range(256):
                dec = bytes(v ^ key for v in nums)
                ok = sum(1 for b in dec if 32 <= b < 127 or b in (9, 10, 13))
                score = ok / len(dec)
                if score > best_score:
                    best_key, best_score, tied = key, score, [key]
                elif score == best_score and score > 0:
                    tied.append(key)
            if best_score >= 0.97:
                # rank tied keys by wordiness (alnum+space ratio) so the true
                # key surfaces above printability-tie false positives
                def _wordy(k):
                    dec = bytes(v ^ k for v in nums).decode("utf-8", "replace")
                    alnum = sum(1 for ch in dec if ch.isalnum() or ch == " ")
                    return alnum / max(len(dec), 1)
                tied.sort(key=_wordy, reverse=True)
                results.append({"offset": m.start(), "len": len(nums),
                                "xor_keys": tied[:6], "score": round(best_score, 3),
                                "decoded": [
                                    bytes(v ^ k for v in nums).decode("utf-8", "replace")[:120]
                                    for k in tied[:3]]})
        ctx.report.samples["xor"] = results[:12]
        ctx.report.add_pass(self.name, applied=len(results) > 0, changed=False,
                            stats={"candidates": len(results)},
                            notes=[f"@{r['offset']}: keys={[hex(k) for k in r['xor_keys']]} "
                                   f"({r['len']} bytes, {r['score']}) "
                                   + " | ".join(repr(x)[:70] for x in r['decoded'][:3])
                                   for r in results[:8]])


# ----------------------------------------------------------------------------
# dispatch — Luraph-style VM dispatch-loop analysis (ported from vmmap.py)
# ----------------------------------------------------------------------------

class DispatchPass(Pass):
    name = "dispatch"
    help = "find VM dispatch loops (while true do local op=ARR[PC]), count handlers, trace executed opcodes in the sandbox"

    # shape 1: while true do local op = ARR[PC]; if-tree ...
    DISP_RE = re.compile(
        r"while[\s\n]+true[\s\n]+do[\s\n]*(?:local[\s\n]+)?([A-Za-z_]\w*)(?:[\s\n]*,[\s\n]*[A-Za-z_]\w*)*[\s\n]*=[\s\n]*([A-Za-z_]\w*)\[([A-Za-z_]\w*)\][\s\n]*;")
    # shape 2 (Luraph v15): while true do if <op><=N then ... (if-tree direct on opcode var)
    DISP_RE2 = re.compile(
        r"while[\s\n]+true[\s\n]+do[\s\n]*if[\s\n]+([A-Za-z_]\w*)[\s\n]*<=" )

    def detect(self, ctx):
        fp = ctx.report.fingerprint
        if fp.get("primary", "").startswith("luraph") or "vm_dispatch_loop" in fp.get("techniques", {}):
            return 1.0
        return 0.2

    def run(self, ctx):
        src = ctx.source
        loops = list(self.DISP_RE.finditer(src))
        info = []
        for i, m in enumerate(loops, 1):
            op, arr, pc = m.group(1), m.group(2), m.group(3)
            # count `if op <= N` style handler branches after the loop head
            tail = src[m.end(): m.end() + 200_000]
            branches = len(re.findall(r"\b(?:elseif|if)\s+" + re.escape(op) + r"\s*(?:<=|>=|<|>|==|~=)", tail))
            info.append({"index": i, "shape": "fetch-array", "op_var": op, "array": arr, "pc": pc,
                         "branches": branches, "offset": m.start()})
        for i, m in enumerate(self.DISP_RE2.finditer(src), len(info) + 1):
            op = m.group(1)
            tail = src[m.end(): m.end() + 200_000]
            branches = len(re.findall(r"\b(?:elseif|if)\s+" + re.escape(op) + r"\s*(?:<=|>=|<|>|==|~=)", tail))
            info.append({"index": i, "shape": "direct-if-tree", "op_var": op,
                         "branches": branches, "offset": m.start()})
        ctx.report.trace["dispatch_loops"] = info
        # opcode trace via sandbox if available
        trace = ctx.state.get("dispatch_trace") or {}
        ctx.report.trace["opcode_trace"] = trace
        ctx.report.add_pass(self.name, applied=len(info) > 0, changed=False,
                            stats={"dispatch_loops": len(info),
                                   "branches": sum(i["branches"] for i in info),
                                   "traced_ops": sum(1 for _ in trace) if trace else 0},
                            notes=[f"loop#{i['index']} ({i['shape']}): op={i['op_var']}"
                                   + (f" arr={i['array']} pc={i['pc']}" if 'array' in i else "")
                                   + f" handler-branches~{i['branches']}" for i in info[:6]])



# ----------------------------------------------------------------------------
# rename — Roblox-API-aware identifier suggestions (ported from names.py)
# ----------------------------------------------------------------------------

class RenamePass(Pass):
    name = "rename"
    help = "suggest semantic names for mangled identifiers from Roblox API usage (report-only; --apply renames globally-unique ones)"

    GENERATED = re.compile(r"^(?:[a-z]\d+(?:_\d+)*|arg\d+_*)$")

    # ported from Deobfuscator-Luraph-V15 core/names.py
    GLOBAL_CALLS = {
        "game:GetService": "service", "tick": "now", "os.clock": "now", "os.time": "now",
        "type": "kind", "typeof": "kind", "tostring": "str", "tonumber": "num",
        "setmetatable": "obj", "loadstring": "chunk", "getgenv": "genv",
        "string.format": "str", "string.rep": "str", "string.sub": "str",
        "table.concat": "str", "math.floor": "n", "math.clamp": "n", "math.min": "n",
        "math.max": "n", "math.abs": "n", "math.random": "n", "select": "value",
        "Instance.new": "instance", "Vector3.new": "vec", "CFrame.new": "cf",
        "Color3.new": "color", "Color3.fromRGB": "color", "UDim2.new": "udim2",
        "task.spawn": "thread", "coroutine.create": "thread",
    }
    METHOD_NAMES = {
        "GetChildren": "children", "GetDescendants": "descendants", "GetPlayers": "players",
        "Clone": "clone", "Connect": "connection", "Create": "tween", "HttpGet": "response",
        "GetAsync": "response", "JSONDecode": "data", "JSONEncode": "json",
        "match": "match", "gsub": "str", "sub": "str", "lower": "str", "upper": "str",
        "format": "str", "rep": "str", "find": "pos", "split": "parts",
        "GetAttribute": "attribute", "IsA": "isA", "Wait": "result",
        "GetProductInfo": "productInfo", "InvokeServer": "response", "GetMouse": "mouse",
    }

    def detect(self, ctx):
        src = ctx.source
        uniq, _ = _mangled_stats(src)
        return min(1.0, uniq / 10.0)

    def run(self, ctx):
        src = ctx.source
        apply_renames = bool(self.opt(ctx, "apply", False))
        suggestions = []

        # local x = game:GetService("Players")  ->  x could be `players`
        for m in re.finditer(
                r"local\s+((?:[A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)*)\s*=\s*"
                r"([A-Za-z_][\w.]*)(?:\s*:\s*([A-Za-z_]\w*))?\s*\(\s*\"([^\"]+)\"\s*\)", src):
            names = [n.strip() for n in m.group(1).split(",")]
            call = m.group(2) + (":" + m.group(3) if m.group(3) else "")
            arg = m.group(4)
            base = None
            if call.endswith('GetService'):
                base = _camel(arg)
            else:
                base = self.METHOD_NAMES.get(m.group(3) or "", None)
            if not base:
                continue
            for i, name in enumerate(names):
                if self.GENERATED.match(name) or len(name) <= 2:
                    sug = base if i == 0 else f"{base}{i + 1}"
                    suggestions.append({"var": name, "suggested": sug, "evidence": m.group(0)[:80]})
        # method-call results: local v = x:GetAsync(...) -> response
        for m in re.finditer(
                r"local\s+([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\s*:\s*(\w+)\s*\(", src):
            name, method = m.group(1), m.group(2)
            base = self.METHOD_NAMES.get(method)
            if base and (self.GENERATED.match(name) or len(name) <= 2):
                suggestions.append({"var": name, "suggested": base, "evidence": m.group(0)[:80]})

        # dedupe by var keeping most common suggestion
        by_var = {}
        for s in suggestions:
            by_var.setdefault(s["var"], s["suggested"])
        ctx.report.suggestions = [{"var": k, "suggested": v} for k, v in by_var.items()]

        changed = False
        if apply_renames and by_var:
            # ONLY rename identifiers that are globally unique & unambiguous
            for var, sug in by_var.items():
                occurrences = len(re.findall(r"\b" + re.escape(var) + r"\b", src))
                if occurrences <= 1:
                    continue
                # safe: rename only if the name is not used as a string/table key
                if re.search(r"[\"'.:]" + re.escape(var) + r"\b", src):
                    continue
                new = re.sub(r"\b" + re.escape(var) + r"\b", sug, src)
                if new != src:
                    src = new
                    changed = True
        if changed:
            ctx.source = src
        ctx.report.add_pass(self.name, applied=True, changed=changed,
                            stats={"suggestions": len(by_var)},
                            notes=[f"{k} -> {v}" for k, v in list(by_var.items())[:8]])


def _camel(s):
    """'UICorner' -> 'uiCorner'; 'Players' -> 'players' (ported from names.py camel())."""
    parts = re.findall(r"[A-Za-z0-9]+", s or "")
    if not parts:
        return None
    w = "".join(p[:1].upper() + p[1:] for p in parts)
    m = re.match(r"^([A-Z]+)([A-Z][a-z].*)$", w)
    if m:
        w = m.group(1).lower() + m.group(2)
    else:
        m = re.match(r"^([A-Z]+)$", w)
        w = w.lower() if m else w[:1].lower() + w[1:]
    if w[:1].isdigit():
        w = "n" + w
    return w[:32] or None


def _mangled_stats(src):
    uniq = set(_MANGLED_SCAN.findall(src[:400_000]))
    return len(uniq), 0


_MANGLED_SCAN = re.compile(r"\b(?:_?[A-Za-z]{1,2}\d{2,}|_[0-9a-f]{4,}|[a-z]\d+(?:_\d+)+|v_\w{4,})\b")


# ----------------------------------------------------------------------------
# vm_static — generalized Clyde-style static VM decoder
# ----------------------------------------------------------------------------

class VmStaticPass(Pass):
    name = "vm_static"
    help = "static VM analysis: locate opcode-decrypt coefficient chain, decrypt opcode stream, disassemble"

    def detect(self, ctx):
        src = ctx.source
        if re.search(r"\d+\+m\*\d+\+m\*?m?\*?\d+|\d+\+m\*\d+\+m\^2\*\d+", src):
            return 1.0
        fp = ctx.report.fingerprint
        if fp.get("primary") == "clyde":
            return 0.9
        if "vm_dispatch_loop" in fp.get("techniques", {}):
            return 0.5
        return 0.1

    def run(self, ctx):
        from .vm_static_impl import analyze
        coeffs = self.opt(ctx, "opcode_coeffs", None)
        result = analyze(ctx.source, coeffs=coeffs)
        ctx.report.trace["vm_static"] = result["summary"]
        ctx.report.samples["vm_static"] = result["disassembly_sample"]
        ctx.report.add_pass(self.name, applied=result["applied"],
                            changed=False, stats=result["summary"],
                            notes=result["notes"][:10])


ALL = [StringsPass, FoldPass, BeautifyPass, PeelPass, XorPass, DispatchPass,
       RenamePass, VmStaticPass]
