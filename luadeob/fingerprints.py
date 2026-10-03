"""luadeob fingerprints — obfuscator & technique detection.

Luraph v15/v14 signature logic ported from Deobfuscator-Luraph-V15 (src/detect.js):
  * header  : "This file was protected using Luraph Obfuscator v<ver>[ https://lura.ph/]"
  * v15 vm  : `return setmetatable({[104]=bit32.countlz,...` + LPH markers
  * v14 vm  : `return({...})` / `local init = (function(...` shapes

Plus: Clyde Protection (reverse-engineered: opcode chain 52+m*211+m^2*189,
position-key i*54+65, running-key a=a+161), IronBrew2, MoonSec, PSU,
and generic technique scans (escape density, string.char chains, base64,
loadstring/HttpGet chains, VM constant tables, mangled identifiers).
"""

from __future__ import annotations

import base64
import binascii
import re

# ----------------------------------------------------------------------------
# Known obfuscator signatures
# ----------------------------------------------------------------------------

# name -> (regex list, score per hit)
_OBFUSCATOR_SIGNATURES = {
    "luraph_v15": [
        (re.compile(r"This file was protected using Luraph Obfuscator v15"), 1.0),
        (re.compile(r"^return setmetatable\(\{", re.M | re.S), 0.45),
        (re.compile(r"\[\d+\]=(?:bit32|buffer|string|table|math)\.\w+"), 0.4),
        (re.compile(r"LPH_(?:NO_VIRTUALIZE|JIT|ENCSTR|ENCNUM|CRASH|OBFUSCATED)"), 0.5),
        (re.compile(r"jO=function\(v,R,g,t,o,N,y,Z,U,i,Q,f,D\)"), 0.6),
    ],
    "luraph_v14": [
        (re.compile(r"This file was protected using Luraph Obfuscator v14[.\d]*"), 1.0),
        (re.compile(r"^return\(\{\}\)", re.M | re.S), 0.4),
        (re.compile(r"^local init = \(function\(\.\.\.", re.M | re.S), 0.4),
        (re.compile(r"return\(\{\}\):K\("), 0.6),
        (re.compile(r"0b[01]{4,}"), 0.15),
    ],
    "clyde": [
        (re.compile(r"52\+m\*211\+m\*m\*189|52\+m\*211\+m\^2\*189"), 0.9),
        (re.compile(r"_0j\(\d+\*54\+65|_0j\(i\*54\+65|\(\d+\*54\+65\),0xFF"), 0.5),
        (re.compile(r"_0a=\d+;_0a=_0a\+\d+|_0a=_0a\+\d+"), 0.35),
        (re.compile(r"\blocal ac,P,ar\b|\blocal _V,aj,_W\b"), 0.6),
        (re.compile(r"\b_4u=\{\(65\+121\)"), 0.7),
    ],
    "ironbrew": [
        (re.compile(r"l{3,}I{3,}|I{3,}l{3,}"), 0.45),
        (re.compile(r"vm_def|IRONBREW|ironbrew", re.I), 0.8),
        (re.compile(r"bit32\.bxor\(bit32\.bxor\("), 0.3),
    ],
    "moonsec": [
        (re.compile(r"moonsec|MoonSec", re.I), 0.85),
        (re.compile(r"\bV2\b.*\bvm\b|\bvm\b.*\bV2\b"), 0.2),
    ],
    "psu": [
        (re.compile(r"PSU_HIDDEN|\bpsu\b", re.I), 0.7),
        (re.compile(r"scriptzure|prometheus", re.I), 0.3),
    ],
    "xen": [
        (re.compile(r"Xen\b|xfalcon", re.I), 0.6),
    ],
}

# ----------------------------------------------------------------------------
# Generic technique scans
# ----------------------------------------------------------------------------

_GENERIC = {
    "loadstring_chain": re.compile(r"\bloadstring\s*\(|\bload\s*\(\s*\w+\s*\)\s*\(|\(\s*load\s*\("),
    "http_loader":      re.compile(r":HttpGet(?:Async)?\s*\(|getgenv|request\s*\(|http_request"),
    "webhook":          re.compile(r"discord(?:app)?\.com/api/webhooks|https://discord\.com/api/webhooks"),
    "getgenv_write":    re.compile(r"getgenv\(\)\s*\.\s*\w+\s*=|getgenv\(\)\[\s*[\"']"),
    "string_char":      re.compile(r"string\.char\s*\(|[^%w]\.char\s*\("),
    "string_byte_table": re.compile(r"string\.byte\s*\(\s*\w+\s*,\s*\w+\s*\)"),
    "bit32_ops":        re.compile(r"bit32\.(?:bxor|band|bor|bnot|lshift|rshift|rrotate|lrotate)"),
    "base64_blob":      None,   # handled specially below
    "anti_tamper":      re.compile(r"checkcaller|islclosure|is_l_closure|debug\.info|hookmetamethod|hookfunction|setreadonly"),
    "executor_ping":    re.compile(r"identifyexecutor|getexecutorname|getexecutor"),
    "vm_dispatch_loop": re.compile(r"while true do\s*(?:local\s+)?([A-Za-z_]\w*)(?:\s*,\s*[A-Za-z_]\w*)*\s*=\s*([A-Za-z_]\w*)\[([A-Za-z_]\w*)\]\s*;"),
    "lph_markers":      re.compile(r"LPH_[A-Z_]+"),
    "packed_vm":        re.compile(r"return setmetatable\(\{|\}\):K\(|\):K\("),
    "mangled_ids":      None,   # handled specially below
    "numeric_expr_arrays": re.compile(r"\{\(\d+[+\-*/]\d+\)"),
}

_MANGLED_RE = re.compile(r"\b(?:_?[A-Za-z]{1,2}\d{2,}|_[0-9a-f]{4,}|[a-z]\d+(?:_\d+)+|v_\w{4,})\b")


def _base64_blob_count(src):
    """Count long base64-looking literals (>=40 chars)."""
    hits = re.findall(r'["\']([A-Za-z0-9+/=]{40,})["\']', src)
    n = 0
    for h in hits[:200]:
        try:
            base64.b64decode(h[: min(len(h), 4096)], validate=False)
            n += 1
        except (binascii.Error, ValueError):
            pass
    return n


def _escape_counts(src):
    """Luau string-escape census (\\xNN, \\ddd, \\u{...})."""
    hex_e = len(re.findall(r"\\x[0-9a-fA-F]{2}", src))
    dec_e = len(re.findall(r"\\\d{1,3}", src))
    uni_e = len(re.findall(r"\\u\{[0-9a-fA-F]{1,6}\}", src))
    return hex_e, dec_e, uni_e


def _mangled_count(src):
    # cap the scan for huge files
    ids = _MANGLED_RE.findall(src[:400_000])
    uniq = set(ids)
    return len(uniq), len(ids)


def _is_mostly_printable(s, threshold=0.85):
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / len(s) >= threshold


# ----------------------------------------------------------------------------
# main entry
# ----------------------------------------------------------------------------

def fingerprint(src):
    """Full fingerprint of a script. Returns a JSON-serializable dict:
    {
      "primary": "luraph_v15",
      "obfuscators": {name: {"score": x, "evidence": [...]}},
      "techniques":  {name: {"count"/"hits": n, ...}},
      "escapes": {"hex": n, "dec": n, "unicode": n},
      "recommended_passes": [...]
    }
    """
    src = src or ""
    head = src[:2000]

    obf = {}
    for name, sigs in _OBFUSCATOR_SIGNATURES.items():
        score, ev = 0.0, []
        for rx, w in sigs:
            m = rx.search(src if w >= 0.4 else src[:4000])
            if m:
                score += w
                snippet = m.group(0)[:60].replace("\n", "\\n")
                ev.append(snippet)
        if score > 0:
            obf[name] = {"score": round(min(score, 1.0), 2), "evidence": ev[:6]}

    primary = "generic"
    if obf:
        primary = max(obf.items(), key=lambda kv: kv[1]["score"])[0]

    # generic techniques
    tech = {}
    for name, rx in _GENERIC.items():
        if rx is None:
            continue
        hits = len(rx.findall(src[:1_000_000]))
        if hits:
            tech[name] = {"hits": hits}

    b64 = _base64_blob_count(src)
    if b64:
        tech["base64_blob"] = {"count": b64}

    hex_e, dec_e, uni_e = _escape_counts(src)
    escapes = {"hex": hex_e, "dec": dec_e, "unicode": uni_e}
    if hex_e >= 8 or dec_e >= 8:
        tech["escaped_strings"] = {"hex": hex_e, "dec": dec_e}

    mu, mi = _mangled_count(src)
    if mu >= 4:
        tech["mangled_identifiers"] = {"unique": mu, "total": mi}

    # header version pin (luraph)
    version = None
    m = re.search(r"Luraph Obfuscator v(\d+)(?:\.(\d+))?", head)
    if m:
        version = f"{m.group(1)}.{m.group(2) or '0'}"
    if version:
        tech["pinned_version"] = {"luraph": version}

    # recommended passes ------------------------------------------------------
    rec = []
    if escapes["hex"] + escapes["dec"] >= 6:
        rec.append("strings")
    if "string_char" in tech:
        rec.append("strings")
    if any(k in tech for k in ("numeric_expr_arrays",)) or re.search(
            r"\(\d+\)\s*\.\.|\d+\+\d+\*\d+", src[:50000]):
        rec.append("fold")
    if any(k in tech for k in ("loadstring_chain", "http_loader", "webhook")):
        rec.append("peel")
    if primary == "luraph_v15" or primary == "luraph_v14" or "vm_dispatch_loop" in tech:
        rec.append("dispatch")
    if "luraph" in primary or "ironbrew" in primary or "clyde" in primary or "vm_dispatch_loop" in tech:
        rec.append("vm_static")
    if tech.get("escaped_strings") and _is_mostly_printable(src):
        rec.append("xor")
    if re.search(r"\[\"?[A-Za-z_]\w*\"?\]\s*=\s*function", src[:100000]) and primary != "generic":
        rec.append("rename")
    if src.count("\n") < 5 and len(src) > 2000:
        rec.append("beautify")
    if not rec:
        rec = ["peel", "beautify"]

    # dedupe, preserve order
    seen, ordered = set(), []
    for p in rec:
        if p not in seen:
            seen.add(p)
            ordered.append(p)

    return {
        "primary": primary,
        "obfuscators": obf,
        "techniques": tech,
        "escapes": escapes,
        "recommended_passes": ordered,
    }
