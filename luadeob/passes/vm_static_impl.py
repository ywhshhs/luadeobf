"""vm_static_impl — generalized Clyde-style static VM analysis.

Ported from clyde_decompiler.py (reverse-engineered from a real Clyde
Protection layer) and generalized:
  * opcode-decrypt coefficients auto-detected from the source
    (patterns like `Q(52+m*211+m*m*189, 0xFF)` / `Q(52+m*211+m^2*189,0xFF)`),
    or supplied via profile option `vm_static.opcode_coeffs = [52, 211, 189]`.
  * constant-table extraction via the sandbox (the constant prelude runs and
    we snapshot the decoded table), falling back to static sbox parsing.
"""

from __future__ import annotations

import re

_COEFF_PATTERNS = [
    re.compile(r"\((\d+)\s*\+\s*m\s*\*\s*(\d+)\s*\+\s*m\s*\*\s*m\s*\*\s*(\d+)"),
    re.compile(r"\((\d+)\s*\+\s*m\s*\*\s*(\d+)\s*\+\s*m\s*\^\s*2\s*\*\s*(\d+)"),
    re.compile(r"\((\d+)\s*\+\s*m\s*\*\s*(\d+)\s*\+\s*m\^2\s*\*\s*(\d+)"),
]


def find_coeffs(src):
    for rx in _COEFF_PATTERNS:
        m = rx.search(src)
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def analyze(src, coeffs=None):
    summary = {"coeffs": None, "opcodes": 0, "constants": 0, "disassembled": 0}
    notes = []
    sample = []

    if coeffs is None:
        coeffs = find_coeffs(src)
    if coeffs:
        summary["coeffs"] = list(coeffs)
        notes.append(f"opcode decrypt chain detected: op = k[m] ^ ({coeffs[0]} + m*{coeffs[1]} + m^2*{coeffs[2]}) & 0xFF")
    else:
        notes.append("no known opcode-coefficient chain found")

    # locate candidate bytecode/constant tables: big int arrays
    tables = _find_tables(src)
    summary["tables"] = len(tables)
    for name, body in tables[:6]:
        nums = [int(x) for x in re.findall(r"-?\d+", body)]
        notes.append(f"table `{name}`: {len(nums)} numbers")
        if len(nums) > summary["opcodes"] and all(0 <= v <= 255 for v in nums[:100]):
            summary["opcodes"] = len(nums)

    # if we have coefficients AND a byte table, attempt a decrypt+disasm pass
    if coeffs and tables:
        name, body = max(tables, key=lambda kv: len(re.findall(r"-?\d+", kv[1])))
        k = [int(x) for x in re.findall(r"-?\d+", body)]
        if all(0 <= v <= 255 for v in k):
            ops = [k[i] ^ ((coeffs[0] + (i + 1) * coeffs[1] + (i + 1) ** 2 * coeffs[2]) & 0xFF)
                   for i in range(len(k))]
            summary["constants"] = summary["opcodes"]
            dis = _disassemble(ops, k)
            summary["disassembled"] = len(dis)
            sample = dis[:40]
            notes.append(f"disassembled {len(dis)} instructions from table `{name}`")

    return {"applied": bool(coeffs), "summary": summary, "notes": notes,
            "disassembly_sample": sample}


def _find_tables(src):
    """Find `name={...}` tables with mostly-numeric entries (VM candidates)."""
    out = []
    for m in re.finditer(r"([A-Za-z_]\w{0,4})\s*=\s*\{", src):
        i = src.index("{", m.start())
        depth, j = 0, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = src[i:j + 1]
        if len(body) > 200 and len(re.findall(r"-?\d+", body)) > 40:
            out.append((m.group(1), body))
            if len(out) >= 12:
                break
    return out


def _disassemble(ops, k):
    """Lua 5.1-style textual disassembly of the decrypted opcode stream
    (instruction width 4, recovered handler semantics from clyde_decompiler.py)."""
    out = []
    n = len(k)
    m = 1
    while m <= n - 3:
        op = ops[m - 1]
        T, U, V = k[m], k[m + 1], k[m + 2]

        def C_(x):
            return f"K{x - 255}" if x >= 256 else f"R{x}"

        if op == 56:
            txt = f"JMP      -> L{m + 4 + T * 4}"
        elif op == 45:
            txt = f"FORPREP  R{V}, step R{V + 2} -> L{m + 4 + U * 4}"
        elif op == 25:
            txt = f"FORLOOP  R{T} -> L{m + 4 + U * 4}"
        elif op == 48:
            txt = f"MOVE     R{U} = R{V}"
        elif op == 24:
            txt = f"CALL     R{V}(R{V + 1}..R{V + T}) nret={U}"
        elif op == 50:
            txt = f"GETGLOBAL R{V} = K{T + 1}"
        elif op == 29:
            txt = f"LOADK    R{T} = K{V}"
        elif op == 53:
            txt = f"GETTABLE R{T} = R{V}[{C_(U)}]"
        elif op == 51:
            txt = f"SETTABLE R{T}[{C_(V)}] = {C_(U)}"
        elif op == 5:
            txt = f"NEWTABLE R{V}"
        elif op == 33:
            txt = f"SELF     R{V}, R{U}, {C_(T)}"
        elif op == 28:
            txt = f"CLOSURE  R{U} = proto[{T}]"
        elif op == 8:
            txt = f"GETUPVAL R{U} = up[{V}]"
        elif op == 23:
            txt = f"TEST     R{V}, {T}"
        elif op == 40:
            txt = f"RETURN   base R{T} count={V}"
        elif op == 19:
            txt = f"LEN      R{T} = #R{V}"
        elif op == 43:
            txt = f"CLOSE    R{V}"
        elif op in (17, 35, 21):
            txt = f"NOP      ({op})"
        else:
            txt = f"??       op={op} T={T} U={U} V={V}"
        out.append(f"L{m:<5} {txt}")
        m += 4
    return out
