"""luadeob luatokens — safe Lua/Luau lexical scanner.

Splits source into segments: code, string literals (short + long), comments.
Every text-mutating pass uses this so it never rewrites inside strings or
comments. Also provides literal decoding/unescaping utilities.
"""

from __future__ import annotations

import re

# ----------------------------------------------------------------------------
# Segment scanning
# ----------------------------------------------------------------------------

def segments(src):
    """Yield (kind, start, end) with kind in {'code','string','longstring','comment','longcomment'}.
    Adjacent code segments are merged. Order is strictly left-to-right."""
    n = len(src)
    i = 0
    out = []
    while i < n:
        c = src[i]
        # comments
        if c == '-' and src.startswith('--', i):
            j = i + 2
            if src.startswith('[[', j) or _longstring_level(src, j):
                lvl_end = _longstring_end(src, j)
                if lvl_end is not None:
                    out.append(('longcomment', i, lvl_end))
                    i = lvl_end
                    continue
            j = src.find('\n', i)
            j = n if j == -1 else j
            out.append(('comment', i, j))
            i = j
            continue
        # long string [[ ]] [==[ ]==]
        if c == '[':
            lvl = _longstring_level(src, i)
            if lvl is not None:
                e = _longstring_end(src, i)
                if e is not None:
                    out.append(('longstring', i, e))
                    i = e
                    continue
        # short string
        if c in '"\'':
            e = _shortstring_end(src, i)
            if e is not None:
                out.append(('string', i, e))
                i = e
                continue
        # plain code char
        if out and out[-1][0] == 'code':
            out[-1] = ('code', out[-1][1], i + 1)
        else:
            out.append(('code', i, i + 1))
        i += 1
    return out


def _longstring_level(src, i):
    """src[i] == '['; return level+1 if [=*[, else None."""
    if i >= len(src) or src[i] != '[':
        return None
    j = i + 1
    while j < len(src) and src[j] == '=':
        j += 1
    if j < len(src) and src[j] == '[':
        return j - i  # number of '=' + framing
    return None


def _longstring_end(src, i):
    lvl = _longstring_level(src, i)
    if lvl is None:
        return None
    closer = ']' + '=' * (lvl - 1) + ']'
    e = src.find(closer, i + lvl + 1)
    if e == -1:
        return len(src)
    return e + len(closer)


def _shortstring_end(src, i):
    q = src[i]
    j = i + 1
    n = len(src)
    while j < n:
        c = src[j]
        if c == '\\':
            j += 2
            continue
        if c == q:
            return j + 1
        if c == '\n':
            return None  # unterminated; treat as code
        j += 1
    return None


def iter_code_ranges(src):
    """Yield (start, end) of code-only regions."""
    for kind, a, b in segments(src):
        if kind == 'code' and b > a:
            yield a, b


# ----------------------------------------------------------------------------
# String literal decode / encode
# ----------------------------------------------------------------------------

_ESC_MAP = {'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11,
            '\\': 92, '"': 34, "'": 39, '\n': 10}
_HEX_RE = re.compile(r'\\x([0-9a-fA-F]{2})')
_DEC_RE = re.compile(r'\\(\d{1,3})')
_UNI_RE = re.compile(r'\\u\{([0-9a-fA-F]{1,6})\}')
_SKIP = {'z'}  # \z skips following whitespace


def decode_lua_string(literal):
    """Decode a Lua short-string literal (including quotes) to bytes-as-str."""
    body = literal[1:-1] if len(literal) >= 2 and literal[0] in '"\'' else literal
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c != '\\':
            out += c.encode('utf-8')
            i += 1
            continue
        i += 1
        if i >= n:
            break
        c = body[i]
        if c == 'x':
            m = _HEX_RE.match(body, i - 1)
            if m:
                out.append(int(m.group(1), 16))
                i += 3
                continue
            out.append(ord('x'))
            i += 1
            continue
        if c in _ESC_MAP:
            out.append(_ESC_MAP[c])
            i += 1
            continue
        if c == 'z':
            i += 1
            while i < n and body[i] in ' \t\r\n':
                i += 1
            continue
        if c.isdigit():
            m = _DEC_RE.match(body, i - 1)
            if m:
                out.append(int(m.group(1)) & 0xFF)
                i += len(m.group(1))
                continue
        if c == 'u':
            m = _UNI_RE.match(body, i - 1)
            if m:
                cp = int(m.group(1), 16)
                out += chr(cp).encode('utf-8')
                i += len(m.group(0))
                continue
        # unknown escape: keep literally
        out += c.encode('utf-8')
        i += 1
    return out.decode('utf-8', 'replace')


def escape_lua_string(s, prefer_ascii=True):
    """Encode a python str as a printable Lua double-quoted literal."""
    out = ['"']
    for ch in s:
        b = ch.encode('utf-8') if not isinstance(ch, bytes) else bytes([ch])
        for byte in b:
            out.append(_escape_byte(byte, prefer_ascii))
    out.append('"')
    return ''.join(out)


def _escape_byte(byte, prefer_ascii=True):
    c = chr(byte)
    if c == '"':
        return '\\"'
    if c == '\\':
        return '\\\\'
    if c == '\n':
        return '\\n'
    if c == '\t':
        return '\\t'
    if c == '\r':
        return '\\r'
    if 32 <= byte < 127:
        return c
    # non-printable: decimal escape is what obfuscators understand everywhere
    if prefer_ascii or byte > 126:
        return '\\%03d' % byte
    return c


def is_mostly_printable(s, threshold=0.85):
    if not s:
        return False
    ok = sum(1 for c in s if c.isprintable() or c in '\n\r\t')
    return ok / len(s) >= threshold


# ----------------------------------------------------------------------------
# Number expression evaluation (Lua semantics: ^ power, / float, % real mod)
# ----------------------------------------------------------------------------

_NUM_TOKEN = re.compile(
    r'\s*(?:(0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)|(.))')

def eval_lua_number_expr(expr):
    """Evaluate a Lua constant arithmetic expression. Returns int|float|None.
    Only evaluates when EVERY token is numeric/operator — any identifier,
    keyword or unknown char returns None."""
    tokens = []
    for m in _NUM_TOKEN.finditer(expr):
        if m.lastindex is None:
            continue
        if m.group(1) is not None:
            tokens.append(m.group(1))
        else:
            op = m.group(2)
            if op in '+-*/%^()':
                tokens.append(op)
            elif op.isspace():
                continue
            else:
                return None  # identifier/keyword/anything unsafe
    if not tokens or not any(t in '+-*/%^' for t in tokens):
        return None
    py = []
    for t in tokens:
        if t == '^':
            py.append('**')
        elif t == '/':
            py.append('/')
        else:
            py.append(t)
    text = ' '.join(py)
    # reject anything Python would treat specially that Lua wouldn't
    if '//' in text or 'lambda' in text or '_(' in text:
        return None
    try:
        val = eval(text, {"__builtins__": {}}, {})  # noqa: S307 — tokens are filtered above
    except Exception:  # noqa: BLE001
        return None
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None
    if isinstance(val, float):
        if val != val or val in (float('inf'), float('-inf')):
            return None
        if val.is_integer() and abs(val) < 2 ** 53:
            return int(val)
        return val
    return val


def lua_number_fmt(val):
    if isinstance(val, int):
        return str(val)
    if val.is_integer() and abs(val) < 2 ** 53:
        return str(int(val))
    return repr(val)


# ----------------------------------------------------------------------------
# Luau syntax check (Lua 5.5 loader + compound-assignment tolerance)
# ----------------------------------------------------------------------------

_COMPOUND = re.compile(r"(\))?(\S+)\s*(\+|-|\*|/|%|\^)=\s*")

def _strip_compound(src):
    """Rewrite Luau `x += y` -> `x = x + (y)` (per line, validation-only)."""
    out = []
    for line in src.split("\n"):
        # simple forms: `name op= expr` (name may end with ] or ")
        m = re.match(r"^(\s*)([\w\.\[\]\"']+)\s*([+\-*/%^])=\s*(.+)$", line)
        if m:
            out.append(f"{m.group(1)}{m.group(2)} = {m.group(2)} {m.group(3)} ({m.group(4)})")
        else:
            out.append(line)
    return "\n".join(out)


def luau_check(src, lua_runtime=None):
    """Best-effort syntax validation. Returns None if OK, else error string.
    Tolerates Luau-only constructs (compound assignment)."""
    try:
        import lupa
        rt = lua_runtime or lupa.LuaRuntime()
        loader = rt.eval('function(src) local g, e = load(src); return g and true or tostring(e) end')
        res = loader(src)
        if res is True:
            return None
        # retry with compound assignment stripped
        stripped = _strip_compound(src)
        if stripped != src:
            res2 = loader(stripped)
            if res2 is True:
                return None
        return str(res)
    except ImportError:
        return "lupa not installed; cannot validate"
