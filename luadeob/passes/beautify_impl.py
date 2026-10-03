"""beautify_impl — reindent Lua/Luau source (tokenizer + header state machine).

Safety invariant: we only ever INSERT newlines/indentation and DROP comments —
never tokens — so output stays syntactically valid even where our statement
heuristics are wrong. Depth mistakes cost only cosmetic indentation.

Handles: `local function f(a, b)` one-line headers, `if/while/for ... then/do`
headers, `repeat/until cond`, standalone do-blocks, Luau compound assignment,
short/long strings, table constructors, and the Luraph glued-header quirk
(restoreHeaderNewline ported from Deobfuscator-Luraph-V15).
"""

from __future__ import annotations

import re

from .. import luatokens as T

_OPENERS = {"function", "if", "for", "while", "do", "repeat"}
_CLOSERS = {"end", "until"}
_MID = {"elseif", "else"}
_SKIP_WORDS = {"then", "do", "local", "return"}


def beautify(src, indent="    "):
    src = _restore_header_newline(src)
    toks = _tokenize(src)

    lines = []
    depth = 0
    buf = []
    pending = None      # None | 'header' | 'params' | 'until'
    pdepth = 0          # paren depth inside a pending header

    def flush():
        nonlocal buf
        text = "".join(buf).strip()
        if text:
            lines.append(indent * max(depth, 0) + text)
        buf = []

    def emit_open(word):
        nonlocal depth, pending, pdepth
        flush()
        lines.append(indent * max(depth, 0) + word)
        depth += 1

    for kind, text in toks:
        word = text.strip()
        is_word = kind == "word"

        if kind == "comment":
            continue

        if pending == "params":
            buf.append(text)
            if kind == "punct" and word in "()" and text == "(":
                pdepth += 1
            elif kind == "punct" and text == ")":
                pdepth -= 1
                if pdepth <= 0:
                    # param list done: the whole function header is one line
                    flush()
                    depth += 1
                    pending = None
                    pdepth = 0
            continue

        if pending == "header":
            buf.append(text)
            if kind == "punct" and text in "([{":
                pdepth += 1
            elif kind == "punct" and text in ")]}":
                pdepth -= 1
            elif (is_word and word in ("then", "do")) and pdepth <= 0:
                flush()
                depth += 1
                pending = None
                pdepth = 0
            continue

        if pending == "until":
            # consume the until-condition: ends at ; / opener / closer / newline
            if (kind == "punct" and word in (";",)) or (kind == "nl") or \
               (is_word and (word in _OPENERS or word in _CLOSERS or word in _MID)):
                flush()
                pending = None
                # reprocess this token as normal
                _reprocess(lines, depth, buf, word, kind, text, is_word,
                           locals_dict := {k: v for k, v in dict(
                               depth=depth, pending=pending).items()})
                depth = locals_dict["depth"]
                pending = locals_dict["pending"]
                continue
            buf.append(text)
            continue

        # pending == None: statement-level tokens
        if kind == "nl":
            if buf and "".join(buf).strip():
                flush()
            continue

        if kind == "punct_space":
            if buf and not buf[-1].endswith(" "):
                buf.append(" ")
            continue

        if kind == "punct":
            buf.append(text)
            if word == ";":
                flush()
            continue

        if is_word and word in _OPENERS:
            if word == "function":
                # keep `local function` together; else open after param list
                buf.append(text)
                pending = "params"
                pdepth = 0
                continue
            if word == "do":
                # standalone do-block (headers consumed their own do above)
                if "".join(buf).strip() and not _endswith_any(buf, ("for", "while", ",")):
                    emit_open(word)
                    continue
                buf.append(text)
                flush()
                depth += 1
                continue
            if word == "repeat":
                emit_open(word)
                continue
            # if / for / while: start a header
            if "".join(buf).strip() and not _endswith_any(buf, ("local", "then", "do", "return", "else")) \
                    and not _endswith_op(buf):
                flush()
            buf.append(text)
            pending = "header"
            pdepth = 0
            continue

        if is_word and word in _CLOSERS:
            flush()
            depth = max(depth - 1, 0)
            lines.append(indent * depth + word)
            if word == "until":
                pending = "until"
            continue

        if is_word and word in _MID:
            flush()
            depth = max(depth - 1, 0)
            if word == "elseif":
                buf.append(word)
                pending = "header"
                pdepth = 0
            else:  # else
                lines.append(indent * depth + word)
                depth += 1
            continue

        # regular word
        if (is_word and word in ("local", "return")) and "".join(buf).strip() \
                and not _endswith_any(buf, ("local", "then", "do", "else", "return")):
            flush()
        buf.append(text)

    flush()
    out = "\n".join(lines)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out + ("\n" if out and not out.endswith("\n") else "")


def _reprocess(lines, depth, buf, word, kind, text, is_word, state):
    """Minimal re-entry for the token that terminated an `until` header."""
    # this only handles indentation-side effects; syntax is never changed
    if is_word and word in _CLOSERS:
        depth = max(depth - 1, 0)
        lines.append("    " * depth + word)
    elif is_word and word in _OPENERS:
        lines.append("    " * depth + word)
        depth += 1
    state["depth"] = depth
    state["pending"] = None


def _endswith_any(buf, words):
    text = "".join(buf).rstrip()
    return any(text.endswith(w) for w in words)


def _endswith_op(buf):
    text = "".join(buf).rstrip()
    return bool(text) and text[-1] in "=+-*/%^>{[(,:"


def _tokenize(src):
    """Yield (kind, text): comment|string|longstring|number|word|punct|nl."""
    out = []
    for kind, a, b in T.segments(src):
        if kind in ("string", "longstring", "longcomment"):
            out.append(("longstring" if kind == "longstring" else
                        ("string" if kind == "string" else "comment"), src[a:b]))
            continue
        if kind == "comment":
            out.append(("comment", src[a:b]))
            continue
        chunk = src[a:b]
        i = 0
        while i < len(chunk):
            c = chunk[i]
            if c in " \t":
                if out and out[-1][0] != "punct_space":
                    out.append(("punct_space", " "))
                i += 1
                continue
            if c == "\n" or c == "\r":
                out.append(("nl", "\n"))
                i += 1
                continue
            m = re.match(r"(0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+)", chunk[i:])
            if m:
                out.append(("number", m.group(0)))
                i += m.end()
                continue
            m = re.match(r"[A-Za-z_]\w*", chunk[i:])
            if m:
                out.append(("word", m.group(0)))
                i += m.end()
                continue
            # multi-char operators
            m = re.match(r"\.\.\.|==|~=|<=|>=|\+=|-=|\*=|/=|%=|\^=|\.\.=|::", chunk[i:])
            out.append(("punct", m.group(0) if m else c))
            i += m.end() if m else 1
    return out


_HEADER_RE = re.compile(
    r"--[ \t]*This file was protected using Luraph Obfuscator v[\d.]+[ \t]*\[https?://lura\.ph/?\]")


def _restore_header_newline(src):
    """Ported: Luraph glues the header comment onto the first code line."""
    m = _HEADER_RE.search(src)
    if m:
        end = m.end()
        nxt = src[end] if end < len(src) else ""
        if nxt not in ("", "\n", "\r"):
            return src[:end] + "\n" + src[end:].lstrip(" \t")
    return src
