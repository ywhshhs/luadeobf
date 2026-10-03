"""luadeob worker — subprocess-isolated sandbox runner.

Usage (internal):  python3 -m luadeob.worker [--fs-root DIR] [--instr N] [--wall S] [--fetch] [--tmpdir DIR]
Reads the Lua source from STDIN, runs it in a fresh sandbox, writes every
captured payload to <tmpdir>/payload_N.lua and prints ONE json line to stdout:
    {"ok": bool, "err": str|null, "urls": [...], "writes": [...], "notes": [...],
     "payloads": [{"path", "size", "sha256", "chunk", "depth"}]}

Why a subprocess: sethook-based timeouts error out of the Lua chunk, but
hostile/obfuscated scripts can catch those errors in pcall loops and keep
running forever; recursion bombs can even segfault the interpreter. A worker
process can be KILLED from the parent, guaranteeing the deadline.
"""

import argparse
import hashlib
import json
import os
import sys


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--fs-root", default=None)
    ap.add_argument("--instr", type=int, default=1_000_000_000)
    ap.add_argument("--wall", type=float, default=8.0)
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--tmpdir", default=None)
    ap.add_argument("--depth", type=int, default=0)
    args = ap.parse_args(argv)

    src = sys.stdin.read()

    from .sandbox import Sandbox
    sb = Sandbox(fetch_real=args.fetch, fs_root=args.fs_root,
                 instr_budget=args.instr, wall_timeout=args.wall)
    ok, err = sb.run(src, chunkname="layer%d" % args.depth)
    caps = sb.drain()

    tmpdir = args.tmpdir or os.path.join(os.environ.get("TMPDIR", "/tmp"), "luadeob_worker")
    os.makedirs(tmpdir, exist_ok=True)

    out_payloads = []
    for i, p in enumerate(caps["payloads"]):
        raw = p["src"]
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "replace")
        path = os.path.join(tmpdir, f"payload_{args.depth}_{i}.lua")
        with open(path, "wb") as f:
            f.write(raw)
        out_payloads.append({
            "path": path,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()[:16],
            "chunk": p["chunk"],
            "depth": p["depth"],
        })

    # writefile captures can also be large: dump to tmpdir as well
    out_writes = []
    for w in caps["writes"]:
        content = sb.fs.writes.get(w["path"])
        if content is None:
            continue
        path = os.path.join(tmpdir, "write_" + os.path.basename(w["path"]).replace("..", "_"))
        with open(path, "wb" if isinstance(content, bytes) else "w") as f:
            f.write(content)
        out_writes.append({"orig": w["path"], "path": path, "size": w["size"]})

    print(json.dumps({
        "ok": ok,
        "err": err,
        "urls": caps["urls"],
        "writes": out_writes,
        "notes": caps["notes"],
        "payloads": out_payloads,
        "teleports": caps["teleports"],
        "queued_on_teleport": caps["queued_on_teleport"],
        "clipboard": caps["clipboard"],
    }, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
