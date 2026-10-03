"""luadeob CLI — agent-friendly command line.

    python3 -m luadeob <input|-> [options]

Examples:
    python3 -m luadeob script.lua --json
    python3 -m luadeob loader.lua --profile luraph -o out/
    python3 -m luadeob obfuscated.lua --learn --learn-to profile.json
    python3 -m luadeob script.lua --profile-file profile.json -o out/
"""

import argparse
import json
import sys

from . import deobfuscate, fingerprint
from .profiles import list_profiles, learn_profile
from .passes import ALL


def build_parser():
    ap = argparse.ArgumentParser(
        prog="luadeob",
        description="Versatile, profile-driven Luau/Lua deobfuscator "
                    "(pass pipeline + full Roblox sandbox env).")
    ap.add_argument("input", help="script file, or '-' for stdin")
    ap.add_argument("-o", "--out", default=None, help="output dir for layers/report/deobfuscated.lua")
    ap.add_argument("--json", action="store_true", help="print full report JSON to stdout (agent mode)")
    ap.add_argument("--profile", default="auto", help=f"builtin profile: {', '.join(list_profiles())}")
    ap.add_argument("--profile-file", default=None, help="custom profile JSON")
    ap.add_argument("--learn", action="store_true", help="fingerprint + emit a moldable profile (no processing)")
    ap.add_argument("--learn-to", default=None, help="save learned profile to this file")
    ap.add_argument("--enable", default=None, help="comma list of passes to enable (after profile)")
    ap.add_argument("--disable", default=None, help="comma list of passes to disable (after profile)")
    ap.add_argument("--only", default=None, help="run exactly these passes: " + ",".join(p.name for p in ALL))
    ap.add_argument("--fetch", action="store_true", help="allow REAL network fetch of HttpGet urls")
    ap.add_argument("--fs-root", default=None, help="readfile() read-through root (virtual FS)")
    ap.add_argument("--max-depth", type=int, default=None, help="peel depth override")
    ap.add_argument("--timeout", type=int, default=None, help="sandbox instruction budget (millions)")
    ap.add_argument("--apply-renames", action="store_true", help="let the rename pass actually rewrite (unique ids only)")
    ap.add_argument("--dry-run", action="store_true", help="fingerprint + pass detect only")
    ap.add_argument("--list-passes", action="store_true")
    ap.add_argument("--list-profiles", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.list_passes:
        for p in ALL:
            print(f"{p.name:<12} {p.help}")
        return 0
    if args.list_profiles:
        for name, desc in list_profiles().items():
            print(f"{name:<20} {desc}")
        return 0

    # ---- read input ---------------------------------------------------------
    if args.input == "-":
        src = sys.stdin.read()
        name = "stdin"
    else:
        try:
            with open(args.input, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
            name = args.input
        except OSError as e:
            print(f"error: cannot read {args.input}: {e}", file=sys.stderr)
            return 1
    if not src.strip():
        print("error: empty input", file=sys.stderr)
        return 1

    # ---- learn mode ----------------------------------------------------------
    if args.learn or args.learn_to:
        prof = learn_profile(src)
        prof["options"] = prof.get("options", {}) or {}
        if args.max_depth is not None:
            prof["options"]["peel.max_depth"] = args.max_depth
        if args.fetch:
            prof["options"]["peel.fetch_real"] = True
        prof.pop("learned_fingerprint", None)
        js = json.dumps(prof, indent=2)
        if args.learn_to:
            with open(args.learn_to, "w", encoding="utf-8") as f:
                f.write(js + "\n")
            if not args.quiet:
                print(f"profile saved: {args.learn_to}")
            if not args.json:
                return 0
        if args.json or not args.learn_to:
            print(js)
        return 0

    # ---- resolve profile -------------------------------------------------------
    profile = args.profile
    if args.profile_file:
        profile = args.profile_file

    options = {}
    if isinstance(profile, str) and profile not in list_profiles():
        pass  # get_profile will raise a clear error
    if args.max_depth is not None:
        options["peel.max_depth"] = args.max_depth
    if args.timeout is not None:
        options["peel.wall_timeout"] = float(args.timeout)
    if args.fetch:
        options["peel.fetch_real"] = True
    if args.apply_renames:
        options["rename.apply"] = True
    if args.out:
        options["out_dir"] = args.out
    if args.fs_root:
        options["fs_root"] = args.fs_root

    # merge options into a dict-profile wrapper
    prof = dict(name=profile, passes="auto", options=options)

    # ---- pass selection --------------------------------------------------------
    enabled = None
    if args.only:
        enabled = args.only.split(",")
    else:
        base = _profile_passes(profile)
        if args.enable:
            enabled = list(base) if base else [p.name for p in ALL]
            for p in args.enable.split(","):
                if p not in enabled:
                    enabled.append(p)
        if args.disable:
            enabled = enabled or list(base) or [p.name for p in ALL]
            enabled = [p for p in enabled if p not in set(args.disable.split(","))]

    # merge profile dict if it's already a dict; else wrap name+options
    report = _run(src, profile=profile, options=options, enabled=enabled,
                  dry_run=args.dry_run)

    # ---- output ------------------------------------------------------------
    outdir = args.out
    if outdir:
        import os
        os.makedirs(outdir, exist_ok=True)
        final = os.path.join(outdir, "deobfuscated.lua")
        with open(final, "w", encoding="utf-8") as f:
            f.write(report.final_source if hasattr(report, "final_source") else "")
        report.outputs["deobfuscated.lua"] = final
        with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as f:
            f.write(report.to_json())
        report.outputs["report.json"] = os.path.join(outdir, "report.json")

    if args.json:
        print(report.to_json())
    elif not args.quiet:
        print(report.summary())

    return 0 if not report.errors else 1


def _profile_passes(profile):
    """Read the 'passes' field of a named/dict profile without full resolution."""
    from .profiles import get_profile
    try:
        prof = get_profile(profile)
        p = prof.get("passes")
        return p if isinstance(p, list) else None
    except (ValueError, OSError):
        return None


def _run(src, profile, options, enabled, dry_run):
    """Like deobfuscate() but with CLI-level pass overrides + final source."""
    import luadeob
    from luadeob.core import Context, Pipeline
    from luadeob.passes import ALL as ALL_CLASSES

    from .profiles import get_profile

    prof = get_profile(profile, source=src)
    merged = dict(prof.get("options", {}))
    merged.update({k: v for k, v in options.items() if v is not None})

    ctx = Context(src, options=merged)
    ctx.report.fingerprint = fingerprint(src)
    ctx.report.set_input(src, name=str(profile))

    enabled_final = enabled if enabled is not None else prof.get("passes")
    if enabled_final == "auto":
        enabled_final = None

    pipe = Pipeline([cls() for cls in ALL_CLASSES])
    pipe.run(ctx, enabled=enabled_final, dry_run=dry_run)
    report = ctx.report
    # stash the final source onto the report object (API convenience)
    report.final_source = ctx.source
    return report


if __name__ == "__main__":
    sys.exit(main())
