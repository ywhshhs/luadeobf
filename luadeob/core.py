"""luadeob core — Pass / Context / Report / Pipeline.

Design goals (agent-first):
  * Every transform is a Pass: `detect()` reports how strongly it applies,
    `run()` mutates the Context. Passes never throw — failures land in the report.
  * Report is JSON-serializable: an AI agent can consume it directly.
  * Options flow through Context.options as flat "pass.option" keys, so a
    profile is a trivially editable JSON file.
"""

from __future__ import annotations

import hashlib
import json
import re
import time


# ----------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------

class Report:
    """Structured, agent-friendly result of a deobfuscation run."""

    def __init__(self):
        self.started = time.time()
        self.input = {}            # name, size, sha256, lines
        self.fingerprint = {}      # see fingerprints.fingerprint()
        self.passes = []           # [{name, applied, changed, stats, notes, errors}]
        self.layers = []           # peel chain: [{depth, kind, size, sha256, tag, note}]
        self.payloads = []         # loadstring payloads: [{depth, size, sha256, chunk, tag}]
        self.urls = []             # [{url, kind, fetched, size}]
        self.files_written = {}    # virtual FS writes: {path: size}
        self.trace = {}            # dispatch/sandbox trace summary
        self.strings_decoded = 0
        self.samples = {}          # small illustrative samples per pass
        self.suggestions = []      # rename/name-inference suggestions
        self.warnings = []
        self.errors = []
        self.outputs = {}          # artifact -> path on disk
        self.duration = 0.0

    # -- collect helpers -----------------------------------------------------
    @staticmethod
    def sha(text):
        if isinstance(text, str):
            text = text.encode("utf-8", "replace")
        return hashlib.sha256(text).hexdigest()[:16]

    def add_pass(self, name, applied, changed=False, stats=None, notes=None, errors=None):
        entry = {"name": name, "applied": bool(applied), "changed": bool(changed),
                 "stats": stats or {}, "notes": notes or [],
                 "errors": [str(e)[:200] for e in (errors or [])]}
        self.passes.append(entry)
        return entry

    def warn(self, msg):
        self.warnings.append(str(msg))

    def error(self, msg):
        self.errors.append(str(msg)[:500])

    def set_input(self, source, name="input"):
        self.input = {"name": name, "size": len(source),
                      "sha256": self.sha(source), "lines": source.count("\n") + 1}

    # -- output ---------------------------------------------------------------
    def to_dict(self):
        self.duration = round(time.time() - self.started, 2)
        return {
            "ok": not self.errors,
            "input": self.input,
            "fingerprint": self.fingerprint,
            "passes": self.passes,
            "layers": self.layers,
            "payloads": self.payloads,
            "urls": self.urls,
            "files_written": self.files_written,
            "trace": self.trace,
            "strings_decoded": self.strings_decoded,
            "samples": self.samples,
            "suggestions": self.suggestions,
            "warnings": self.warnings,
            "errors": self.errors,
            "outputs": self.outputs,
            "duration_sec": self.duration,
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)

    # -- human summary ----------------------------------------------------------
    def summary(self):
        out = []
        fp = self.fingerprint
        prim = fp.get("primary", "unknown")
        score = fp.get("obfuscators", {}).get(prim, {}).get("score", 0)
        out.append(f"[luadeob] {self.input.get('name')}  "
                   f"({self.input.get('size', 0):,} bytes, {self.input.get('lines', 0):,} lines)")
        out.append(f"  obfuscator : {prim} (confidence {score:.2f})")
        techs = fp.get("techniques", {})
        if techs:
            tops = sorted(techs.items(), key=lambda kv: -_tech_score(kv[1]))[:6]
            out.append("  techniques : " + ", ".join(
                f"{k} ({_tech_score(v)})" for k, v in tops))
        for p in self.passes:
            flag = "+" if p["changed"] else ("~" if p["applied"] else "-")
            stats = p["stats"]
            s = ", ".join(f"{k}={v}" for k, v in stats.items()) if stats else ""
            out.append(f"  [{flag}] {p['name']:<12} {s}")
            for n in p["notes"][:8]:
                out.append(f"        . {n}")
            if len(p["notes"]) > 8:
                out.append(f"        . ... +{len(p['notes']) - 8} more")
        for e in self.errors:
            out.append(f"  ERROR: {e}")
        for o, path in self.outputs.items():
            out.append(f"  saved: {path} ({o})")
        out.append(f"  done in {self.duration}s")
        return "\n".join(out)


def _tech_score(v):
    if isinstance(v, dict):
        return v.get("count", v.get("hits", 1))
    if isinstance(v, bool):
        return 1 if v else 0
    return v if isinstance(v, (int, float)) else 1


# ----------------------------------------------------------------------------
# Context
# ----------------------------------------------------------------------------

class Context:
    """Shared state flowing through passes."""

    def __init__(self, source, options=None):
        self.source = source
        self.options = dict(options or {})
        self.report = Report()
        self.state = {}            # pass-to-pass scratch (e.g. sandbox captures)

    def opt(self, key, default=None, prefix=""):
        """Read option 'prefix.key' (pass calls with their own name as prefix)."""
        if prefix:
            v = self.options.get(f"{prefix}.{key}")
            if v is not None:
                return v
        return self.options.get(key, default)


# ----------------------------------------------------------------------------
# Pass
# ----------------------------------------------------------------------------

class Pass:
    """Base class for a deobfuscation pass."""
    name = "base"
    #: short description shown in --list-passes
    help = ""

    def detect(self, ctx: Context) -> float:
        """0..1 confidence this pass applies to the current source."""
        return 0.5

    def run(self, ctx: Context) -> None:
        """Execute. Mutate ctx.source / ctx.report. Never raise."""
        raise NotImplementedError

    # -- helpers --------------------------------------------------------------
    def opt(self, ctx, key, default=None):
        return ctx.opt(key, default, prefix=self.name)

    def safe_run(self, ctx: Context) -> None:
        """run() wrapped: errors go to the report instead of aborting the pipeline."""
        try:
            self.run(ctx)
        except Exception as e:  # noqa: BLE001 — pipeline must survive any pass
            ctx.report.error(f"pass '{self.name}' failed: {e}")
            ctx.report.add_pass(self.name, applied=False, errors=[e])


# ----------------------------------------------------------------------------
# Pipeline
# ----------------------------------------------------------------------------

class Pipeline:
    def __init__(self, passes):
        self.passes = list(passes)

    def run(self, ctx: Context, enabled=None, detect_threshold=0.25,
            dry_run=False, quiet=False) -> Report:
        """Run all enabled passes in order.

        enabled: explicit pass-name list (None = auto-detect driven);
        a name not present in self.passes is skipped with a warning.
        """
        rep = ctx.report
        by_name = {p.name: p for p in self.passes}
        if enabled is not None:
            unknown = [n for n in enabled if n not in by_name]
            for n in unknown:
                rep.warn(f"unknown pass '{n}' ignored (known: {', '.join(by_name)})")
            order = [by_name[n] for n in enabled if n in by_name]
            auto = False
        else:
            order = list(self.passes)
            auto = True

        for p in order:
            try:
                conf = p.detect(ctx)
            except Exception as e:  # noqa: BLE001
                conf = 0.0
                rep.error(f"pass '{p.name}' detect() failed: {e}")
            applies = (conf >= detect_threshold) if auto else True
            if dry_run:
                rep.add_pass(p.name, applied=applies, stats={"confidence": round(conf, 2)})
                continue
            if applies:
                before = p.name and rep.strings_decoded
                p.safe_run(ctx)
            else:
                rep.add_pass(p.name, applied=False,
                             notes=[f"skipped (detect confidence {conf:.2f} < {detect_threshold})"])
        return rep
