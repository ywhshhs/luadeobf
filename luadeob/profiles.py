"""luadeob profiles — builtin + custom (JSON) profiles + learn-from-fingerprint.

A profile is a plain JSON-serializable dict:
    {
      "name": "myobf",
      "description": "what this obfuscation looks like",
      "passes": ["strings", "fold", "beautify", "peel", "dispatch", ...],  # or "auto"
      "options": {"peel.max_depth": 32, "vm_static.opcode_coeffs": [52,211,189], ...}
    }

Options keys are "<pass>.<option>" (an unprefixed key applies to every pass
that reads it, e.g. "out_dir").
"""

from __future__ import annotations

import json

_BUILTIN = {
    "auto": {
        "name": "auto",
        "description": "fingerprint-driven: every pass decides by its detect() score",
        "passes": "auto",
        "options": {},
    },
    "full": {
        "name": "full",
        "description": "all passes, forced on",
        "passes": ["strings", "fold", "beautify", "peel", "xor", "dispatch", "rename", "vm_static"],
        "options": {},
    },
    "safe": {
        "name": "safe",
        "description": "no sandbox execution, no code rewriting — detection & static analysis only",
        "passes": ["strings", "fold", "xor", "dispatch", "vm_static"],
        "options": {"strings.min_length": 6, "fold.max_expr": 0},
    },
    "strings-only": {
        "name": "strings-only",
        "description": "decode strings/escapes only",
        "passes": ["strings"],
        "options": {},
    },
    "static-only": {
        "name": "static-only",
        "description": "static passes incl. VM analysis; no Lua sandbox execution",
        "passes": ["strings", "fold", "beautify", "xor", "dispatch", "vm_static", "rename"],
        "options": {},
    },
    "dynamic-only": {
        "name": "dynamic-only",
        "description": "sandbox trace/peel only (fast behaviour recon)",
        "passes": ["peel", "dispatch"],
        "options": {},
    },
    "clyde": {
        "name": "clyde",
        "description": "Clyde Protection v2 (VM constant chain + self-decrypting opcodes + layered loadstring)",
        "passes": ["strings", "fold", "peel", "vm_static", "beautify"],
        "options": {
            "peel.max_depth": 32,
            "vm_static.opcode_coeffs": [52, 211, 189],
        },
    },
    "luraph": {
        "name": "luraph",
        "description": "Luraph v14/v15 (VM dispatch loops, LPH markers, lazy constants)",
        "passes": ["strings", "fold", "beautify", "peel", "dispatch", "rename"],
        "options": {
            "peel.max_depth": 12,
            "rename.apply": False,
        },
    },
    "luraph-aggressive": {
        "name": "luraph-aggressive",
        "description": "Luraph with apply-rename + deep peel + xor hunt",
        "passes": ["strings", "fold", "beautify", "peel", "dispatch", "rename", "xor"],
        "options": {
            "peel.max_depth": 24,
            "rename.apply": True,
        },
    },
    "ironbrew": {
        "name": "ironbrew",
        "description": "IronBrew2-style VM (triple-lIlI identifiers, bxor-chains)",
        "passes": ["strings", "fold", "beautify", "peel", "dispatch", "vm_static"],
        "options": {"peel.max_depth": 12},
    },
    "moonsec": {
        "name": "moonsec",
        "description": "MoonSec V2/V3",
        "passes": ["strings", "fold", "beautify", "peel", "dispatch"],
        "options": {"peel.max_depth": 12},
    },
    "loader": {
        "name": "loader",
        "description": "download-exec loaders (escaped urls, HttpGet, checksummed payloads, queue_on_teleport)",
        "passes": ["strings", "fold", "peel", "beautify"],
        "options": {"peel.max_depth": 8},
    },
}


def list_profiles():
    return {k: v["description"] for k, v in _BUILTIN.items()}


def get_profile(profile, source=None):
    """Resolve a profile by name, dict, or path to JSON. Falls back to 'auto'."""
    if profile is None:
        profile = "auto"
    if isinstance(profile, dict):
        prof = _deepcopy(profile)
        prof.setdefault("name", "custom")
        prof.setdefault("passes", "auto")
        prof.setdefault("options", {})
        return prof
    if isinstance(profile, str):
        if profile in _BUILTIN:
            return _deepcopy(_BUILTIN[profile])
        # maybe a file path
        import os
        if os.path.isfile(profile):
            with open(profile, "r", encoding="utf-8") as f:
                prof = json.load(f)
            prof.setdefault("name", os.path.basename(profile))
            prof.setdefault("passes", "auto")
            prof.setdefault("options", {})
            return prof
        if source is not None and profile == "auto":
            return _deepcopy(_BUILTIN["auto"])
        raise ValueError(f"unknown profile '{profile}' (known: {', '.join(_BUILTIN)})")
    raise ValueError("profile must be a name, dict, or file path")


def learn_profile(source):
    """Fingerprint a script and emit a moldable profile for it."""
    from .fingerprints import fingerprint
    fp = fingerprint(source)
    primary = fp.get("primary", "generic")
    if primary in _BUILTIN:
        prof = _deepcopy(_BUILTIN[primary])
    else:
        prof = _deepcopy(_BUILTIN["auto"])
    prof["passes"] = fp.get("recommended_passes", ["peel", "beautify"])
    prof["description"] = (f"learned: primary={primary}, "
                           f"techniques={sorted(fp.get('techniques', {}).keys())}")
    prof["learned_fingerprint"] = fp
    return prof


def _deepcopy(d):
    return json.loads(json.dumps(d))
