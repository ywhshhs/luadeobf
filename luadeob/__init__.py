"""luadeob — versatile, profile-driven Luau/Lua deobfuscator framework.

Python API (agent-friendly):

    from luadeob import deobfuscate, fingerprint, get_profile

    report = deobfuscate(source, profile="auto")   # -> Report
    print(report.summary())
    data = report.to_dict()                        # JSON-serializable dict

    # custom profile (mold to a specific obfuscation):
    report = deobfuscate(source, profile={
        "name": "myobf",
        "passes": ["strings", "fold", "beautify", "peel", "dispatch"],
        "options": {"peel.max_depth": 32, "rename.apply": False},
    })

    # peel a specific known obfuscator with tuned options:
    report = deobfuscate(source, profile="clyde")
"""

from .core import Pass, Context, Report, Pipeline
from .passes import ALL as ALL_PASSES
from .passes import (BeautifyPass, DispatchPass, FoldPass, PeelPass,  # noqa: F401
                     RenamePass, StringsPass, VmStaticPass, XorPass)
from .fingerprints import fingerprint
from .profiles import get_profile, list_profiles, learn_profile

__version__ = "1.0.0"


def deobfuscate(source, profile="auto", dry_run=False, quiet=False):
    """Run the full pipeline on `source`. Returns a Report."""
    prof = get_profile(profile, source=source)
    ctx = Context(source, options=prof.get("options", {}))
    ctx.report.fingerprint = fingerprint(source)
    ctx.report.set_input(source, name=prof.get("name", "auto"))
    enabled = prof.get("passes")
    if enabled == "auto":
        enabled = None
    pipe = Pipeline([cls() for cls in ALL_PASSES])
    pipe.run(ctx, enabled=enabled, dry_run=dry_run)
    return ctx.report
