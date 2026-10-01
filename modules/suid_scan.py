"""SUID/SGID scanner: finds files that run with their owner's/group's privileges.
Detection rules (known-normal and risky program names) come from config/signatures.json.
"""
import subprocess

from modules.config_loader import load

_cfg = load()
KNOWN_NORMAL = set(_cfg.get("suid_known_normal", []))
RISKY = set(_cfg.get("risky_programs", []))


def _find(perm):
    r = subprocess.run(
        ["find", "/", "-xdev", "-perm", perm, "-type", "f"],
        capture_output=True, text=True,
    )
    return [line for line in r.stdout.splitlines() if line]


def _classify(path, kind):
    name = path.split("/")[-1]
    bit = "u-s" if kind == "SUID" else "g-s"
    if name in RISKY:
        return ("HIGH",
                f"{kind} on '{name}' can allow running commands with elevated privileges.",
                f"Remove the bit if not needed: chmod {bit} {path}")
    if name in KNOWN_NORMAL:
        return ("INFO", f"Standard {kind} program.", "No action needed.")
    return ("MEDIUM", f"Unrecognised {kind} file, needs manual review.",
            f"Check if it is needed. Remove the bit if not: chmod {bit} {path}")


def scan():
    findings = []
    for perm, kind in (("-4000", "SUID"), ("-2000", "SGID")):
        for path in _find(perm):
            severity, reason, rec = _classify(path, kind)
            findings.append({
                "title": f"{kind} file: {path}",
                "evidence": f"{path} has the {kind} bit set. {reason}",
                "severity": severity,
                "recommendation": rec,
            })
    return findings
