"""Capabilities scanner: finds files with Linux capabilities and flags dangerous ones.
Dangerous capability list comes from config/signatures.json.
"""
import subprocess

from modules.config_loader import load

DANGEROUS = load().get("capability_dangerous", {})


def scan():
    try:
        r = subprocess.run(["getcap", "-r", "/"], capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        return [{"title": "getcap not installed",
                 "evidence": "The 'getcap' command was not found.",
                 "severity": "INFO",
                 "recommendation": "Install it: sudo apt install libcap2-bin"}]
    except subprocess.TimeoutExpired:
        return [{"title": "Capability scan timed out", "evidence": "getcap took too long.",
                 "severity": "INFO", "recommendation": "Re-run the scan."}]

    findings = []
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        lower = line.lower()
        hits = [c for c in DANGEROUS if c in lower]
        if hits:
            findings.append({
                "title": f"Dangerous capability: {line.strip()}",
                "evidence": line.strip() + "\n" + " ".join(DANGEROUS[h] for h in hits),
                "severity": "HIGH",
                "recommendation": "Remove it if unneeded: setcap -r <file>",
            })
        else:
            findings.append({
                "title": f"File capability: {line.strip()}",
                "evidence": line.strip(),
                "severity": "INFO",
                "recommendation": "No action needed unless the program is unexpected.",
            })
    if not findings:
        findings.append({"title": "No file capabilities found", "evidence": "getcap returned nothing.",
                         "severity": "INFO", "recommendation": "None."})
    return findings
