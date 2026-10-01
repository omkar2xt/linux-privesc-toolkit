"""Kernel scanner: compares the running kernel version against a small local
reference list of known Linux kernel local-privilege-escalation CVEs.

IMPORTANT LIMITATION: config/signatures.json ships with only a handful of
well-known CVEs for demonstration. It is NOT a live feed. In a real
deployment this module should query a maintained source (e.g. the NVD API)
instead of - or alongside - the static list.
"""
import platform
import re

from modules.config_loader import load

CVE_LIST = load().get("kernel_cves", [])


def _version_tuple(v):
    """'5.10.102-1-amd64' -> (5, 10, 102). Non-numeric parts are ignored."""
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums[:3]) if nums else (0,)


def _in_range(kernel, lo, hi):
    return _version_tuple(lo) <= _version_tuple(kernel) <= _version_tuple(hi)


# Kernel major.minor lines whose upstream support has ended, as of this
# toolkit's last update. This is a small static reference for demonstration,
# not a live feed - a real deployment should check https://kernel.org for the
# current supported branches.
EOL_BEFORE = (5, 4)  # anything older than 5.4 is treated as end-of-life


def _is_eol(kernel):
    v = _version_tuple(kernel)
    return v[:2] < EOL_BEFORE if len(v) >= 2 else False


def scan():
    kernel = platform.release()
    findings = [{
        "title": "Kernel version",
        "evidence": f"Running kernel: {kernel}",
        "severity": "INFO",
        "recommendation": "Keep the kernel updated via the distribution's package manager.",
    }]

    if _is_eol(kernel):
        findings.append({
            "title": "Kernel appears outdated / potentially end-of-life",
            "evidence": f"Kernel {kernel} is older than the {'.'.join(map(str, EOL_BEFORE))} "
                        f"line used as this toolkit's EOL cutoff. Older kernels no longer "
                        f"receive security patches upstream and are more likely to contain "
                        f"unpatched local privilege-escalation bugs.",
            "severity": "MEDIUM",
            "recommendation": "Upgrade to a currently supported kernel version. "
                               "Check https://kernel.org for the current supported branches.",
        })

    matched = False
    for entry in CVE_LIST:
        if _in_range(kernel, entry["min_version"], entry["max_version"]):
            matched = True
            findings.append({
                "title": f"Potentially affected by {entry['cve']} ({entry['name']})",
                "evidence": f"Kernel {kernel} falls within the affected range "
                            f"{entry['min_version']} - {entry['max_version']}. {entry['note']}",
                "severity": entry.get("severity", "HIGH"),
                "recommendation": "Update the kernel to a patched version and reboot. "
                                   "Verify against the NVD entry for this CVE before relying on this result.",
            })

    if not matched:
        findings.append({
            "title": "No known kernel LPE CVEs matched",
            "evidence": f"Kernel {kernel} did not match any entry in the local reference list. "
                        "This does not guarantee the kernel is unaffected by all vulnerabilities, "
                        "only that it is not in this project's small demonstration list.",
            "severity": "INFO",
            "recommendation": "Cross-check with a maintained CVE feed for a complete assessment.",
        })
    return findings
