"""Linux Privilege Escalation Detection Toolkit
Detection only. No exploitation is performed."""
import json
import os
from datetime import datetime

from modules import (
    system_info, suid_scan, permission_scan, sudo_scan, capability_scan,
    cron_scan, service_scan, kernel_scan, report_html,
)

MODULES = [
    system_info, suid_scan, permission_scan, sudo_scan, service_scan,
    cron_scan, kernel_scan, capability_scan,
]
ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def main():
    print("Linux Privilege Escalation Detection Toolkit")
    print("(detection only, no exploitation)\n")

    findings = []
    for module in MODULES:
        name = module.__name__.split(".")[-1]
        print(f"[*] Running {name} ...")
        try:
            findings.extend(module.scan())
        except Exception as exc:  # one broken module must not stop the scan
            findings.append({"title": f"Module error: {name}", "evidence": str(exc),
                             "severity": "INFO", "recommendation": "Check the module."})

    findings.sort(key=lambda f: ORDER[f["severity"]])

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = [f"REPORT generated {datetime.now():%Y-%m-%d %H:%M:%S}", "=" * 60,
             "SUMMARY: " + ", ".join(f"{k}={counts[k]}" for k in ORDER if k in counts),
             "=" * 60]
    for f in findings:
        lines += [f"\n[{f['severity']}] {f['title']}",
                  f"Evidence:\n{f['evidence']}",
                  f"Recommendation: {f['recommendation']}"]
    report = "\n".join(lines)
    print("\n" + report)

    os.makedirs("reports", exist_ok=True)
    with open("reports/report.txt", "w") as fh:
        fh.write(report)
    with open("reports/report.json", "w") as fh:
        json.dump({"generated": datetime.now().isoformat(), "summary": counts,
                   "findings": findings}, fh, indent=2)
    with open("reports/report.html", "w") as fh:
        fh.write(report_html.build(findings, counts))
    print("\n[+] Saved reports/report.txt, reports/report.json, reports/report.html")


if __name__ == "__main__":
    main()
