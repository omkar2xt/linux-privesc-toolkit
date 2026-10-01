"""Sudo scanner: analyses `sudo -l` output for risky rules."""
import subprocess

# Programs that can spawn a shell or edit arbitrary files if run as root
DANGEROUS = {"vim", "vi", "nano", "find", "python", "python3", "perl", "bash",
             "sh", "less", "more", "awk", "nmap", "cp", "env", "tar", "man",
             "ruby", "php", "node", "tee", "dd", "mv", "chmod", "chown"}


def scan():
    try:
        # -n = never prompt for a password (so the scan cannot hang)
        r = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return [{"title": "Sudo not installed", "evidence": "The 'sudo' command was not found.",
                 "severity": "INFO", "recommendation": "None."}]
    except subprocess.TimeoutExpired:
        return [{"title": "Sudo check timed out", "evidence": "sudo -n -l did not finish.",
                 "severity": "INFO", "recommendation": "Re-run the scan."}]

    output = (r.stdout + r.stderr).strip()
    if r.returncode != 0:
        return [{
            "title": "Sudo rules could not be listed without a password",
            "evidence": output or "sudo -n -l returned an error.",
            "severity": "INFO",
            "recommendation": "Normal for a locked-down user. No passwordless sudo access found.",
        }]

    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("("):
            continue  # rule lines look like: (ALL : ALL) NOPASSWD: /usr/bin/x
        nopasswd = "NOPASSWD" in line
        rule_cmds = line.split(":")[-1].strip()

        if nopasswd and rule_cmds.upper() == "ALL":
            sev, why = "CRITICAL", "Any command can be run as root with no password."
        elif rule_cmds.upper() == "ALL":
            sev, why = "HIGH", "Any command can be run as root (password required)."
        else:
            cmds = [c.strip().split("/")[-1] for c in rule_cmds.split(",")]
            bad = [c for c in cmds if c in DANGEROUS]
            if bad and nopasswd:
                sev, why = "HIGH", f"Passwordless sudo on shell-capable programs: {', '.join(bad)}."
            elif bad:
                sev, why = "MEDIUM", f"Sudo allowed on shell-capable programs: {', '.join(bad)}."
            elif nopasswd:
                sev, why = "LOW", "Passwordless sudo on specific commands."
            else:
                continue

        findings.append({
            "title": f"Sudo rule: {line}",
            "evidence": f"{line}\n{why}",
            "severity": sev,
            "recommendation": "Edit with 'visudo': remove NOPASSWD and restrict to exact, safe commands.",
        })

    if not findings:
        findings.append({"title": "Sudo rules reviewed", "evidence": output,
                         "severity": "INFO", "recommendation": "No risky sudo rules detected."})
    return findings
