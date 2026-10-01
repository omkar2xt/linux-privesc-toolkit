"""System information module: who is running the scan and how privileged are they."""
import os
import platform
import subprocess


def scan():
    uid = os.getuid()
    groups = subprocess.run(["id", "-Gn"], capture_output=True, text=True).stdout.strip()
    privilege = "Root" if uid == 0 else "Standard User"
    user = os.environ.get("USER") or subprocess.run(
        ["whoami"], capture_output=True, text=True).stdout.strip()

    evidence = (
        f"User: {user}\n"
        f"UID: {uid}\n"
        f"Groups: {groups}\n"
        f"Hostname: {platform.node()}\n"
        f"OS: {platform.system()} {platform.release()}\n"
        f"Architecture: {platform.machine()}\n"
        f"Privilege: {privilege}"
    )
    return [{
        "title": "System information",
        "evidence": evidence,
        "severity": "INFO",
        "recommendation": "Run the scan as a standard user to see what an attacker would see.",
    }]
