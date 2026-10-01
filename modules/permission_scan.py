"""Permission scanner: world-writable files/directories, plus explicit checks
on the sensitive files and home directories named in the project brief.
"""
import os
import stat
import subprocess

SENSITIVE = ("/etc/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/")
SCRIPT_EXT = (".sh", ".py", ".pl", ".rb")
SEARCH_DIRS = [d for d in ["/etc", "/usr", "/opt", "/home", "/var", "/srv", "/root", "/tmp"]
               if os.path.isdir(d)]


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return [line for line in r.stdout.splitlines() if line]


def _check_critical_file(path, expected_max_mode, description):
    """Flags /etc/passwd or /etc/shadow if permissions are looser than expected."""
    if not os.path.exists(path):
        return None
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    if mode & ~expected_max_mode:  # any bit set beyond what's allowed
        return {
            "title": f"Incorrect permissions on {path}",
            "evidence": f"{path} has permissions {oct(mode)}. {description} "
                        f"Expected at most {oct(expected_max_mode)}.",
            "severity": "CRITICAL" if path.endswith("shadow") else "HIGH",
            "recommendation": f"chmod {oct(expected_max_mode)[2:]} {path}",
        }
    return None


def _check_home_dirs():
    findings = []
    home_root = "/home"
    if not os.path.isdir(home_root):
        return findings
    for entry in os.listdir(home_root):
        path = os.path.join(home_root, entry)
        if not os.path.isdir(path):
            continue
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        if mode & stat.S_IWOTH:
            findings.append({
                "title": f"World-writable home directory: {path}",
                "evidence": f"{path} has permissions {oct(mode)}, allowing any user to "
                            f"write into another user's home directory.",
                "severity": "HIGH",
                "recommendation": f"chmod o-w {path}",
            })
        elif mode & stat.S_IROTH:
            findings.append({
                "title": f"World-readable home directory: {path}",
                "evidence": f"{path} has permissions {oct(mode)}, allowing any user to "
                            f"read another user's files (SSH keys, history, configs).",
                "severity": "MEDIUM",
                "recommendation": f"chmod o-rx {path}  # or chmod 700 {path} for full privacy",
            })
    return findings


def scan():
    findings = []

    # --- Explicit checks named in the project brief ---
    passwd_finding = _check_critical_file(
        "/etc/passwd", 0o644,
        "/etc/passwd should not be writable by group or others.")
    if passwd_finding:
        findings.append(passwd_finding)

    shadow_finding = _check_critical_file(
        "/etc/shadow", 0o640,
        "/etc/shadow holds password hashes and must not be readable/writable by others.")
    if shadow_finding:
        findings.append(shadow_finding)

    findings.extend(_check_home_dirs())

    if not passwd_finding and not shadow_finding:
        findings.append({
            "title": "/etc/passwd and /etc/shadow permissions reviewed",
            "evidence": "Both files have expected, non-permissive permissions.",
            "severity": "INFO",
            "recommendation": "None.",
        })

    # --- General world-writable file/directory scan ---
    files = _run(["find", *SEARCH_DIRS, "-xdev", "-type", "f", "-perm", "-0002"])
    for path in files:
        if path.startswith(SENSITIVE) or path.endswith(SCRIPT_EXT):
            severity = "HIGH"
            reason = "Any user can modify this file, and it may be executed by a privileged user."
        else:
            severity = "MEDIUM"
            reason = "Any user can modify this file."
        findings.append({
            "title": f"World-writable file: {path}",
            "evidence": f"{path} has 'others' write permission. {reason}",
            "severity": severity,
            "recommendation": f"chmod o-w {path}",
        })

    dirs = _run(["find", *SEARCH_DIRS, "-xdev", "-type", "d",
                 "-perm", "-0002", "!", "-perm", "-1000"])
    for path in dirs:
        findings.append({
            "title": f"World-writable directory (no sticky bit): {path}",
            "evidence": f"{path} lets any user create or delete files inside it.",
            "severity": "MEDIUM",
            "recommendation": f"chmod o-w {path} (or add the sticky bit: chmod +t {path})",
        })
    return findings

