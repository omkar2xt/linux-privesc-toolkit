"""Systemd service scanner: finds services that run as root whose executable
(ExecStart) is writable by a normal user. This is read-only static analysis
of unit files - it does not start, stop, or reload any service.
"""
import os
import re
import stat

UNIT_DIRS = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]

EXEC_START_RE = re.compile(r"^\s*ExecStart\s*=\s*(.*)$", re.IGNORECASE)
USER_RE = re.compile(r"^\s*User\s*=\s*(\S+)$", re.IGNORECASE)
PATH_ENV_RE = re.compile(r"^\s*Environment\s*=\s*[\"']?PATH=([^\"'\s]+)[\"']?", re.IGNORECASE)


def _check_path_security(path_value, unit_name, findings):
    """A PATH entry that is '.', empty, or world-writable lets any user hijack
    what command a root service actually runs."""
    entries = path_value.split(":")
    for entry in entries:
        if entry in ("", "."):
            findings.append({
                "title": f"Insecure PATH in service: {unit_name}",
                "evidence": f"PATH={path_value} contains the current directory ('{entry}'), "
                            f"so a malicious binary placed in the service's working directory "
                            f"could be executed instead of the real one.",
                "severity": "HIGH",
                "recommendation": "Remove '.' or empty entries from the PATH in the unit file.",
            })
            continue
        if os.path.isdir(entry):
            try:
                st = os.stat(entry)
                if st.st_mode & stat.S_IWOTH:
                    findings.append({
                        "title": f"World-writable PATH directory in service: {unit_name}",
                        "evidence": f"PATH={path_value} includes {entry}, which is "
                                    f"world-writable. Any user could place a malicious "
                                    f"binary there for the root service to run.",
                        "severity": "HIGH",
                        "recommendation": f"chmod o-w {entry}, or remove it from PATH.",
                    })
            except OSError:
                pass


def _parse_unit_file(path):
    exec_start, user, path_env = None, None, None
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                if exec_start is None:
                    m = EXEC_START_RE.match(line)
                    if m:
                        exec_start = m.group(1).strip()
                if user is None:
                    m = USER_RE.match(line)
                    if m:
                        user = m.group(1).strip()
                if path_env is None:
                    m = PATH_ENV_RE.match(line)
                    if m:
                        path_env = m.group(1).strip()
    except (PermissionError, OSError):
        return None, None, None
    return exec_start, user, path_env


def _binary_path(exec_start_line):
    """ExecStart can have flags like '-' prefix or '@' prefix and arguments; take the binary."""
    if not exec_start_line:
        return None
    cmd = exec_start_line.lstrip("-").lstrip("@").strip()
    if not cmd:
        return None
    return cmd.split()[0]


def scan():
    findings = []
    seen = set()

    for unit_dir in UNIT_DIRS:
        if not os.path.isdir(unit_dir):
            continue
        try:
            entries = os.listdir(unit_dir)
        except PermissionError:
            continue
        for name in entries:
            if not name.endswith(".service"):
                continue
            if name in seen:
                continue
            seen.add(name)
            path = os.path.join(unit_dir, name)
            if not os.path.isfile(path):
                continue

            exec_start, user, path_env = _parse_unit_file(path)
            runs_as_root = user is None or user == "root"
            if not runs_as_root:
                continue

            if path_env:
                _check_path_security(path_env, name, findings)

            if not exec_start:
                continue

            binary = _binary_path(exec_start)
            if not binary or not binary.startswith("/") or not os.path.exists(binary):
                continue

            try:
                st = os.stat(binary)
            except OSError:
                continue

            if st.st_mode & stat.S_IWOTH:
                findings.append({
                    "title": f"Root service runs a world-writable executable: {name}",
                    "evidence": f"{path} runs as root and executes {binary}, which is "
                                f"world-writable ({oct(stat.S_IMODE(st.st_mode))}).",
                    "severity": "HIGH",
                    "recommendation": f"chmod o-w {binary}",
                })
            elif st.st_mode & stat.S_IWGRP:
                findings.append({
                    "title": f"Root service runs a group-writable executable: {name}",
                    "evidence": f"{path} runs as root and executes {binary}, which is "
                                f"group-writable ({oct(stat.S_IMODE(st.st_mode))}).",
                    "severity": "MEDIUM",
                    "recommendation": f"chmod g-w {binary}, or review group membership.",
                })

    if not findings:
        findings.append({
            "title": "Systemd services reviewed",
            "evidence": "No root-run service pointing to a world- or group-writable "
                        "executable was found.",
            "severity": "INFO",
            "recommendation": "None.",
        })
    return findings
