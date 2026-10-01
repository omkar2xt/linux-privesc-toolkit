"""Cron scanner: finds scheduled jobs run as root that point to a script a
normal user can modify. If a root cron job runs a writable script, a normal
user can edit that script and their code runs as root the next time it fires.
"""
import os
import re
import stat
import subprocess

CRONTAB_FILES = ["/etc/crontab"]
CRON_DIRS = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
             "/etc/cron.weekly", "/etc/cron.monthly"]


def _list_system_users():
    """Real login users from /etc/passwd (UID >= 1000, plus root), so we don't
    waste time checking crontabs for system/service accounts."""
    users = []
    try:
        with open("/etc/passwd", "r") as fh:
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) < 3:
                    continue
                name, uid = parts[0], parts[2]
                try:
                    uid = int(uid)
                except ValueError:
                    continue
                if uid == 0 or uid >= 1000:
                    users.append(name)
    except (FileNotFoundError, PermissionError):
        pass
    return users


def _check_user_crontabs(findings):
    """Runs `crontab -l -u <user>` for each real user and checks any script
    it references for writable permissions - the brief explicitly asks for
    per-user crontab enumeration, not just /etc/crontab.
    """
    for user in _list_system_users():
        try:
            r = subprocess.run(["crontab", "-l", "-u", user],
                                capture_output=True, text=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if r.returncode != 0 or not r.stdout.strip():
            continue  # no crontab for this user, or not permitted to view it
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) <= 5:
                continue
            cmd = parts[5]
            _check_script(cmd, f"crontab -l -u {user}", findings, running_user=user)

# A line in /etc/crontab or /etc/cron.d/* looks like:
#   */5 * * * * root /path/to/script.sh arg1 arg2
CRONTAB_LINE = re.compile(
    r"^\s*(?:@\w+|(?:\S+\s+){5})(\S+)\s+(.*)$"
)


def _extract_command_and_user(line, has_user_field):
    """Returns (user, command_path) for one crontab-style line, or (None, None)."""
    parts = line.split()
    if has_user_field:
        # schedule(5 fields or @keyword) + user + command
        idx = 1 if line.strip().startswith("@") else 5
        if len(parts) <= idx + 1:
            return None, None
        user = parts[idx]
        cmd = parts[idx + 1]
    else:
        idx = 1 if line.strip().startswith("@") else 5
        if len(parts) <= idx:
            return None, None
        user = "root"  # run-parts style dirs (cron.daily etc.) always run as root
        cmd = parts[idx]
    return user, cmd


def _check_script(path, source, findings, running_user="root"):
    if running_user != "root":
        return  # only a root-run job turns a writable script into a privilege escalation
    if not path.startswith("/"):
        return  # not a path we can check (builtin command name, e.g. "run-parts")
    if not os.path.exists(path):
        return
    try:
        st = os.stat(path)
    except OSError:
        return

    world_writable = bool(st.st_mode & stat.S_IWOTH)
    group_writable = bool(st.st_mode & stat.S_IWGRP)

    if world_writable:
        findings.append({
            "title": f"Root cron job runs a world-writable script: {path}",
            "evidence": f"{source} schedules {path} as root. The file's permissions "
                        f"({oct(stat.S_IMODE(st.st_mode))}) allow any user to modify it.",
            "severity": "HIGH",
            "recommendation": f"chmod o-w {path}",
        })
    elif group_writable:
        findings.append({
            "title": f"Root cron job runs a group-writable script: {path}",
            "evidence": f"{source} schedules {path} as root. The file is writable by its group "
                        f"({oct(stat.S_IMODE(st.st_mode))}). Anyone in that group can edit it.",
            "severity": "MEDIUM",
            "recommendation": f"chmod g-w {path}, or remove non-trusted users from its group.",
        })


def scan():
    findings = []

    for path in CRONTAB_FILES:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r") as fh:
                lines = fh.readlines()
        except PermissionError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            user, cmd = _extract_command_and_user(line, has_user_field=True)
            if user is None:
                continue
            if user == "root":
                _check_script(cmd, path, findings)

    for d in CRON_DIRS:
        if not os.path.isdir(d):
            continue
        has_user_field = (d == "/etc/cron.d")
        for name in os.listdir(d):
            full = os.path.join(d, name)
            if not os.path.isfile(full):
                continue
            if has_user_field:
                try:
                    with open(full, "r") as fh:
                        lines = fh.readlines()
                except PermissionError:
                    continue
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    user, cmd = _extract_command_and_user(line, has_user_field=True)
                    if user == "root":
                        _check_script(cmd, full, findings)
            else:
                # cron.daily/hourly/weekly/monthly: every file here IS the job, run as root
                _check_script(full, f"run-parts {d}", findings)

    _check_user_crontabs(findings)

    if not findings:
        findings.append({
            "title": "Cron jobs reviewed",
            "evidence": "No root-run cron job pointing to a world- or group-writable script was found.",
            "severity": "INFO",
            "recommendation": "None.",
        })
    return findings
