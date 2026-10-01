"""Loads config/signatures.json once and shares it across modules."""
import json
import os

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "signatures.json")
_cache = None


def load():
    global _cache
    if _cache is not None:
        return _cache
    try:
        with open(_CONFIG_PATH, "r") as fh:
            _cache = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        # Fall back to safe, minimal built-in defaults so a missing/broken
        # config file never crashes the whole scan.
        _cache = {
            "suid_known_normal": ["passwd", "sudo", "su", "mount", "umount"],
            "risky_programs": ["find", "vim", "python", "python3", "bash", "sh"],
            "capability_dangerous": {"cap_setuid": "Can change its user ID (become root)."},
            "kernel_cves": [],
        }
    return _cache
