"""
Parse fapolicyd logs and report status/denials.

fapolicyd logs denials to /var/log/fapolicyd/fapolicyd.log in format:
  rule=N dec=deny_log|deny perm=execute uid=N pid=N exe=PATH : path=DENIED_PATH ftype=FTYPE trust=N

Also checks the audit log at /var/log/audit/audit.log for AVC / FANOTIFY
entries tagged with fapolicyd.
"""

import os
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Optional

from .db import get_conn, count_trust
from .enforcement import fapolicyd_is_active, get_permissive, get_trust_path, get_rules_path
from .logger import info, warn, error, GREEN, YELLOW, RED, BLUE, NC


FAPOLICYD_LOG  = "/var/log/fapolicyd/fapolicyd.log"
AUDIT_LOG      = "/var/log/audit/audit.log"

# Match denial lines from fapolicyd.log
_DENIAL_RE = re.compile(
    r"rule=(?P<rule>\S+)\s+dec=(?P<dec>\S+)\s+perm=(?P<perm>\S+)\s+"
    r"uid=(?P<uid>\S+)\s+pid=(?P<pid>\S+)\s+exe=(?P<exe>\S+)\s*:\s*"
    r"path=(?P<path>\S+)\s+ftype=(?P<ftype>\S+)\s+trust=(?P<trust>\S+)"
)

# Match audit.log lines (alternative source)
_AUDIT_DENIAL_RE = re.compile(
    r"type=(?:AVC|FANOTIFY).*?fapolicyd.*?name=(?P<path>\S+)"
)


def parse_fapolicyd_log(max_lines=200):
    # type: (int) -> List[Dict]
    """
    Parse the last *max_lines* lines of /var/log/fapolicyd/fapolicyd.log
    and return denial records.
    """
    denials = []
    if not os.path.isfile(FAPOLICYD_LOG):
        return denials

    lines = _tail_file(FAPOLICYD_LOG, max_lines)
    for line in lines:
        if "dec=deny" not in line:
            continue
        m = _DENIAL_RE.search(line)
        if m:
            denials.append({
                "source": "fapolicyd.log",
                "rule":   m.group("rule"),
                "dec":    m.group("dec"),
                "perm":   m.group("perm"),
                "uid":    m.group("uid"),
                "pid":    m.group("pid"),
                "exe":    m.group("exe"),
                "path":   m.group("path"),
                "ftype":  m.group("ftype"),
                "trust":  m.group("trust"),
                "raw":    line.rstrip(),
            })
    return denials


def parse_audit_log(max_lines=500):
    # type: (int) -> List[Dict]
    """
    Scan the last *max_lines* of /var/log/audit/audit.log for
    fapolicyd-related denial events.
    """
    denials = []
    if not os.path.isfile(AUDIT_LOG):
        return denials

    lines = _tail_file(AUDIT_LOG, max_lines)
    for line in lines:
        if "fapolicyd" not in line:
            continue
        if "denied" not in line.lower() and "deny" not in line.lower():
            continue
        m = _AUDIT_DENIAL_RE.search(line)
        path = m.group("path") if m else "<unknown>"
        denials.append({
            "source": "audit.log",
            "path":   path,
            "raw":    line.rstrip(),
        })
    return denials


def get_recent_denials(max_lines=200):
    # type: (int) -> List[Dict]
    """Return combined denial list from both log sources."""
    denials = parse_fapolicyd_log(max_lines)
    if not denials:
        # Fall back to audit log
        denials = parse_audit_log(max_lines)
    return denials


# ---------------------------------------------------------------------------
# Status report
# ---------------------------------------------------------------------------

def show_status():
    """Print a human-readable status summary to stdout."""
    active = fapolicyd_is_active()
    permissive = get_permissive()

    # Enforcement state label
    if not active:
        state_label = "{}STOPPED{}".format(RED, NC)
        state_detail = "fapolicyd is not running"
    elif permissive:
        state_label = "{}AUDIT (permissive){}".format(YELLOW, NC)
        state_detail = "logging only — execution NOT blocked"
    else:
        state_label = "{}ENFORCING{}".format(GREEN, NC)
        state_detail = "execution of untrusted binaries is BLOCKED"

    print("")
    print("{}=== ccdc-guard status ==={}" .format(BLUE, NC))
    print("  Enforcement state : {}".format(state_label))
    print("  Detail            : {}".format(state_detail))

    # Trust counts
    conn = get_conn()
    counts = count_trust(conn)
    conn.close()
    total = sum(counts.values())
    print("  Trust entries     : {} total".format(total))
    for src, cnt in sorted(counts.items()):
        print("    {:20s}: {}".format(src, cnt))

    # Trust file / rules paths
    trust_path = get_trust_path()
    rules_path = get_rules_path()
    print("  Trust file        : {}{}{}".format(
        GREEN if os.path.isfile(trust_path) else RED, trust_path, NC))
    print("  Rules file        : {}{}{}".format(
        GREEN if os.path.isfile(rules_path) else RED, rules_path, NC))

    # Recent denials count
    denials = get_recent_denials(50)
    print("  Recent denials    : {}".format(len(denials)))
    print("")


def show_denials(count=50):
    # type: (int) -> None
    """Print recent execution denials."""
    denials = get_recent_denials(count * 3)  # over-fetch to filter down
    if not denials:
        # Try both sources explicitly and report which files are missing
        if not os.path.isfile(FAPOLICYD_LOG) and not os.path.isfile(AUDIT_LOG):
            warn("No fapolicyd or audit log found")
        else:
            info("No denials found in the last {} log lines".format(count * 3))
        return

    shown = denials[:count]
    print("")
    print("{}=== Recent execution denials ({} of {}) ==={}" .format(
        BLUE, len(shown), len(denials), NC))
    for d in shown:
        if d["source"] == "fapolicyd.log":
            print("  {}DENY{}  exe={} path={} uid={} rule={}".format(
                RED, NC,
                d.get("exe", "?"),
                d.get("path", "?"),
                d.get("uid", "?"),
                d.get("rule", "?"),
            ))
        else:
            print("  {}DENY{}  {}".format(RED, NC, d.get("raw", d.get("path", "?"))))
    print("")


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _tail_file(path, n):
    # type: (str, int) -> List[str]
    """Return the last *n* lines of *path*."""
    try:
        # Use `tail` for large files — fast and OS-provided
        result = subprocess.run(
            ["tail", "-n", str(n), path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="replace").splitlines()
    except Exception:
        pass
    # Pure-Python fallback
    try:
        with open(path, errors="replace") as fh:
            lines = fh.readlines()
        return [l.rstrip("\n") for l in lines[-n:]]
    except OSError:
        return []
