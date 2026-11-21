"""
fapolicyd enforcement engine.

Handles:
  - installing fapolicyd if absent
  - detecting old vs new fapolicyd layout
  - writing CCDC policy rules
  - writing the user trust file
  - toggling permissive / enforce mode
  - reloading fapolicyd
  - starting/stopping fapolicyd
  - post-enforce service health check with auto-rollback
"""

import os
import re
import subprocess
import time
from typing import List, Optional, Tuple

from .db import get_conn
from .discovery import detect_distro, get_active_service_names, is_service_active
from .logger import ccdc_log, info, warn, error, critical
from .trust import generate_trust_lines, preflight_services
from .recovery import take_snapshot


# ---------------------------------------------------------------------------
# Path constants (detected lazily)
# ---------------------------------------------------------------------------

FAPOLICYD_CONF   = "/etc/fapolicyd/fapolicyd.conf"
RULES_D_DIR      = "/etc/fapolicyd/rules.d"
RULES_LEGACY     = "/etc/fapolicyd/fapolicyd.rules"
TRUST_D_DIR      = "/etc/fapolicyd/trust.d"
TRUST_D_FILE     = "/etc/fapolicyd/trust.d/ccdc.trust"
TRUST_LEGACY     = "/etc/fapolicyd/fapolicyd.trust"

CCDC_RULES_FILE  = "/etc/fapolicyd/rules.d/50-ccdc.rules"

CCDC_POLICY = """\
# CCDC Guard -- generated policy
allow perm=execute all : trust=1
allow perm=execute all : trust=2
deny perm=execute all : dir=/tmp
deny perm=execute all : dir=/var/tmp
deny perm=execute all : dir=/dev/shm
deny perm=execute all : dir=/run/shm
deny perm=execute all : all
"""


# ---------------------------------------------------------------------------
# Layout detection
# ---------------------------------------------------------------------------

def _has_rules_d():
    # type: () -> bool
    return os.path.isdir(RULES_D_DIR)


def _has_trust_d():
    # type: () -> bool
    return os.path.isdir(TRUST_D_DIR)


def get_rules_path():
    # type: () -> str
    return CCDC_RULES_FILE if _has_rules_d() else RULES_LEGACY


def get_trust_path():
    # type: () -> str
    return TRUST_D_FILE if _has_trust_d() else TRUST_LEGACY


# ---------------------------------------------------------------------------
# fapolicyd installation
# ---------------------------------------------------------------------------

def install_fapolicyd():
    # type: () -> bool
    """Install fapolicyd if it is not already present. Returns True on success."""
    if _fapolicyd_installed():
        info("fapolicyd is already installed")
        return True
    info("Installing fapolicyd…")
    distro = detect_distro()
    if distro == "deb":
        cmds = [
            ["apt-get", "update", "-y"],
            ["apt-get", "install", "-y", "fapolicyd"],
        ]
    else:
        # Try dnf first, fall back to yum
        if _cmd_exists("dnf"):
            cmds = [["dnf", "install", "-y", "fapolicyd"]]
        else:
            cmds = [["yum", "install", "-y", "fapolicyd"]]
    for cmd in cmds:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            error("Install command failed: {}".format(" ".join(cmd)))
            error(result.stderr.decode("utf-8", errors="replace"))
            return False
    if _fapolicyd_installed():
        info("fapolicyd installed successfully")
        ccdc_log("fapolicyd_installed")
        return True
    error("fapolicyd installation appeared to succeed but binary not found")
    return False


def _fapolicyd_installed():
    # type: () -> bool
    return _cmd_exists("fapolicyd") or os.path.isfile("/usr/sbin/fapolicyd")


def _cmd_exists(name):
    # type: (str) -> bool
    try:
        result = subprocess.run(
            ["which", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# Rules management
# ---------------------------------------------------------------------------

def write_rules():
    # type: () -> str
    """Write the CCDC policy rules file. Returns the path written."""
    rules_path = get_rules_path()
    # Ensure parent dir exists
    rules_dir = os.path.dirname(rules_path)
    if rules_dir:
        os.makedirs(rules_dir, exist_ok=True)

    with open(rules_path, "w") as fh:
        fh.write(CCDC_POLICY)

    info("Rules written to {}".format(rules_path))
    ccdc_log("rules_written", path=rules_path)
    return rules_path


def read_rules():
    # type: () -> str
    path = get_rules_path()
    if os.path.isfile(path):
        with open(path) as fh:
            return fh.read()
    return ""


# ---------------------------------------------------------------------------
# Trust file management
# ---------------------------------------------------------------------------

def write_trust_file():
    # type: () -> str
    """Write the fapolicyd user trust file from DB. Returns path written."""
    trust_path = get_trust_path()
    trust_dir = os.path.dirname(trust_path)
    if trust_dir:
        os.makedirs(trust_dir, exist_ok=True)

    conn = get_conn()
    content = generate_trust_lines(conn)
    conn.close()

    with open(trust_path, "w") as fh:
        fh.write(content)

    info("Trust file written to {} ({} entries)".format(
        trust_path, content.count("\n")))
    ccdc_log("trust_file_written", path=trust_path,
             detail="lines={}".format(content.count("\n")))
    return trust_path


def read_trust_file():
    # type: () -> str
    path = get_trust_path()
    if os.path.isfile(path):
        with open(path) as fh:
            return fh.read()
    return ""


# ---------------------------------------------------------------------------
# fapolicyd.conf management
# ---------------------------------------------------------------------------

def read_conf():
    # type: () -> str
    if os.path.isfile(FAPOLICYD_CONF):
        with open(FAPOLICYD_CONF) as fh:
            return fh.read()
    return ""


def _set_conf_key(key, value):
    # type: (str, str) -> None
    """Set a key = value in fapolicyd.conf, adding it if not present."""
    if not os.path.isfile(FAPOLICYD_CONF):
        error("fapolicyd.conf not found at {}".format(FAPOLICYD_CONF))
        return
    with open(FAPOLICYD_CONF) as fh:
        content = fh.read()

    pattern = re.compile(r"^(\s*{}\s*=\s*).*$".format(re.escape(key)), re.MULTILINE)
    replacement = "{} = {}".format(key, value)
    if pattern.search(content):
        content = pattern.sub(replacement, content)
    else:
        content += "\n{}\n".format(replacement)

    with open(FAPOLICYD_CONF, "w") as fh:
        fh.write(content)


def set_permissive(permissive):
    # type: (bool) -> None
    """Set permissive mode on (1) or off (0) in fapolicyd.conf."""
    val = "1" if permissive else "0"
    _set_conf_key("permissive", val)
    mode = "permissive" if permissive else "enforce"
    info("fapolicyd mode set to: {}".format(mode))
    ccdc_log("mode_set", detail="permissive={}".format(val))


def get_permissive():
    # type: () -> Optional[bool]
    """Return current permissive setting from conf, or None if unknown."""
    conf = read_conf()
    m = re.search(r"^\s*permissive\s*=\s*(\d)", conf, re.MULTILINE)
    if m:
        return m.group(1) == "1"
    return None


# ---------------------------------------------------------------------------
# fapolicyd reload / start / stop
# ---------------------------------------------------------------------------

def reload_fapolicyd():
    # type: () -> bool
    """
    Reload fapolicyd trust DB.
    Try `fapolicyd-cli --update` first; fall back to SIGHUP.
    Returns True if the reload appeared successful.
    """
    # First attempt: fapolicyd-cli --update (preferred for trust file changes)
    if _cmd_exists("fapolicyd-cli"):
        result = subprocess.run(
            ["fapolicyd-cli", "--update"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            info("fapolicyd trust DB reloaded via fapolicyd-cli --update")
            ccdc_log("fapolicyd_reloaded", detail="method=cli")
            return True
        warn("fapolicyd-cli --update failed; trying SIGHUP fallback")

    # Fallback: SIGHUP
    result = subprocess.run(
        ["systemctl", "kill", "-s", "SIGHUP", "fapolicyd"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        info("fapolicyd reloaded via SIGHUP")
        ccdc_log("fapolicyd_reloaded", detail="method=sighup")
        return True

    error("Failed to reload fapolicyd")
    return False


def start_fapolicyd():
    # type: () -> bool
    result = subprocess.run(
        ["systemctl", "enable", "--now", "fapolicyd"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        info("fapolicyd started and enabled")
        ccdc_log("fapolicyd_started")
        return True
    error("Failed to start fapolicyd: {}".format(
        result.stderr.decode("utf-8", errors="replace")))
    return False


def stop_fapolicyd():
    # type: () -> bool
    result = subprocess.run(
        ["systemctl", "stop", "fapolicyd"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        info("fapolicyd stopped")
        ccdc_log("fapolicyd_stopped")
        return True
    error("Failed to stop fapolicyd")
    return False


def fapolicyd_is_active():
    # type: () -> bool
    result = subprocess.run(
        ["systemctl", "is-active", "fapolicyd"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = result.stdout.decode("utf-8", errors="replace").strip()
    return output == "active"


# ---------------------------------------------------------------------------
# Audit mode (permissive + running)
# ---------------------------------------------------------------------------

def enable_audit_mode():
    # type: () -> bool
    """Enable fapolicyd in permissive/audit mode (logs denials, doesn't block)."""
    if not install_fapolicyd():
        return False
    # Snapshot before changes
    conn = get_conn()
    take_snapshot(conn, "pre_audit", read_rules(), read_trust_file(), read_conf())
    conn.close()

    write_rules()
    write_trust_file()
    set_permissive(True)

    if not fapolicyd_is_active():
        ok = start_fapolicyd()
    else:
        ok = reload_fapolicyd()
        # Also restart to pick up conf changes
        subprocess.run(
            ["systemctl", "restart", "fapolicyd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ok = fapolicyd_is_active()

    if ok:
        info("Audit mode active — denials logged but NOT blocked")
        ccdc_log("audit_enabled")
    else:
        error("Failed to activate audit mode")
    return ok


# ---------------------------------------------------------------------------
# Enforce mode
# ---------------------------------------------------------------------------

def enable_enforce_mode():
    # type: () -> bool
    """
    Enable fapolicyd enforcement.

    1. Run service pre-flight (auto-add unpackaged service binaries).
    2. Snapshot current state.
    3. Write rules + trust file.
    4. Set permissive=0.
    5. (Re)start fapolicyd.
    6. Wait 3 s, check all previously-active services.
    7. Auto-rollback if any service died.
    """
    if not install_fapolicyd():
        return False

    # Step 1 — pre-flight
    info("Running service pre-flight check…")
    preflight_services(verbose=True)

    # Record services that are active right now (before we enforce)
    active_before = get_active_service_names()
    info("Active services before enforce: {}".format(len(active_before)))

    # Step 2 — snapshot
    conn = get_conn()
    take_snapshot(conn, "pre_enforce", read_rules(), read_trust_file(), read_conf())
    conn.close()

    # Step 3 — write rules + trust
    write_rules()
    write_trust_file()

    # Step 4 — set enforcement mode
    set_permissive(False)

    # Step 5 — start / restart
    if not fapolicyd_is_active():
        ok = start_fapolicyd()
    else:
        result = subprocess.run(
            ["systemctl", "restart", "fapolicyd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ok = result.returncode == 0
        if ok:
            info("fapolicyd restarted")

    if not ok:
        error("fapolicyd failed to start — aborting enforce")
        ccdc_log("enforce_failed", detail="fapolicyd did not start")
        return False

    # Step 6 — post-check
    info("Waiting 3 s for services to settle…")
    time.sleep(3)

    failed_services = []
    for svc in active_before:
        if not is_service_active(svc):
            failed_services.append(svc)

    if failed_services:
        critical("Services died after enforcement: {}".format(
            ", ".join(failed_services)))
        ccdc_log("enforce_rollback_triggered",
                 detail="dead_services={}".format(",".join(failed_services)))
        # Step 7 — auto-rollback
        from .recovery import do_rollback
        do_rollback()
        return False

    info("All services healthy. Enforcement is ACTIVE.")
    ccdc_log("enforce_enabled",
             detail="active_services={}".format(len(active_before)))
    return True
