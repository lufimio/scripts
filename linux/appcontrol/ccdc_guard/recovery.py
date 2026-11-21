"""
Snapshot and rollback for fapolicyd configuration.

A snapshot captures rules, trust file, and fapolicyd.conf at a point in time.
Rollback restores the most recent snapshot and restarts fapolicyd.
"""

import os
import subprocess

from .db import get_conn, save_snapshot, latest_snapshot
from .logger import ccdc_log, info, warn, error, critical


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

def take_snapshot(conn, description, rules_content, trust_content, conf_content):
    """Save current fapolicyd state to the DB snapshots table."""
    save_snapshot(conn, description, rules_content, trust_content, conf_content)
    info("Snapshot saved: {}".format(description))
    ccdc_log("snapshot_saved", detail=description)


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

def do_rollback():
    """
    Restore the most recent snapshot: rewrite rules, trust, and conf files,
    then restart fapolicyd.
    """
    # Import here to avoid circular imports at module level
    from .enforcement import (
        get_rules_path, get_trust_path,
        FAPOLICYD_CONF, fapolicyd_is_active,
    )

    conn = get_conn()
    snap = latest_snapshot(conn)
    conn.close()

    if snap is None:
        critical("No snapshot found — cannot rollback")
        ccdc_log("rollback_failed", detail="no snapshot")
        return False

    critical("ROLLING BACK to snapshot: {}".format(snap["description"]))

    rules_path = get_rules_path()
    trust_path = get_trust_path()

    # Restore rules
    if snap["rules_content"] is not None:
        _write_file(rules_path, snap["rules_content"])
        info("Rules restored to {}".format(rules_path))

    # Restore trust file
    if snap["trust_content"] is not None:
        trust_dir = os.path.dirname(trust_path)
        if trust_dir:
            os.makedirs(trust_dir, exist_ok=True)
        _write_file(trust_path, snap["trust_content"])
        info("Trust file restored to {}".format(trust_path))

    # Restore conf
    if snap["conf_content"] is not None:
        _write_file(FAPOLICYD_CONF, snap["conf_content"])
        info("fapolicyd.conf restored")

    # Restart fapolicyd
    if fapolicyd_is_active():
        result = subprocess.run(
            ["systemctl", "restart", "fapolicyd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            info("fapolicyd restarted after rollback")
            ccdc_log("rollback_complete", detail="snapshot={}".format(snap["description"]))
            return True
        else:
            error("fapolicyd restart failed after rollback")
    else:
        # fapolicyd wasn't running before — stop it to restore that state
        subprocess.run(
            ["systemctl", "stop", "fapolicyd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        info("fapolicyd stopped (was not running in snapshot)")
        ccdc_log("rollback_complete", detail="fapolicyd_stopped")
        return True

    return False


def _write_file(path, content):
    # type: (str, str) -> None
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
