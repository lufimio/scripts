"""
JSON + syslog logging — matches the CCDC repo-wide log format exactly.
Every log line written to /var/log/ccdc/changes.log and forwarded to syslog.
"""

import json
import os
import subprocess
import socket
from datetime import datetime, timezone

CCDC_LOG = "/var/log/ccdc/changes.log"

# ---------------------------------------------------------------------------
# Terminal colour helpers
# ---------------------------------------------------------------------------

RED    = '\033[0;31m'
GREEN  = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE   = '\033[0;34m'
NC     = '\033[0m'


def info(msg):
    print("{}[INFO]{} {}".format(GREEN, NC, msg))


def warn(msg):
    print("{}[WARN]{} {}".format(YELLOW, NC, msg))


def error(msg):
    print("{}[ERROR]{} {}".format(RED, NC, msg))


def critical(msg):
    print("{}[CRIT]{} {}".format(RED, NC, msg))


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------

def ccdc_log(action, path="", detail=""):
    """Write a JSON line to /var/log/ccdc/changes.log and to syslog."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    host = socket.gethostname().split(".")[0]
    path_s = str(path).replace('"', '\\"')
    detail_s = str(detail).replace('"', '\\"')
    record = {
        "ts": ts,
        "host": host,
        "script": "ccdc-guard",
        "action": action,
        "path": path_s,
        "detail": detail_s,
    }
    try:
        os.makedirs("/var/log/ccdc", exist_ok=True)
        with open(CCDC_LOG, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass
    try:
        subprocess.run(
            ["logger", "-t", "ccdc-guard",
             "action={} path={} {}".format(action, path_s, detail_s)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception:
        pass
