"""
Systemd drop-in security hardening generator.

Preview-only — prints the drop-in content to stdout but does NOT write
any files. The operator reviews and applies manually.

Restrictions applied follow systemd security best practices and are
appropriate for most network-facing services in a CCDC environment.
"""

import os
import subprocess
from typing import List, Optional, Tuple

from .logger import warn, BLUE, YELLOW, NC


# Each entry is either ("# comment text", None) or ("Key", "value").
_RESTRICTIONS = [
    ("# Privilege escalation", None),
    ("NoNewPrivileges",           "true"),
    ("# Filesystem access", None),
    ("ProtectSystem",             "strict"),
    ("ProtectHome",               "true"),
    ("PrivateTmp",                "true"),
    ("PrivateDevices",            "true"),
    ("ProtectKernelTunables",     "true"),
    ("ProtectKernelModules",      "true"),
    ("ProtectKernelLogs",         "true"),
    ("ProtectControlGroups",      "true"),
    ("# Network", None),
    ("RestrictAddressFamilies",   "AF_INET AF_INET6 AF_UNIX"),
    ("# System call filtering", None),
    ("SystemCallArchitectures",   "native"),
    ("RestrictNamespaces",        "true"),
    ("LockPersonality",           "true"),
    ("MemoryDenyWriteExecute",    "true"),
    ("RestrictRealtime",          "true"),
    ("RestrictSUIDSGID",          "true"),
    ("# Capabilities", None),
    ("CapabilityBoundingSet",     ""),
    ("AmbientCapabilities",       ""),
]

# Services that need extra capabilities — skip capability stripping for these
_HIGH_PRIV_SERVICES = {
    "sshd.service", "ssh.service",
    "NetworkManager.service",
    "systemd-networkd.service",
    "auditd.service",
    "fapolicyd.service",
}


def generate_dropin(service_name):
    # type: (str) -> str
    """
    Generate a systemd drop-in security configuration for *service_name*.
    Returns the content as a string (preview only — does not write to disk).
    """
    if not service_name.endswith(".service"):
        service_name = service_name + ".service"

    high_priv = service_name in _HIGH_PRIV_SERVICES

    user       = _get_unit_property(service_name, "User") or "root"
    working_dir = _get_unit_property(service_name, "WorkingDirectory") or "/"

    lines = [
        "# ccdc-guard hardening drop-in for {}".format(service_name),
        "# Generated as a PREVIEW — review before applying.",
        "# To apply: install at /etc/systemd/system/{}.d/50-ccdc-harden.conf".format(
            service_name),
        "# Then: systemctl daemon-reload && systemctl restart {}".format(service_name),
        "#",
        "# Service info: User={} WorkingDirectory={}".format(user, working_dir),
        "",
        "[Service]",
    ]

    _skip_caps = {"CapabilityBoundingSet", "AmbientCapabilities"}

    for key, value in _RESTRICTIONS:
        if value is None:
            # This is a comment section header
            lines.append("")
            lines.append(key)
            continue
        # Skip capability stripping for privileged services
        if high_priv and key in _skip_caps:
            lines.append("# SKIPPED for privileged service: {}={}".format(key, value))
            continue
        lines.append("{}={}".format(key, value))

    return "\n".join(lines) + "\n"


def _get_unit_property(service_name, prop):
    # type: (str, str) -> Optional[str]
    try:
        result = subprocess.run(
            ["systemctl", "show", "-p", prop, "--value", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            val = result.stdout.decode("utf-8", errors="replace").strip()
            return val if val else None
    except Exception:
        pass
    return None


def show_harden_preview(service_name):
    # type: (str) -> None
    """Print the drop-in preview with coloured headers."""
    if not service_name.endswith(".service"):
        service_name_full = service_name + ".service"
    else:
        service_name_full = service_name

    # Check the service exists on this host
    result = subprocess.run(
        ["systemctl", "show", service_name_full, "--no-pager"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        warn("Service '{}' not found — generating generic drop-in".format(
            service_name_full))

    content = generate_dropin(service_name_full)

    drop_in_path = "/etc/systemd/system/{}.d/50-ccdc-harden.conf".format(
        service_name_full)

    print("")
    print("{}=== Hardening drop-in preview for {} ==={}".format(
        BLUE, service_name_full, NC))
    print("{}Would be written to:{} {}".format(YELLOW, NC, drop_in_path))
    print("")
    print(content)
    print("{}NOTE: This is a preview. No files have been written.{}".format(
        YELLOW, NC))
    print("To apply:")
    print("  mkdir -p {}".format(os.path.dirname(drop_in_path)))
    print("  # pipe the preview output into the drop-in path, then:")
    print("  systemctl daemon-reload && systemctl restart {}".format(service_name_full))
    print("")
