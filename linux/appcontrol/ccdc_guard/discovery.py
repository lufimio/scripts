"""
Inventory: running processes, systemd services, executables on PATH.
Distro detection and package-backend selection also live here.
"""

import os
import re
import subprocess
from typing import Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------

def read_os_release():
    # type: () -> Dict[str, str]
    fields = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        if not os.path.isfile(path):
            continue
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if "=" not in line or line.startswith("#"):
                    continue
                key, _, val = line.partition("=")
                fields[key.strip()] = val.strip().strip('"')
        break
    return fields


def detect_distro():
    # type: () -> str
    """Return 'rpm', 'deb', or 'apk' based on /etc/os-release."""
    info = read_os_release()
    rpm_ids = {"rhel", "fedora", "rocky", "almalinux", "centos"}
    # Check ID and ID_LIKE
    distro_id = info.get("ID", "").lower()
    id_like = info.get("ID_LIKE", "").lower()

    if distro_id == "alpine":
        return "apk"

    if distro_id in rpm_ids:
        return "rpm"
    for token in id_like.split():
        if token in rpm_ids:
            return "rpm"

    deb_ids = {"debian", "ubuntu"}
    if distro_id in deb_ids:
        return "deb"
    for token in id_like.split():
        if token in deb_ids:
            return "deb"

    # Fallback: probe for package manager binaries
    if _cmd_exists("apk"):
        return "apk"
    if _cmd_exists("rpm"):
        return "rpm"
    if _cmd_exists("dpkg"):
        return "deb"
    return "rpm"  # best guess


def _cmd_exists(name):
    # type: (str) -> bool
    try:
        subprocess.run(
            ["which", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except FileNotFoundError:
        return False


def get_package_backend():
    """Return the appropriate package backend module."""
    distro = detect_distro()
    if distro == "deb":
        from .packages import deb as backend
    elif distro == "apk":
        from .packages import apk as backend
    else:
        from .packages import rpm as backend
    return backend


# ---------------------------------------------------------------------------
# Running processes
# ---------------------------------------------------------------------------

def get_running_processes():
    # type: () -> List[Dict]
    """Return list of dicts with pid, exe, cmdline for each running process."""
    procs = []
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,exe,args", "--no-headers"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            return _fallback_proc_scan()
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            pid = parts[0]
            exe = parts[1]
            cmdline = parts[2] if len(parts) > 2 else ""
            if exe and exe != "-":
                procs.append({"pid": pid, "exe": exe, "cmdline": cmdline})
    except Exception:
        return _fallback_proc_scan()
    return procs


def _fallback_proc_scan():
    # type: () -> List[Dict]
    """Walk /proc/<pid>/exe as a fallback."""
    procs = []
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            exe_link = "/proc/{}/exe".format(entry)
            try:
                exe = os.readlink(exe_link)
                # strip " (deleted)" suffix if present
                exe = exe.replace(" (deleted)", "")
                cmdline_path = "/proc/{}/cmdline".format(entry)
                cmdline = ""
                if os.path.isfile(cmdline_path):
                    with open(cmdline_path, "rb") as fh:
                        cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                procs.append({"pid": entry, "exe": exe, "cmdline": cmdline})
            except OSError:
                continue
    except OSError:
        pass
    return procs


# ---------------------------------------------------------------------------
# Executables on $PATH
# ---------------------------------------------------------------------------

def get_path_executables():
    # type: () -> List[str]
    """Return list of executable file paths found on the system PATH."""
    seen = set()  # type: Set[str]
    result = []
    path_dirs = os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").split(":")
    # Also scan standard dirs even if not on PATH
    for extra in ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"):
        if extra not in path_dirs:
            path_dirs.append(extra)
    for d in path_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                if fpath in seen:
                    continue
                seen.add(fpath)
                if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                    result.append(fpath)
        except OSError:
            continue
    return result


# ---------------------------------------------------------------------------
# Systemd service exec paths
# ---------------------------------------------------------------------------

_EXEC_DIRECTIVES = re.compile(
    r"^\s*Exec(?:Start|StartPre|StartPost|Stop|Reload)\s*=\s*(.+)$",
    re.IGNORECASE,
)
# Env-var substitution prefixes fapolicyd doesn't care about
_EXEC_PREFIX = re.compile(r"^[@!+\-]+")


def _strip_exec_modifiers(value):
    # type: (str) -> str
    """Strip systemd exec-line prefixes (@, !, +, -) and leading whitespace."""
    value = value.strip()
    value = _EXEC_PREFIX.sub("", value)
    # Only want the first token (the binary path, not its args)
    parts = value.split()
    if not parts:
        return ""
    candidate = parts[0]
    # Discard env-var style values like ${VAR}
    if candidate.startswith("$"):
        return ""
    return candidate


def parse_unit_file_execs(unit_file_path):
    # type: (str) -> List[str]
    """Extract all executable paths referenced in a systemd unit file."""
    paths = []
    try:
        with open(unit_file_path, errors="replace") as fh:
            for line in fh:
                m = _EXEC_DIRECTIVES.match(line)
                if not m:
                    continue
                path = _strip_exec_modifiers(m.group(1))
                if path and path.startswith("/"):
                    paths.append(path)
    except OSError:
        pass
    return paths


def get_active_services():
    # type: () -> List[Dict]
    """
    Return list of dicts describing each active systemd service and the
    exec paths found in its unit file.

    Each dict: { 'name': str, 'unit_file': str, 'exec_paths': [str] }
    """
    services = []
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=active",
             "--no-legend", "--no-pager", "--plain"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            return services
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if not parts:
                continue
            unit_name = parts[0]
            # Resolve the unit file path
            unit_file = _resolve_unit_file(unit_name)
            exec_paths = []
            if unit_file:
                exec_paths = parse_unit_file_execs(unit_file)
            services.append({
                "name": unit_name,
                "unit_file": unit_file or "",
                "exec_paths": exec_paths,
            })
    except Exception:
        pass
    return services


def _resolve_unit_file(unit_name):
    # type: (str) -> str
    """Return the path of the unit file for the given unit name, or empty string."""
    try:
        result = subprocess.run(
            ["systemctl", "show", "-p", "FragmentPath", "--value", unit_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            path = result.stdout.decode("utf-8", errors="replace").strip()
            if path and os.path.isfile(path):
                return path
    except Exception:
        pass
    return ""


def get_active_service_names():
    # type: () -> List[str]
    """Return just the list of currently active systemd service unit names."""
    names = []
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=active",
             "--no-legend", "--no-pager", "--plain"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            return names
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if parts:
                names.append(parts[0])
    except Exception:
        pass
    return names


def is_service_active(service_name):
    # type: (str) -> bool
    """Return True if the named systemd service is currently active."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        output = result.stdout.decode("utf-8", errors="replace").strip()
        return output == "active"
    except Exception:
        return False
