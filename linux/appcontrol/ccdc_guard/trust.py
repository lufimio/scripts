"""
Trust baseline: SHA-256 hashing, trust entry management, service pre-flight.

trust=1  → package-managed (we record it but fapolicyd reads from the package DB)
trust=2  → user trust file  (we write /etc/fapolicyd/trust.d/ccdc.trust)
"""

import hashlib
import os
import stat
from typing import Dict, List, Optional, Tuple

from .db import (
    get_conn, upsert_trust, remove_trust, get_trust,
    list_trust, record_approval, upsert_service_manifest,
)
from .discovery import (
    get_active_services, get_path_executables, get_package_backend,
)
from .logger import ccdc_log, info, warn, error


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_file(path):
    # type: (str) -> Optional[str]
    """Return the hex SHA-256 of *path*, or None if the file cannot be read."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def file_size(path):
    # type: (str) -> Optional[int]
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _is_elf(path):
    # type: (str) -> bool
    """Return True if the file looks like an ELF binary (magic bytes \x7fELF)."""
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
        return magic == b"\x7fELF"
    except OSError:
        return False


def _is_executable(path):
    # type: (str) -> bool
    try:
        st = os.stat(path)
        return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Baseline generation
# ---------------------------------------------------------------------------

def build_baseline(verbose=True):
    # type: (bool) -> Dict
    """
    Inventory executables and classify them as package-managed (trust=1)
    or unpackaged (trust=2 candidates flagged for review).

    Returns summary dict.
    """
    backend = get_package_backend()
    if verbose:
        info("Loading package file list (may take a moment)…")
    pkg_files = backend.get_all_package_files()
    if verbose:
        info("Package-managed files: {}".format(len(pkg_files)))

    executables = get_path_executables()
    if verbose:
        info("Executables found on PATH: {}".format(len(executables)))

    conn = get_conn()
    trusted_pkg = 0
    custom_found = 0
    errors_count = 0

    for path in executables:
        if not os.path.isfile(path):
            continue
        digest = sha256_file(path)
        if digest is None:
            errors_count += 1
            continue
        size = file_size(path)
        if path in pkg_files:
            source = "package"
            trusted_pkg += 1
        else:
            source = "custom"
            custom_found += 1
            if verbose:
                warn("Unpackaged executable: {}".format(path))
        upsert_trust(conn, path, digest, size, source)

    conn.close()
    summary = {
        "package_managed": trusted_pkg,
        "custom": custom_found,
        "errors": errors_count,
    }
    ccdc_log("baseline_complete",
             detail="pkg={} custom={} errors={}".format(
                 trusted_pkg, custom_found, errors_count))
    return summary


# ---------------------------------------------------------------------------
# Service pre-flight
# ---------------------------------------------------------------------------

def preflight_services(verbose=True):
    # type: (bool) -> List[Dict]
    """
    Before enforcement: enumerate active service exec paths.
    Auto-add unpackaged ones to trust=2 with a warning.

    Returns list of service manifest dicts.
    """
    backend = get_package_backend()
    pkg_files = backend.get_all_package_files()
    services = get_active_services()
    conn = get_conn()
    manifest = []

    for svc in services:
        for exec_path in svc["exec_paths"]:
            if not os.path.isfile(exec_path):
                continue
            is_pkg = exec_path in pkg_files
            auto_added = False

            if not is_pkg:
                digest = sha256_file(exec_path)
                size = file_size(exec_path)
                if digest is not None:
                    if verbose:
                        warn(
                            "Service {} uses unpackaged binary {} — "
                            "auto-adding to trust=2".format(svc["name"], exec_path)
                        )
                    upsert_trust(conn, exec_path, digest, size, "service_auto",
                                 notes="auto-added for service {}".format(svc["name"]))
                    auto_added = True
                    ccdc_log("service_auto_trust", path=exec_path,
                             detail="service={}".format(svc["name"]))

            upsert_service_manifest(
                conn,
                service_name=svc["name"],
                exec_path=exec_path,
                was_trusted=1 if is_pkg else 0,
                auto_added=1 if auto_added else 0,
            )
            manifest.append({
                "service": svc["name"],
                "exec_path": exec_path,
                "was_trusted": is_pkg,
                "auto_added": auto_added,
            })

    conn.close()
    return manifest


# ---------------------------------------------------------------------------
# approve / update / revoke
# ---------------------------------------------------------------------------

def approve_file(path, notes=""):
    # type: (str, str) -> bool
    """Add *path* to user trust (trust=2). Returns True on success."""
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        error("File not found: {}".format(path))
        return False
    digest = sha256_file(path)
    if digest is None:
        error("Cannot read file: {}".format(path))
        return False
    size = file_size(path)
    conn = get_conn()
    existing = get_trust(conn, path)
    if existing and existing["source"] == "user":
        warn("{} is already approved (sha256 unchanged)".format(path))
        conn.close()
        return True
    upsert_trust(conn, path, digest, size, "user", notes=notes)
    record_approval(conn, path, digest, "approve", notes=notes)
    conn.close()
    info("Approved: {} [{}]".format(path, digest[:16]))
    ccdc_log("approve", path=path, detail="sha256={}".format(digest))
    return True


def update_file(path, notes=""):
    # type: (str, str) -> bool
    """Re-hash *path* and update its trust record. Returns True on success."""
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        error("File not found: {}".format(path))
        return False
    conn = get_conn()
    existing = get_trust(conn, path)
    if existing is None:
        warn("{} is not in trust DB — use 'approve' first".format(path))
        conn.close()
        return False
    digest = sha256_file(path)
    if digest is None:
        error("Cannot read file: {}".format(path))
        conn.close()
        return False
    size = file_size(path)
    old_hash = existing["sha256"]
    upsert_trust(conn, path, digest, size, existing["source"], notes=notes)
    record_approval(conn, path, digest, "update",
                    notes="was={}".format(old_hash[:16]))
    conn.close()
    info("Updated: {} [{}]".format(path, digest[:16]))
    ccdc_log("update_trust", path=path,
             detail="old={} new={}".format(old_hash[:16], digest[:16]))
    return True


def revoke_file(path):
    # type: (str) -> bool
    """Remove *path* from trust DB. Returns True on success."""
    path = os.path.realpath(path)
    conn = get_conn()
    existing = get_trust(conn, path)
    if existing is None:
        warn("{} is not in trust DB".format(path))
        conn.close()
        return False
    old_hash = existing["sha256"]
    remove_trust(conn, path)
    record_approval(conn, path, old_hash, "revoke")
    conn.close()
    info("Revoked: {}".format(path))
    ccdc_log("revoke_trust", path=path, detail="sha256={}".format(old_hash))
    return True


# ---------------------------------------------------------------------------
# Trust file generation (called by enforcement.py)
# ---------------------------------------------------------------------------

def generate_trust_lines(conn):
    # type: (...) -> str
    """
    Generate the content for the fapolicyd user trust file.
    Only include entries with source in ('user', 'service_auto', 'custom').
    Format: /path SIZE SHA256
    """
    rows = list_trust(conn)
    lines = []
    include_sources = {"user", "service_auto", "custom"}
    for row in rows:
        if row["source"] not in include_sources:
            continue
        size = row["size"] if row["size"] is not None else 0
        lines.append("{} {} {}".format(row["path"], size, row["sha256"]))
    return "\n".join(lines) + ("\n" if lines else "")
