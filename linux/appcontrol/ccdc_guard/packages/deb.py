"""
DEB package trust backend.

Reads /var/lib/dpkg/info/*.list files for the full set of package-owned paths,
and uses `dpkg -S <path>` for per-file ownership checks.
"""

import glob
import os
import subprocess
from typing import Set


def get_all_package_files():
    # type: () -> Set[str]
    """Return the set of all file paths owned by any installed DEB package."""
    owned = set()
    list_dir = "/var/lib/dpkg/info"
    if not os.path.isdir(list_dir):
        return owned
    pattern = os.path.join(list_dir, "*.list")
    for list_file in glob.glob(pattern):
        try:
            with open(list_file, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("/"):
                        owned.add(line)
        except OSError:
            continue
    return owned


def is_package_owned(path):
    # type: (str) -> bool
    """Return True if *path* is owned by an installed DEB package."""
    try:
        result = subprocess.run(
            ["dpkg", "-S", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
