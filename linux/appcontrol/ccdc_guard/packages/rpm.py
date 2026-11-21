"""
RPM package trust backend.

Uses `rpm -qla` to list every file owned by any installed package, and
`rpm -qf <path>` to check whether a specific file is package-managed.
"""

import subprocess
from typing import Set


def get_all_package_files():
    # type: () -> Set[str]
    """Return the set of all file paths owned by any RPM package."""
    try:
        result = subprocess.run(
            ["rpm", "-qla"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            return set()
        lines = result.stdout.decode("utf-8", errors="replace").splitlines()
        return {line.strip() for line in lines if line.strip().startswith("/")}
    except FileNotFoundError:
        return set()


def is_package_owned(path):
    # type: (str) -> bool
    """Return True if *path* is owned by an installed RPM package."""
    try:
        result = subprocess.run(
            ["rpm", "-qf", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
