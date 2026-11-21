"""
APK package trust backend (Alpine Linux).

Uses `apk info -L <pkg>` to list files owned by a package, and
`apk info --who-owns <path>` to check whether a specific file is package-managed.
"""

import subprocess
from typing import Set


def get_all_package_files():
    # type: () -> Set[str]
    """Return the set of all file paths owned by any installed APK package."""
    try:
        # List all installed packages first
        pkg_result = subprocess.run(
            ["apk", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if pkg_result.returncode != 0:
            return set()
        packages = pkg_result.stdout.decode("utf-8", errors="replace").splitlines()

        owned = set()
        for pkg in packages:
            pkg = pkg.strip()
            if not pkg:
                continue
            result = subprocess.run(
                ["apk", "info", "-L", pkg],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("/"):
                    owned.add(line)
        return owned
    except FileNotFoundError:
        return set()


def is_package_owned(path):
    # type: (str) -> bool
    """Return True if *path* is owned by an installed APK package."""
    try:
        result = subprocess.run(
            ["apk", "info", "--who-owns", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
