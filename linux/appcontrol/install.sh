#!/usr/bin/env bash
# install.sh — install ccdc-guard on a single host.
# Must be run as root.
set -euo pipefail

INSTALL_SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DEST="/opt/ccdc-guard"
BIN_LINK="/usr/local/bin/ccdc-guard"
STATE_DIR="/var/lib/ccdc-guard"
LOG_DIR="/var/log/ccdc"

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: install.sh must be run as root" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            rhel|fedora|rocky|almalinux|centos) echo "rpm"; return ;;
        esac
        case "${ID_LIKE:-}" in
            *rhel*|*fedora*|*centos*) echo "rpm"; return ;;
        esac
        case "${ID:-}" in
            alpine) echo "apk"; return ;;
        esac
        case "${ID:-}" in
            debian|ubuntu) echo "deb"; return ;;
        esac
        case "${ID_LIKE:-}" in
            *debian*) echo "deb"; return ;;
        esac
    fi
    # Fallback: probe package manager binaries
    if command -v apk &>/dev/null; then echo "apk"; return; fi
    if command -v rpm &>/dev/null; then echo "rpm"; return; fi
    if command -v dpkg &>/dev/null; then echo "deb"; return; fi
    echo "rpm"  # best guess
}

DISTRO="$(detect_distro)"
echo "Detected distro type: $DISTRO"

# ---------------------------------------------------------------------------
# Install Python 3
# ---------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
    echo "Installing Python 3..."
    if [[ "$DISTRO" == "deb" ]]; then
        apt-get update -y -q
        apt-get install -y python3
    elif [[ "$DISTRO" == "apk" ]]; then
        apk add --no-cache python3
    else
        if command -v dnf &>/dev/null; then
            dnf install -y python3
        else
            yum install -y python3
        fi
    fi
fi
echo "Python 3: $(python3 --version)"

# ---------------------------------------------------------------------------
# Install fapolicyd (do NOT start it yet)
# ---------------------------------------------------------------------------
install_fapolicyd=false
if ! command -v fapolicyd &>/dev/null && [[ ! -f /usr/sbin/fapolicyd ]]; then
    install_fapolicyd=true
fi

if $install_fapolicyd; then
    # fapolicyd is an RPM-ecosystem tool; not available on Debian/Ubuntu or Alpine
    if [[ "$DISTRO" == "rpm" ]]; then
        echo "Installing fapolicyd (not starting)..."
        if command -v dnf &>/dev/null; then
            dnf install -y fapolicyd
        else
            yum install -y fapolicyd
        fi
        # Prevent autostart on install
        systemctl disable fapolicyd 2>/dev/null || true
        systemctl stop fapolicyd 2>/dev/null || true
        echo "fapolicyd installed (not started)"
    else
        echo "Skipping fapolicyd: only supported on RPM-based distros (Rocky/Fedora/RHEL)"
    fi
else
    echo "fapolicyd already installed"
fi

# ---------------------------------------------------------------------------
# Copy package files
# ---------------------------------------------------------------------------
echo "Installing ccdc-guard to $INSTALL_DEST..."
mkdir -p "$INSTALL_DEST"

# Copy everything from appcontrol/ (we may be called from /tmp/ccdc-guard-pkg/
# where the full appcontrol dir was SCP'd, so INSTALL_SRC is that directory)
cp -r "$INSTALL_SRC/ccdc_guard" "$INSTALL_DEST/"
cp "$INSTALL_SRC/ccdc-guard"    "$INSTALL_DEST/"

chmod +x "$INSTALL_DEST/ccdc-guard"

# ---------------------------------------------------------------------------
# Symlink
# ---------------------------------------------------------------------------
ln -sf "$INSTALL_DEST/ccdc-guard" "$BIN_LINK"
echo "Symlink: $BIN_LINK -> $INSTALL_DEST/ccdc-guard"

# ---------------------------------------------------------------------------
# State + log directories
# ---------------------------------------------------------------------------
mkdir -p "$STATE_DIR" "$LOG_DIR"
chmod 750 "$STATE_DIR"
chmod 755 "$LOG_DIR"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "ccdc-guard installed. Run: ccdc-guard baseline"
