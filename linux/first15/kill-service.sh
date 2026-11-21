#!/bin/sh
# killsvc.sh - stop and disable a service on systemd, OpenRC, or SysV/TinyCore.
# Usage: killsvc.sh <service>   (run as root)

[ "$#" -eq 1 ] || { echo "Usage: $0 <service>" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Must be run as root" >&2; exit 1; }

svc=$1
has() { command -v "$1" >/dev/null 2>&1; }

if [ -d /run/systemd/system ] && has systemctl; then
    # systemd
    systemctl stop "$svc"
    systemctl disable "$svc"

elif has rc-service && has rc-update; then
    # OpenRC (del without a runlevel removes it from all runlevels)
    rc-service "$svc" stop
    rc-update del "$svc"

else
    # SysV init (incl. TinyCore)
    for dir in /etc/init.d /usr/local/etc/init.d; do
        if [ -x "$dir/$svc" ]; then
            "$dir/$svc" stop
            break
        fi
    done

    if has update-rc.d; then
        update-rc.d -f "$svc" remove
    elif has chkconfig; then
        chkconfig "$svc" off
    elif [ -f /opt/bootlocal.sh ]; then
        # TinyCore: services start from bootlocal.sh, so drop the entry
        tmp=$(mktemp) || exit 1
        grep -vF "init.d/$svc" /opt/bootlocal.sh > "$tmp"
        cat "$tmp" > /opt/bootlocal.sh
        rm -f "$tmp"
        has filetool.sh && filetool.sh -b >/dev/null 2>&1  # persist change
    fi
fi
