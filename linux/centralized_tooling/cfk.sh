#!/usr/bin/env bash

if [ -z "${CCDC_CRFIX:-}" ] && grep -qs $'\r' "$0"; then find "$(dirname -- "$0")" -type f -name '*.sh' -not -path '*/.git/*' -exec sed -i 's/\r$//' {} + ; CCDC_CRFIX=1 exec bash "$0" "$@"; fi #

set +x
set -euo pipefail


ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SELF="$ROOT/$(basename -- "${BASH_SOURCE[0]}")"
INVENTORY="${CCDC_HOSTS:-$ROOT/hosts.yml}"

usage() {
    echo "Usage: $0 [-s|--sudo] [-q|--quiet] HOST|@lin|@win|@all SCRIPT [SCRIPT_ARGS...]" >&2
    echo "  -s, --sudo    Run the script via sudo on Linux hosts (password from inventory)" >&2
    echo "  -q, --quiet   Print only the script output (no banners, separators, or summary)" >&2
    exit 2
}

# CCDC_SUDO / CCDC_QUIET let batch mode pass the options down to per-host invocations.
use_sudo="${CCDC_SUDO:-0}"
quiet="${CCDC_QUIET:-0}"
while (( $# > 0 )); do
    case "$1" in
        -s|--sudo) use_sudo=1; shift ;;
        -q|--quiet) quiet=1; shift ;;
        -h|--help) usage ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; usage ;;
        *) break ;;
    esac
done

# Informational output only; suppressed in quiet mode. Errors still go to stderr.
say() { [[ "$quiet" == 1 ]] || printf '%s\n' "$*"; }
sayerr() { [[ "$quiet" == 1 ]] || printf '%s\n' "$*" >&2; }

(( $# >= 2 )) || usage
target="$1"
requested="$2"
shift 2

if [[ -n "${CCDC_INPUT_FD:-}" && "$target" == @* ]]; then
    echo 'fd 3 input requires a single host; the controller supplies one stream per host' >&2
    exit 1
fi

for tool in yq jq base64; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing dependency: $tool" >&2; exit 1; }
done
[[ -r "$INVENTORY" ]] || { echo "Cannot read inventory: $INVENTORY" >&2; exit 1; }

# Supports both the Go yq v4 and the jq-based yq typically packaged on Kali.
if yq --version 2>&1 | grep -qi mikefarah; then
    inventory_json="$(yq -o=json '.' "$INVENTORY")"
else
    inventory_json="$(yq -c '.' "$INVENTORY")"
fi
jq -e 'type == "object"' <<<"$inventory_json" >/dev/null || {
    echo "Inventory must be a YAML mapping of hostname -> settings" >&2
    exit 1
}

script_for_os() {
    local name="$1" os="$2"
    case "$os" in
        lin)
            case "$name" in
                *.ps1) printf '%s.sh' "${name%.ps1}" ;;
                *.sh|*.py) printf '%s' "$name" ;;
                *) printf '%s.sh' "$name" ;;
            esac
            ;;
        win)
            case "$name" in
                *.sh) printf '%s.ps1' "${name%.sh}" ;;
                *.ps1) printf '%s' "$name" ;;
                *) printf '%s.ps1' "$name" ;;
            esac
            ;;
        *) echo "Invalid OS: $os" >&2; return 1 ;;
    esac
}

# Batch mode: select matching hosts, run one at a time, Linux before Windows.
case "$target" in
    @lin|@win|@all)
        mapfile -t hosts < <(jq -r --arg select "$target" '
            [to_entries[]
             | select(.value.os == "lin" or .value.os == "win")
             | select($select == "@all" or
                      ($select == "@lin" and .value.os == "lin") or
                      ($select == "@win" and .value.os == "win"))]
            | sort_by(if .value.os == "lin" then 0 else 1 end)
            | .[].key
        ' <<<"$inventory_json")

        (( ${#hosts[@]} > 0 )) || { echo "No matching hosts for $target" >&2; exit 1; }

        # Check scripts for all target OSes BEFORE changing any host.
        declare -a scripts=()
        for host in "${hosts[@]}"; do
            os="$(jq -r --arg h "$host" '.[$h].os' <<<"$inventory_json")"
            script="$(script_for_os "$requested" "$os")"
            [[ "$script" = /* ]] || script="$ROOT/$script"
            [[ -f "$script" && -r "$script" ]] || {
                echo "Missing script for $host ($os): $script" >&2
                exit 1
            }
            scripts+=("$script")
        done

        successes=0
        failures=0
        for i in "${!hosts[@]}"; do
            host="${hosts[i]}"
            script="${scripts[i]}"
            [[ "$quiet" == 1 ]] || printf '\n=== %s | %s ===\n' "$host" "$script"
            if CCDC_BATCH=1 CCDC_SUDO="$use_sudo" CCDC_QUIET="$quiet" bash "$SELF" "$host" "$script" "$@"; then
                successes=$((successes + 1))
            else
                failures=$((failures + 1))
                sayerr "FAILED: $host"
            fi
        done
        [[ "$quiet" == 1 ]] || printf '\nCompleted: %d succeeded, %d failed\n' "$successes" "$failures"
        (( failures == 0 ))
        exit $?
        ;;
esac

# Single host mode.
entry="$(jq -c --arg h "$target" '.[$h] // empty' <<<"$inventory_json")"
[[ -n "$entry" ]] || { echo "Unknown host: $target" >&2; exit 1; }

ip="$(jq -r '.ip // empty' <<<"$entry")"
user="$(jq -r '.user // empty' <<<"$entry")"
pass="$(jq -r '.pass // empty' <<<"$entry")"
os="$(jq -r '.os // empty' <<<"$entry")"
port="$(jq -r '.port // empty' <<<"$entry")"
[[ -n "$ip" && -n "$user" && -n "$pass" ]] || {
    echo "Host $target requires ip, user, and pass" >&2
    exit 1
}
script="$(script_for_os "$requested" "$os")"
[[ "$script" = /* ]] || script="$ROOT/$script"
[[ -f "$script" && -r "$script" ]] || { echo "Cannot read $script" >&2; exit 1; }

# Quote arguments for a remote POSIX shell / PowerShell.
shquote() { local s=${1//\'/\'\\\'\'}; printf "'%s'" "$s"; }
psquote() { local s=${1//\'/\'\'}; printf "'%s'" "$s"; }

case "$os" in
    lin)
        command -v sshpass >/dev/null 2>&1 || { echo "Missing dependency: sshpass" >&2; exit 1; }
        case "$script" in
            *.sh)
                interpreter=bash
                [[ "${CCDC_POSIX_SH:-0}" != 1 ]] || interpreter='sh'
                placeholder=' ccdc-script'
                ;;
            *.py) interpreter=python3; placeholder='' ;;
            *) echo "Linux scripts must be .sh or .py" >&2; exit 1 ;;
        esac
        port="${port:-22}"
        payload="$(base64 -w0 <"$script")"
        # Quiet mode: have ssh suppress its own warnings/"Connection closed" notices.
        ssh_quiet=()
        [[ "$quiet" == 1 ]] && ssh_quiet=(-q)
        # Execute the local script from memory; stdin remains available for prompts.
        sudo_prefix=""
        [[ "$use_sudo" == 1 ]] && sudo_prefix="sudo -S -p '' -- "
        remote="${sudo_prefix}$interpreter -c \"\$(printf '%s' '$payload' | base64 -d)\"$placeholder"
        for arg in "$@"; do remote+=" $(shquote "$arg")"; done
        if [[ "${CCDC_INPUT_FD:-}" == 3 ]]; then
            [[ "$use_sudo" != 1 ]] || { echo 'Do not combine --sudo with the fd 3 protocol; use CCDC_INPUT_ROOT=1' >&2; exit 1; }
            [[ "$target" != @* ]] || { echo 'fd 3 input requires a single host' >&2; exit 1; }
            remote="PATH=/run/wrappers/bin:/run/current-system/sw/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH; exec 3<&0; exec 0</dev/null; export CCDC_INPUT_FD=3; $remote"
            if [[ "${CCDC_INPUT_ROOT:-0}" == 1 ]]; then
                # Consume the first protocol line before dispatch. sudo askpass
                # leaves the rest of stdin untouched even with cached/NOPASSWD sudo.
                # This helper contains an environment lookup, never a password.
                runner=$(shquote "$remote")
                # Variables in this string expand on the target, not locally.
                # shellcheck disable=SC2016
                remote='set +x
PATH=/run/wrappers/bin:/run/current-system/sw/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
IFS= read -r CCDC_ELEVATION_PASSWORD || exit 1
if [ "$(id -u)" = 0 ]; then
    unset CCDC_ELEVATION_PASSWORD
    sh -c '"$runner"'
else
    command -v sudo >/dev/null 2>&1 || { echo "Root or password-authenticated sudo is required for bootstrap/restore" >&2; exit 1; }
    umask 077
    helper=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-askpass.XXXXXXXX") || exit 1
    trap '\''rm -f "$helper/askpass"; rmdir "$helper"'\'' 0
    trap '\''exit 1'\'' 1 2 3 15
    printf '\''#!/bin/sh\nprintf "%%s\\n" "$CCDC_ELEVATION_PASSWORD"\n'\'' >"$helper/askpass" || exit 1
    chmod 700 "$helper/askpass" || exit 1
    export CCDC_ELEVATION_PASSWORD
    SUDO_ASKPASS="$helper/askpass" sudo -A -k -- sh -c '"$runner"'
fi'
            fi
            auth=()
            if [[ "${CCDC_PASSWORD_ONLY:-0}" == 1 ]]; then
                auth=(-o PubkeyAuthentication=no -o 'PreferredAuthentications=password,keyboard-interactive'
                      -o ControlMaster=no -o ControlPath=none -o NumberOfPasswordPrompts=1)
            fi
            say "[$target] SSH $user@$ip:$port (noninteractive protocol)"
            SSHPASS="$pass" sshpass -e ssh -T "${ssh_quiet[@]}" "${auth[@]}" \
                -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
                -o ServerAliveInterval=10 -o ServerAliveCountMax=2 \
                -p "$port" -- "$user@$ip" "$remote" <&3
        elif [[ -n "${CCDC_INPUT_FD:-}" ]]; then
            echo 'CCDC_INPUT_FD must be 3' >&2
            exit 1
        elif [[ "$use_sudo" == 1 ]]; then
            # sudo -S reads the password from stdin, so pipe it in (never put it
            # on a command line). No TTY is allocated, and the script's own stdin
            # is empty after the password line, so interactive prompts won't work.
            say "[$target] SSH $user@$ip:$port (sudo)"
            printf '%s\n' "$pass" | SSHPASS="$pass" sshpass -e ssh "${ssh_quiet[@]}" \
                -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
                -p "$port" -- "$user@$ip" "$remote"
        else
            say "[$target] SSH $user@$ip:$port"
            tty=()
            [[ -t 0 ]] && tty=(-tt)
            SSHPASS="$pass" sshpass -e ssh "${tty[@]}" "${ssh_quiet[@]}" \
                -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
                -p "$port" -- "$user@$ip" "$remote"
        fi
        ;;
    win)
        for tool in evil-winrm expect; do
            command -v "$tool" >/dev/null 2>&1 || { echo "Missing dependency: $tool" >&2; exit 1; }
        done
        [[ "$script" == *.ps1 ]] || { echo "Windows scripts must be .ps1" >&2; exit 1; }
        if [[ "$use_sudo" == 1 ]]; then
            sayerr "[$target] Note: --sudo only applies to Linux hosts; ignoring for Windows"
        fi
        port="${port:-5985}"
        tmpdir="$(mktemp -d)"
        trap 'rm -rf -- "$tmpdir"' EXIT
        payload="$(base64 -w0 <"$script")"
        {
            printf 'function Invoke-CCDC {\n'
            printf "  \$ErrorActionPreference = 'Stop'\n"
            printf "  \$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))\n" "$payload"
            # These variables belong to PowerShell, not the local shell.
            # shellcheck disable=SC2016
            printf '  $runner = [scriptblock]::Create($source)\n'
            # shellcheck disable=SC2016
            printf '  & $runner'
            for arg in "$@"; do
                if [[ "$arg" =~ ^-[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
                    printf ' %s' "$arg"
                else
                    printf ' %s' "$(psquote "$arg")"
                fi
            done
            printf '\n}\n'
        } >"$tmpdir/ccdc_run.ps1"

        export CCDC_WIN_IP="$ip" CCDC_WIN_USER="$user" CCDC_WIN_PASS="$pass"
        export CCDC_WIN_PORT="$port" CCDC_WIN_DIR="$tmpdir"
        export CCDC_BATCH="${CCDC_BATCH:-0}"
        export CCDC_QUIET="$quiet"
        say "[$target] WinRM $user@$ip:$port"
        expect <<'EXPECT'
set timeout 30
set quiet [expr {$env(CCDC_QUIET) == "1"}]
set prompt {\*Evil-WinRM\* PS [^\r\n]*> ?}
set cmd [list evil-winrm -n -N -i $env(CCDC_WIN_IP) -u $env(CCDC_WIN_USER) \
                -p $env(CCDC_WIN_PASS) -P $env(CCDC_WIN_PORT) -s $env(CCDC_WIN_DIR)]
if {$env(CCDC_WIN_PORT) == "5986"} { lappend cmd -S }
# Hide the spawn command line so the password isn't echoed to the terminal.
log_user 0
spawn {*}$cmd
# In quiet mode keep expect's own output off entirely (banner, prompts, echo).
if {!$quiet} { log_user 1 }
expect {
    -re $prompt { send -- "ccdc_run.ps1\r" }
    timeout { puts stderr "Timed out connecting to WinRM"; exit 1 }
    eof { puts stderr "WinRM disconnected before loading script"; exit 1 }
}
expect {
    -re $prompt {}
    timeout { puts stderr "Timed out loading PowerShell script"; exit 1 }
    eof { puts stderr "WinRM disconnected while loading script"; exit 1 }
}
# Quiet mode always uses the marker path (non-interactive) so the output can be
# captured and cleaned of the echoed command line and markers.
if {$env(CCDC_BATCH) == "1" || $quiet} {
    # The markers are concatenated on the remote side to avoid matching echo.
    send -- {try { Invoke-CCDC; Write-Output ('__CCDC_' + 'OK__') } catch { Write-Host $_; Write-Output ('__CCDC_' + 'FAIL__') }}
    send -- "\r"
    set timeout 600
    expect {
        -re {__CCDC_OK__} { set result 0 }
        -re {__CCDC_FAIL__} { set result 1 }
        timeout { puts stderr "Timed out running PowerShell script"; exit 1 }
        eof { puts stderr "WinRM disconnected during PowerShell script"; exit 1 }
    }
    if {$quiet} {
        set buf $expect_out(buffer)
        # Drop the echoed command line (everything through its first newline).
        set e [string first "'FAIL__') \}\}" $buf]
        if {$e >= 0} {
            set nl [string first "\n" $buf $e]
            if {$nl >= 0} { set buf [string range $buf [expr {$nl + 1}] end] }
        }
        # Drop the result marker and carriage returns.
        regsub -all {__CCDC_(OK|FAIL)__} $buf {} buf
        set buf [string map [list "\r" ""] $buf]
        puts -nonewline [string trimright $buf]
        puts ""
    }
    expect {
        -re $prompt { send -- "exit\r" }
        timeout { puts stderr "Timed out returning to WinRM prompt"; exit 1 }
        eof { exit $result }
    }
    set timeout 15
    expect eof
    exit $result
} else {
    send -- "Invoke-CCDC\r"
    interact
}
EXPECT
        ;;
    *) echo "Unknown OS '$os'" >&2; exit 1 ;;
esac
