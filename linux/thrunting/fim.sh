#!/bin/bash
# File Integrity Monitor — single-pass, not a daemon.
# Subcommands:
#   init   Build a SHA-256 baseline of critical files
#   check  Compare current state against the baseline
#
# Baseline stored at: /var/lib/ccdc/fim-baseline.sha256
# Changed files backed up to: /var/backups/ccdc/fim/
# Findings logged to: /var/log/ccdc/changes.log (JSON lines)
#
# Web server dirs auto-detected from running processes.
# Run `init` once at hardening time, `check` via cfk.sh cron.
set -uo pipefail

QUIET=false
ISSUES_FOUND=0

CCDC_LOG=/var/log/ccdc/changes.log
CCDC_BACKUP=/var/backups/ccdc/fim
BASELINE=/var/lib/ccdc/fim-baseline.sha256

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ccdc_log() {
    local action="$1" path="${2:-}" detail="${3:-}"
    local ts host
    ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')
    host=$(hostname -s 2>/dev/null || echo unknown)
    path="${path//\"/\\\"}"; detail="${detail//\"/\\\"}"
    mkdir -p "$(dirname "$CCDC_LOG")" 2>/dev/null
    printf '{"ts":"%s","host":"%s","script":"fim","action":"%s","path":"%s","detail":"%s"}\n' \
        "$ts" "$host" "$action" "$path" "$detail" >> "$CCDC_LOG" 2>/dev/null
    logger -t ccdc-fim "action=$action path=$path $detail" 2>/dev/null || true
}

backup_changed_file() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    local ts dest_dir dest
    ts=$(date +%s)
    # Mirror the directory structure under the backup dir
    dest_dir="$CCDC_BACKUP/$(dirname "$src")"
    dest="$dest_dir/$(basename "$src").changed.$ts"
    mkdir -p "$dest_dir" 2>/dev/null
    cp -a "$src" "$dest" 2>/dev/null && echo "$dest" || echo ""
}

log_info()     { [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1" || true; }
log_warn()     { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_critical() { echo -e "${RED}[CRIT]${NC} $1"; }

check_root() {
    [[ $EUID -eq 0 ]] || { echo -e "${RED}[ERROR]${NC} Must be run as root"; exit 3; }
}

usage() {
    echo "Usage: $0 <init|check> [-q|--quiet]"
    echo "  init   Build SHA-256 baseline of critical files"
    echo "  check  Compare current state against baseline"
    echo "  -q     Suppress informational output"
    exit 0
}

SUBCOMMAND=""
while [[ $# -gt 0 ]]; do
    case $1 in
        init|check) SUBCOMMAND="$1"; shift ;;
        -q|--quiet) QUIET=true; shift ;;
        -h|--help)  usage ;;
        *) shift ;;
    esac
done

[[ -n "$SUBCOMMAND" ]] || usage
check_root

# --- Build the list of directories/files to monitor ---
get_scan_targets() {
    local targets=(
        # Auth and account management
        /etc/passwd
        /etc/shadow
        /etc/group
        /etc/gshadow
        /etc/sudoers
        /etc/sudoers.d
        # PAM
        /etc/pam.d
        /etc/pam.conf
        # SSH
        /etc/ssh/sshd_config
        /etc/ssh/sshd_config.d
        /root/.ssh
        # Cron
        /etc/crontab
        /etc/cron.d
        /etc/cron.daily
        /etc/cron.hourly
        /etc/cron.weekly
        /etc/cron.monthly
        /var/spool/cron
        /var/spool/cron/crontabs
        # Init / boot
        /etc/rc.local
        /etc/init.d
        /etc/systemd/system
        /lib/systemd/system
        # Dynamic linker
        /etc/ld.so.preload
        /etc/ld.so.conf
        /etc/ld.so.conf.d
        # Shell profiles
        /etc/profile
        /etc/profile.d
        /etc/bash.bashrc
        /etc/bashrc
        /etc/environment
        # Binaries and libraries
        /bin
        /sbin
        /usr/bin
        /usr/sbin
        /usr/local/bin
        /usr/local/sbin
        # Hosts / resolv
        /etc/hosts
        /etc/resolv.conf
        /etc/nsswitch.conf
    )

    # Auto-detect web server document roots and config dirs
    local webserver_procs
    webserver_procs=$(ps -eo comm 2>/dev/null | grep -E '^(nginx|apache2|httpd)$' | sort -u) || true

    if echo "$webserver_procs" | grep -q nginx; then
        log_info "nginx detected — adding web dirs to FIM scope"
        targets+=(
            /etc/nginx
            /var/www
            /usr/share/nginx
        )
        # Try to extract configured document roots from nginx
        while IFS= read -r root_dir; do
            [[ -d "$root_dir" ]] && targets+=("$root_dir")
        done < <(grep -hroE 'root\s+[^;]+' /etc/nginx 2>/dev/null | awk '{print $2}' | sort -u)
    fi

    if echo "$webserver_procs" | grep -qE 'apache2|httpd'; then
        log_info "Apache detected — adding web dirs to FIM scope"
        targets+=(
            /etc/apache2
            /etc/httpd
            /var/www
            /usr/share/apache2
        )
        # Try to extract configured document roots from apache
        for conf in /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*; do
            [[ -f "$conf" ]] || continue
            while IFS= read -r root_dir; do
                [[ -d "$root_dir" ]] && targets+=("$root_dir")
            done < <(grep -iE '^\s*DocumentRoot' "$conf" 2>/dev/null | awk '{print $2}' | tr -d '"')
        done
    fi

    # Also monitor home dirs for .ssh and shell profiles
    for home in /home/* /root; do
        [[ -d "$home" ]] || continue
        for f in .ssh .bashrc .bash_profile .profile .zshrc; do
            [[ -e "$home/$f" ]] && targets+=("$home/$f")
        done
    done

    printf '%s\n' "${targets[@]}"
}

# --- INIT: Build baseline ---
cmd_init() {
    echo "========================================"
    echo "CCDC FIM INIT — $(date)"
    echo "========================================"
    echo ""

    if [[ -f "$BASELINE" ]]; then
        local existing_count
        existing_count=$(wc -l < "$BASELINE" 2>/dev/null || echo 0)
        log_warn "Baseline already exists at $BASELINE ($existing_count entries)"
        log_warn "Overwriting with fresh baseline..."
        local ts_bak
        ts_bak=$(date +%s)
        cp -a "$BASELINE" "${BASELINE}.bak.$ts_bak" 2>/dev/null
        ccdc_log "fim_init_overwrite" "$BASELINE" "backup:${BASELINE}.bak.$ts_bak,previous_entries:$existing_count"
    fi

    mkdir -p "$(dirname "$BASELINE")" 2>/dev/null
    : > "$BASELINE"
    chmod 600 "$BASELINE"

    local file_count=0
    local err_count=0
    local targets
    mapfile -t targets < <(get_scan_targets)

    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        local hash
        hash=$(sha256sum "$f" 2>/dev/null) || { ((err_count++)) || true; continue; }
        echo "$hash" >> "$BASELINE"
        ((file_count++)) || true
    done < <(
        for t in "${targets[@]}"; do
            if [[ -d "$t" ]]; then
                find "$t" -type f 2>/dev/null
            elif [[ -f "$t" ]]; then
                echo "$t"
            fi
        done | sort -u
    )

    echo ""
    echo "========================================"
    log_info "Baseline complete: $file_count files hashed, $err_count errors"
    log_info "Baseline stored at: $BASELINE"
    ccdc_log "fim_init_complete" "$BASELINE" "files:$file_count,errors:$err_count"
    echo "========================================"
}

# --- CHECK: Compare against baseline ---
cmd_check() {
    echo "========================================"
    echo "CCDC FIM CHECK — $(date)"
    echo "========================================"
    echo ""

    if [[ ! -f "$BASELINE" ]]; then
        echo -e "${RED}[ERROR]${NC} No baseline found at $BASELINE — run 'fim.sh init' first"
        ccdc_log "fim_check_no_baseline" "$BASELINE" ""
        exit 2
    fi

    local baseline_count
    baseline_count=$(wc -l < "$BASELINE" 2>/dev/null || echo 0)
    log_info "Baseline has $baseline_count entries"

    # Build a temp file with current hashes for all baselined paths
    local tmp_current
    tmp_current=$(mktemp /tmp/ccdc-fim-current.XXXXXX)
    trap 'rm -f "$tmp_current"' EXIT

    local recalc_errors=0
    while IFS=  read -r line; do
        # sha256sum format: "<hash>  <path>"
        local path
        path=$(echo "$line" | awk '{print $2}')
        [[ -z "$path" ]] && continue

        if [[ ! -f "$path" ]]; then
            ((ISSUES_FOUND++)) || true
            log_critical "FILE DELETED: $path"
            ccdc_log "fim_deleted" "$path" ""
            continue
        fi

        local current_hash
        current_hash=$(sha256sum "$path" 2>/dev/null) || { ((recalc_errors++)) || true; continue; }
        echo "$current_hash" >> "$tmp_current"

        local baseline_hash; baseline_hash=$(echo "$line" | awk '{print $1}')
        local current_hash_only; current_hash_only=$(echo "$current_hash" | awk '{print $1}')

        if [[ "$baseline_hash" != "$current_hash_only" ]]; then
            ((ISSUES_FOUND++)) || true
            log_critical "FILE MODIFIED: $path"
            local bak; bak=$(backup_changed_file "$path")
            ccdc_log "fim_modified" "$path" "baseline_hash:$baseline_hash,current_hash:$current_hash_only,backup:$bak"
        fi
    done < "$BASELINE"

    # Check for new files in monitored directories
    local new_files=0
    local targets
    mapfile -t targets < <(get_scan_targets)
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        if ! grep -qF "  $f" "$BASELINE" 2>/dev/null; then
            ((ISSUES_FOUND++)) || true; ((new_files++)) || true
            log_critical "NEW FILE: $f"
            local bak; bak=$(backup_changed_file "$f")
            local hash; hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
            ccdc_log "fim_new_file" "$f" "hash:$hash,backup:$bak"
        fi
    done < <(
        for t in "${targets[@]}"; do
            if [[ -d "$t" ]]; then
                find "$t" -type f 2>/dev/null
            elif [[ -f "$t" ]]; then
                echo "$t"
            fi
        done | sort -u
    )

    echo ""
    echo "========================================"
    if [[ $ISSUES_FOUND -eq 0 ]]; then
        log_info "Clean — no integrity violations found"
        ccdc_log "fim_check_complete" "" "issues:0,recalc_errors:$recalc_errors"
    else
        log_warn "Integrity violations: $ISSUES_FOUND (modified/deleted/new files)"
        log_warn "Changed files backed up to: $CCDC_BACKUP"
        ccdc_log "fim_check_complete" "" "issues:$ISSUES_FOUND,new_files:$new_files,recalc_errors:$recalc_errors"
    fi
    echo "========================================"
}

case "$SUBCOMMAND" in
    init)  cmd_init ;;
    check) cmd_check ;;
esac
