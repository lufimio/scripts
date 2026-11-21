#!/bin/bash
# Detects and neutralizes common persistence mechanisms:
# LD_PRELOAD injections, /etc/ld.so.preload, rc.local backdoors,
# Apache mod_rootme, and suspicious .so files in temp dirs.
# Run once or via cron from the Kali controller via cfk.sh.
set -uo pipefail

DRY_RUN=false
QUIET=false
ISSUES_FOUND=0
ISSUES_FIXED=0

CCDC_LOG=/var/log/ccdc/changes.log
CCDC_BACKUP=/var/backups/ccdc/sweep

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
    printf '{"ts":"%s","host":"%s","script":"securitySweep","action":"%s","path":"%s","detail":"%s"}\n' \
        "$ts" "$host" "$action" "$path" "$detail" >> "$CCDC_LOG" 2>/dev/null
    logger -t ccdc-securitySweep "action=$action path=$path $detail" 2>/dev/null || true
}

backup_file() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    local ts dest
    ts=$(date +%s)
    dest="$CCDC_BACKUP/$(basename "$src").bak.$ts"
    mkdir -p "$CCDC_BACKUP" 2>/dev/null
    cp -a "$src" "$dest" 2>/dev/null && echo "$dest" || echo ""
}

log_info()     { [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1" || true; }
log_warn()     { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_critical() { echo -e "${RED}[CRIT]${NC} $1"; }
log_fixed()    { echo -e "${GREEN}[FIXED]${NC} $1"; }

check_root() {
    [[ $EUID -eq 0 ]] || { echo -e "${RED}[ERROR]${NC} Must be run as root"; exit 3; }
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--dry-run) DRY_RUN=true; shift ;;
        -q|--quiet)   QUIET=true; shift ;;
        -h|--help)
            echo "Usage: $0 [-n|--dry-run] [-q|--quiet]"
            echo "Detects and removes LD_PRELOAD hooks, rc.local backdoors, mod_rootme, suspicious libs."
            exit 0 ;;
        *) shift ;;
    esac
done

check_root

# --- CHECK 1: LD_PRELOAD in profile/environment scripts ---
check_ld_preload() {
    log_info "Checking for LD_PRELOAD persistence in profile scripts..."
    local search_targets=(/etc/profile.d /etc/profile /etc/environment /etc/bash.bashrc /etc/bashrc)
    for home in /home/* /root; do
        [[ -d "$home" ]] || continue
        for f in .bashrc .bash_profile .profile .zshrc; do
            [[ -f "$home/$f" ]] && search_targets+=("$home/$f")
        done
    done

    for target in "${search_targets[@]}"; do
        local files=()
        if [[ -d "$target" ]]; then
            while IFS= read -r f; do files+=("$f"); done < <(find "$target" -type f 2>/dev/null)
        elif [[ -f "$target" ]]; then
            files=("$target")
        fi
        for file in "${files[@]}"; do
            grep -qE '^\s*(export\s+)?LD_(PRELOAD|LIBRARY_PATH|AUDIT)\s*=' "$file" 2>/dev/null || continue
            ((ISSUES_FOUND++)) || true
            log_critical "LD_ export found in: $file"
            grep -nE '^\s*(export\s+)?LD_(PRELOAD|LIBRARY_PATH|AUDIT)\s*=' "$file" 2>/dev/null
            if [[ "$DRY_RUN" == "false" ]]; then
                local bak; bak=$(backup_file "$file")
                sed -i 's/^\(\s*\(export\s\+\)\?LD_\(PRELOAD\|LIBRARY_PATH\|AUDIT\)\s*=\)/# DISABLED BY CCDC SWEEP: \1/' "$file"
                log_fixed "Commented out LD_ exports in $file"
                ccdc_log "comment_ld_export" "$file" "backup:$bak"
                ((ISSUES_FIXED++)) || true
            else
                ccdc_log "dryrun_ld_export" "$file" ""
            fi
        done
    done
}

# --- CHECK 2: /etc/ld.so.preload ---
check_ld_so_preload() {
    log_info "Checking /etc/ld.so.preload..."
    [[ -f /etc/ld.so.preload ]] || { log_info "/etc/ld.so.preload not present"; return; }
    grep -qE '^\s*/' /etc/ld.so.preload 2>/dev/null || { log_info "/etc/ld.so.preload is empty/clean"; return; }

    ((ISSUES_FOUND++)) || true
    log_critical "/etc/ld.so.preload contains injections:"
    grep -E '^\s*/' /etc/ld.so.preload
    if [[ "$DRY_RUN" == "false" ]]; then
        local bak; bak=$(backup_file /etc/ld.so.preload)
        : > /etc/ld.so.preload
        log_fixed "Emptied /etc/ld.so.preload"
        ccdc_log "clear_ld_so_preload" "/etc/ld.so.preload" "backup:$bak"
        ((ISSUES_FIXED++)) || true
    else
        ccdc_log "dryrun_ld_so_preload" "/etc/ld.so.preload" ""
    fi
}

# --- CHECK 3: rc.local backdoors ---
check_rc_local() {
    log_info "Checking /etc/rc.local..."
    [[ -f /etc/rc.local ]] || return
    local suspicious
    suspicious=$(grep -cvE '^\s*(#|exit\s+0\s*$|$)' /etc/rc.local 2>/dev/null || echo 0)
    suspicious=$(echo "$suspicious" | tail -1)
    [[ "$suspicious" -gt 0 ]] || { log_info "/etc/rc.local is clean"; return; }

    ((ISSUES_FOUND++)) || true
    log_critical "/etc/rc.local has $suspicious suspicious line(s):"
    grep -vE '^\s*(#|exit\s+0\s*$|$)' /etc/rc.local 2>/dev/null | head -20
    if [[ "$DRY_RUN" == "false" ]]; then
        local bak; bak=$(backup_file /etc/rc.local)
        printf '#!/bin/bash\n# rc.local cleaned by CCDC security sweep\nexit 0\n' > /etc/rc.local
        chmod 644 /etc/rc.local
        log_fixed "Neutralized /etc/rc.local"
        ccdc_log "neutralize_rc_local" "/etc/rc.local" "suspicious_lines:$suspicious,backup:$bak"
        ((ISSUES_FIXED++)) || true
    else
        ccdc_log "dryrun_rc_local" "/etc/rc.local" "suspicious_lines:$suspicious"
    fi
}

# --- CHECK 4: Apache mod_rootme ---
check_mod_rootme() {
    log_info "Checking for Apache mod_rootme..."
    for conf in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf \
                /etc/httpd/conf.d/*.conf /etc/apache2/mods-enabled/*.load \
                /etc/apache2/mods-enabled/*.conf; do
        [[ -f "$conf" ]] || continue
        grep -qiE '^\s*(LoadModule|Include).*rootme' "$conf" 2>/dev/null || continue
        ((ISSUES_FOUND++)) || true
        log_critical "mod_rootme found in $conf"
        if [[ "$DRY_RUN" == "false" ]]; then
            local bak; bak=$(backup_file "$conf")
            sed -i 's/^\(\s*\(LoadModule\|Include\).*rootme\)/# DISABLED BY CCDC SWEEP: \1/' "$conf"
            log_fixed "Disabled mod_rootme in $conf"
            ccdc_log "disable_mod_rootme" "$conf" "backup:$bak"
            ((ISSUES_FIXED++)) || true
        else
            ccdc_log "dryrun_mod_rootme" "$conf" ""
        fi
    done

    local rootme_so
    rootme_so=$(find /usr/lib /usr/lib64 /usr/local/lib -name "*rootme*" -type f 2>/dev/null || true)
    if [[ -n "$rootme_so" ]]; then
        while IFS= read -r rf; do
            ((ISSUES_FOUND++)) || true
            log_critical "mod_rootme .so found: $rf"
            if [[ "$DRY_RUN" == "false" ]]; then
                local bak; bak=$(backup_file "$rf")
                mv "$rf" "${rf}.DISABLED" 2>/dev/null
                log_fixed "Renamed $rf → ${rf}.DISABLED"
                ccdc_log "disable_rootme_so" "$rf" "renamed_to:${rf}.DISABLED,backup:$bak"
                ((ISSUES_FIXED++)) || true
            else
                ccdc_log "dryrun_rootme_so" "$rf" ""
            fi
        done <<< "$rootme_so"
    fi

    [[ $ISSUES_FOUND -eq 0 ]] && log_info "No mod_rootme found"
}

# --- CHECK 5: Suspicious .so files in temp dirs ---
check_suspicious_libs() {
    log_info "Checking for suspicious shared libraries in temp directories..."
    local found=0
    for dir in /tmp /dev/shm /var/tmp /run/shm; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r so_file; do
            [[ -z "$so_file" ]] && continue
            ((ISSUES_FOUND++)) || true; ((found++)) || true
            log_critical "Suspicious lib in temp dir: $so_file"
            if [[ "$DRY_RUN" == "false" ]]; then
                local bak; bak="$CCDC_BACKUP/$(basename "$so_file").bak.$(date +%s)"
                mkdir -p "$CCDC_BACKUP" 2>/dev/null
                mv "$so_file" "$bak" 2>/dev/null
                log_fixed "Quarantined $so_file → $bak"
                ccdc_log "quarantine_lib" "$so_file" "quarantined_to:$bak"
                ((ISSUES_FIXED++)) || true
            else
                ccdc_log "dryrun_suspicious_lib" "$so_file" ""
            fi
        done < <(find "$dir" -maxdepth 2 \( -name "*.so" -o -name "*.so.*" \) -type f 2>/dev/null)
    done
    [[ $found -eq 0 ]] && log_info "No suspicious libs found in temp dirs"
}

# --- Main ---
echo "========================================"
echo "CCDC SECURITY SWEEP — $(date)"
[[ "$DRY_RUN" == "true" ]] && echo -e "${YELLOW}DRY RUN — no changes will be made${NC}"
echo "========================================"
echo ""

check_ld_preload
check_ld_so_preload
check_rc_local
check_mod_rootme
check_suspicious_libs

echo ""
echo "========================================"
if [[ $ISSUES_FOUND -eq 0 ]]; then
    log_info "Clean — no persistence mechanisms found"
    ccdc_log "sweep_complete" "" "issues:0"
elif [[ "$DRY_RUN" == "true" ]]; then
    log_warn "Issues found: $ISSUES_FOUND (dry-run, nothing changed)"
    ccdc_log "sweep_complete" "" "issues:$ISSUES_FOUND,fixed:0,dry_run:true"
else
    log_warn "Issues found: $ISSUES_FOUND | Fixed: $ISSUES_FIXED"
    ccdc_log "sweep_complete" "" "issues:$ISSUES_FOUND,fixed:$ISSUES_FIXED"
fi
echo "========================================"
