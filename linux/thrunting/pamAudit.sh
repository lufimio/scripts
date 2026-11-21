#!/bin/bash
# Audits PAM configuration for suspicious entries:
# pam_exec with scripts, unexpected pam_python/pam_perl modules,
# unknown .so files in PAM module dirs, and world-writable PAM configs.
# Audit-only — reports findings, does not modify PAM config.
# Run at hardening time and periodically via cfk.sh cron.
set -uo pipefail

QUIET=false
ISSUES_FOUND=0

CCDC_LOG=/var/log/ccdc/changes.log

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
    printf '{"ts":"%s","host":"%s","script":"pamAudit","action":"%s","path":"%s","detail":"%s"}\n' \
        "$ts" "$host" "$action" "$path" "$detail" >> "$CCDC_LOG" 2>/dev/null
    logger -t ccdc-pamAudit "action=$action path=$path $detail" 2>/dev/null || true
}

log_info()     { [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1" || true; }
log_warn()     { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_critical() { echo -e "${RED}[CRIT]${NC} $1"; }

check_root() {
    [[ $EUID -eq 0 ]] || { echo -e "${RED}[ERROR]${NC} Must be run as root"; exit 3; }
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -q|--quiet) QUIET=true; shift ;;
        -h|--help)
            echo "Usage: $0 [-q|--quiet]"
            echo "Audits PAM configuration for suspicious entries. Audit-only, no changes made."
            exit 0 ;;
        *) shift ;;
    esac
done

check_root

PAM_DIRS=(/etc/pam.d /etc/pam.conf)
PAM_MODULE_DIRS=(/lib/security /lib64/security /usr/lib/security /usr/lib64/security
                 /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security
                 /lib/aarch64-linux-gnu/security /usr/lib/aarch64-linux-gnu/security)

# --- CHECK 1: pam_exec entries pointing to scripts ---
check_pam_exec() {
    log_info "Checking for pam_exec entries in PAM config..."
    local found=0
    for target in "${PAM_DIRS[@]}"; do
        local files=()
        if [[ -d "$target" ]]; then
            while IFS= read -r f; do files+=("$f"); done < <(find "$target" -type f 2>/dev/null)
        elif [[ -f "$target" ]]; then
            files=("$target")
        else
            continue
        fi
        for file in "${files[@]}"; do
            local matches
            matches=$(grep -nE '^\s*\S+\s+\S+\s+pam_exec\.so' "$file" 2>/dev/null) || continue
            [[ -z "$matches" ]] && continue
            ((ISSUES_FOUND++)) || true; ((found++)) || true
            log_critical "pam_exec found in: $file"
            echo "$matches"
            # Extract the script path if present
            while IFS= read -r line; do
                local script
                script=$(echo "$line" | grep -oE 'pam_exec\.so\s+\S+' | awk '{print $2}' 2>/dev/null) || true
                [[ -n "$script" ]] && ccdc_log "pam_exec_found" "$file" "script:$script,line:$(echo "$line" | sed 's/"/\\"/g')"
            done <<< "$matches"
        done
    done
    [[ $found -eq 0 ]] && log_info "No pam_exec entries found"
}

# --- CHECK 2: Scripting language PAM modules (pam_python, pam_perl, pam_lua) ---
check_script_modules() {
    log_info "Checking for scripting language PAM modules..."
    local found=0
    for target in "${PAM_DIRS[@]}"; do
        local files=()
        if [[ -d "$target" ]]; then
            while IFS= read -r f; do files+=("$f"); done < <(find "$target" -type f 2>/dev/null)
        elif [[ -f "$target" ]]; then
            files=("$target")
        else
            continue
        fi
        for file in "${files[@]}"; do
            local matches
            matches=$(grep -nE '^\s*\S+\s+\S+\s+pam_(python|perl|lua|ruby|tcl)\.' "$file" 2>/dev/null) || continue
            [[ -z "$matches" ]] && continue
            ((ISSUES_FOUND++)) || true; ((found++)) || true
            log_critical "Scripting language PAM module in: $file"
            echo "$matches"
            ccdc_log "pam_script_module_found" "$file" "matches:$(echo "$matches" | head -1 | sed 's/"/\\"/g')"
        done
    done
    [[ $found -eq 0 ]] && log_info "No scripting language PAM modules found"
}

# --- CHECK 3: Unknown .so files in PAM module directories ---
check_unknown_modules() {
    log_info "Checking for unknown .so files in PAM module directories..."
    local found=0

    # Build list of all .so modules referenced in PAM config
    local referenced_modules=()
    for target in "${PAM_DIRS[@]}"; do
        local files=()
        if [[ -d "$target" ]]; then
            while IFS= read -r f; do files+=("$f"); done < <(find "$target" -type f 2>/dev/null)
        elif [[ -f "$target" ]]; then
            files=("$target")
        else
            continue
        fi
        for file in "${files[@]}"; do
            while IFS= read -r mod; do
                referenced_modules+=("$mod")
            done < <(grep -hoE 'pam_[a-zA-Z0-9_]+\.so' "$file" 2>/dev/null | sort -u)
        done
    done

    for mod_dir in "${PAM_MODULE_DIRS[@]}"; do
        [[ -d "$mod_dir" ]] || continue
        while IFS= read -r so_file; do
            [[ -z "$so_file" ]] && continue
            local mod_name; mod_name=$(basename "$so_file")
            # Warn about any .so that isn't a standard pam_ prefixed module
            if ! [[ "$mod_name" == pam_*.so* ]]; then
                ((ISSUES_FOUND++)) || true; ((found++)) || true
                log_critical "Non-standard module in PAM dir: $so_file"
                ccdc_log "non_standard_pam_module" "$so_file" "reason:no_pam_prefix"
            fi
            # Warn about recently modified modules (within last 24h)
            if find "$so_file" -mtime -1 -type f 2>/dev/null | grep -q .; then
                ((ISSUES_FOUND++)) || true; ((found++)) || true
                log_critical "Recently modified PAM module: $so_file"
                local mtime; mtime=$(stat -c '%y' "$so_file" 2>/dev/null)
                ccdc_log "recently_modified_pam_module" "$so_file" "mtime:$mtime"
            fi
        done < <(find "$mod_dir" -maxdepth 1 -name "*.so*" -type f 2>/dev/null)
    done
    [[ $found -eq 0 ]] && log_info "No unknown PAM modules found"
}

# --- CHECK 4: World-writable or suspicious permissions on PAM config files ---
check_pam_permissions() {
    log_info "Checking PAM config file permissions..."
    local found=0
    for target in "${PAM_DIRS[@]}"; do
        local files=()
        if [[ -d "$target" ]]; then
            while IFS= read -r f; do files+=("$f"); done < <(find "$target" -type f 2>/dev/null)
        elif [[ -f "$target" ]]; then
            files=("$target")
        else
            continue
        fi
        for file in "${files[@]}"; do
            # World-writable
            if [[ -w "$file" ]] && stat -c '%a' "$file" 2>/dev/null | grep -qE '^..[2367]'; then
                ((ISSUES_FOUND++)) || true; ((found++)) || true
                local mode; mode=$(stat -c '%04a' "$file")
                log_critical "World-writable PAM config: $file (mode $mode)"
                ccdc_log "world_writable_pam_config" "$file" "mode:$mode"
            fi
            # Not owned by root
            local owner; owner=$(stat -c '%U' "$file" 2>/dev/null)
            if [[ "$owner" != "root" ]]; then
                ((ISSUES_FOUND++)) || true; ((found++)) || true
                log_critical "PAM config not owned by root: $file (owner: $owner)"
                ccdc_log "pam_config_bad_owner" "$file" "owner:$owner"
            fi
        done
    done
    [[ $found -eq 0 ]] && log_info "PAM config permissions look clean"
}

# --- CHECK 5: Dump full PAM config for manual review ---
dump_pam_summary() {
    log_info "PAM config summary (non-comment, non-blank lines):"
    for target in "${PAM_DIRS[@]}"; do
        [[ -d "$target" || -f "$target" ]] || continue
        local files=()
        if [[ -d "$target" ]]; then
            while IFS= read -r f; do files+=("$f"); done < <(find "$target" -type f 2>/dev/null | sort)
        else
            files=("$target")
        fi
        for file in "${files[@]}"; do
            local content
            content=$(grep -vE '^\s*(#|$)' "$file" 2>/dev/null) || continue
            [[ -z "$content" ]] && continue
            echo "--- $file ---"
            echo "$content"
            echo ""
        done
    done
}

echo "========================================"
echo "CCDC PAM AUDIT — $(date)"
echo "(audit-only, no changes made)"
echo "========================================"
echo ""

check_pam_exec
check_script_modules
check_unknown_modules
check_pam_permissions

echo ""
echo "========================================"
if [[ $ISSUES_FOUND -eq 0 ]]; then
    log_info "Clean — no suspicious PAM configuration found"
    ccdc_log "pam_audit_complete" "" "issues:0"
else
    log_warn "Suspicious PAM entries found: $ISSUES_FOUND — review manually"
    ccdc_log "pam_audit_complete" "" "issues:$ISSUES_FOUND"
    echo ""
    dump_pam_summary
fi
echo "========================================"
