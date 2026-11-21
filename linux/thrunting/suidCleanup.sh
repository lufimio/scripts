#!/bin/bash
# Strips SUID/SGID bits from GTFOBins-listed binaries.
# Skips sudo, passwd, su, and newgrp (legitimately need SUID).
# Logs each strip with original mode so it's reversible.
# Run at hardening time and periodically via cfk.sh cron.
set -uo pipefail

DRY_RUN=false
QUIET=false
SCAN_ALL=false
ISSUES_FOUND=0
ISSUES_FIXED=0

CCDC_LOG=/var/log/ccdc/changes.log
CCDC_BACKUP=/var/backups/ccdc/suid

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
    printf '{"ts":"%s","host":"%s","script":"suidCleanup","action":"%s","path":"%s","detail":"%s"}\n' \
        "$ts" "$host" "$action" "$path" "$detail" >> "$CCDC_LOG" 2>/dev/null
    logger -t ccdc-suidCleanup "action=$action path=$path $detail" 2>/dev/null || true
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
        -a|--all)     SCAN_ALL=true; shift ;;
        -h|--help)
            echo "Usage: $0 [-n|--dry-run] [-q|--quiet] [-a|--all]"
            echo "Strips SUID/SGID from GTFOBins-listed binaries."
            echo "  -a  Scan all SUID/SGID binaries (not just known GTFOBins list)"
            exit 0 ;;
        *) shift ;;
    esac
done

check_root

# Binaries that MUST keep SUID/SGID — never touch these
WHITELIST=(
    sudo
    passwd
    su
    newgrp
    pkexec
    # ping and mount may be needed depending on distro
)

is_whitelisted() {
    local name; name=$(basename "$1")
    for w in "${WHITELIST[@]}"; do
        [[ "$name" == "$w" ]] && return 0
    done
    return 1
}

# GTFOBins SUID list — commonly exploitable binaries
GTFOBINS_SUID=(
    apt apt-get
    ar
    aria2c
    ash
    at
    awk
    base32 base64
    basenc
    bash
    bpftrace
    busybox
    bzip2
    c89 c99
    cancel
    cat
    chmod chown chroot
    cmp
    cobc
    cp
    csh
    csplit
    curl
    cut
    dash
    date
    dd
    dialog
    diff
    dig
    docker
    doas
    ed
    emacs
    env
    eqn
    expand
    expect
    file
    find
    finger
    flock
    fmt
    fold
    gawk
    gdb
    gem
    genisoimage
    git
    grep
    gtester
    gzip
    hd
    head
    hexdump
    id
    ifconfig
    install
    ionice
    ip
    jq
    ksh
    ld.so
    less
    logsave
    look
    lua
    make
    man
    mawk
    more
    mount
    mv
    mysql
    nano
    nawk
    nc netcat ncat
    nice
    nl
    nmap
    node nodejs
    nohup
    od
    openssl
    perl
    php
    pic
    pico
    pip pip3
    pr
    python python2 python3
    readelf
    restic
    rev
    rlwrap
    rpm
    rsync
    ruby
    run-mailcap
    run-parts
    rview rvim
    scp
    sed
    setarch
    sftp
    shuf
    socat
    sort
    split
    sqlite3
    ssh
    start-stop-daemon
    stdbuf
    strace
    strings
    tac
    tail
    tar
    taskset
    tclsh
    tee
    telnet
    tftp
    timeout
    tshark
    ul
    unexpand
    uniq
    unshare
    unzip
    update-alternatives
    uudecode uuencode
    valgrind
    view
    vim vi
    watch
    wget
    whiptail
    xargs
    xdotool
    xxd
    xz
    yash
    zip
    zsh
    zsoelim
)

in_gtfobins() {
    local name; name=$(basename "$1")
    for g in "${GTFOBINS_SUID[@]}"; do
        [[ "$name" == "$g" ]] && return 0
    done
    return 1
}

strip_suid() {
    local binary="$1"
    local orig_mode
    orig_mode=$(stat -c '%04a' "$binary" 2>/dev/null) || return

    ((ISSUES_FOUND++)) || true
    log_critical "SUID/SGID on: $binary (mode $orig_mode)"

    if [[ "$DRY_RUN" == "false" ]]; then
        # Strip both SUID (4000) and SGID (2000)
        chmod u-s,g-s "$binary" 2>/dev/null
        local new_mode
        new_mode=$(stat -c '%04a' "$binary" 2>/dev/null)
        log_fixed "Stripped SUID/SGID: $binary ($orig_mode → $new_mode)"
        ccdc_log "strip_suid" "$binary" "original_mode:$orig_mode,new_mode:$new_mode,restore:chmod $orig_mode $binary"
        ((ISSUES_FIXED++)) || true
    else
        ccdc_log "dryrun_strip_suid" "$binary" "original_mode:$orig_mode"
    fi
}

scan_suid_binaries() {
    log_info "Scanning for SUID/SGID binaries..."
    local checked=0 skipped=0

    while IFS= read -r binary; do
        [[ -z "$binary" ]] && continue
        ((checked++)) || true

        if is_whitelisted "$binary"; then
            log_info "Whitelisted (skipping): $binary"
            ((skipped++)) || true
            continue
        fi

        if [[ "$SCAN_ALL" == "true" ]]; then
            strip_suid "$binary"
        elif in_gtfobins "$binary"; then
            strip_suid "$binary"
        else
            log_info "Not in GTFOBins list (skipping): $binary"
            ((skipped++)) || true
        fi
    done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort)

    log_info "Scanned $checked SUID/SGID binaries, skipped $skipped"
}

echo "========================================"
echo "CCDC SUID CLEANUP — $(date)"
[[ "$DRY_RUN" == "true" ]] && echo -e "${YELLOW}DRY RUN — no changes will be made${NC}"
[[ "$SCAN_ALL" == "true" ]] && echo -e "${YELLOW}ALL MODE — stripping all non-whitelisted SUID/SGID${NC}"
echo "========================================"
echo ""

scan_suid_binaries

echo ""
echo "========================================"
if [[ $ISSUES_FOUND -eq 0 ]]; then
    log_info "Clean — no problematic SUID/SGID binaries found"
    ccdc_log "suid_cleanup_complete" "" "issues:0"
elif [[ "$DRY_RUN" == "true" ]]; then
    log_warn "Issues found: $ISSUES_FOUND (dry-run, nothing changed)"
    ccdc_log "suid_cleanup_complete" "" "issues:$ISSUES_FOUND,fixed:0,dry_run:true"
else
    log_warn "Issues found: $ISSUES_FOUND | Fixed: $ISSUES_FIXED"
    ccdc_log "suid_cleanup_complete" "" "issues:$ISSUES_FOUND,fixed:$ISSUES_FIXED"
fi
echo "========================================"
