#!/bin/sh
# status:  draft
# risk:    lockout
# tested:  never (container runs only, see testing/README.md)
#
# Rewrites sshd_config from a known-good block (no Include, no Match), validates
# it, reloads sshd (SIGHUP) and checks the effective values with sshd -T.
# That is all it does: ssh-audit looks first, ssh-keys moves the
# authorized_keys files afterwards.
#
# WHAT STOPS WORKING: public key logins (PubkeyAuthentication no), root login
# (PermitRootLogin no), all forwarding. Password logins stay on.
# AUTO-REVERT: 180 seconds after the reload the old configuration is put back
# and sshd is reloaded again, unless /var/run/ccdc-ssh-ok exists by then.
# To keep the change, log in from a NEW terminal and create that file as
# root. The harden-ssh service does this for you.
# Everything replaced is copied first to /root/ccdc-ssh-backup.<time>/.
# Not root: audit only, nothing is changed.
#
# Tiny Core runs from RAM: the change is lost on reboot unless
# /usr/local/etc/ssh is in /opt/.filetool.lst and you run filetool.sh -b.

PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin"
export PATH
LC_ALL=C
export LC_ALL

# ---- helpers ----------------------------------------------------------------
WARNS=0
LOGF=""
if mkdir -p /var/log/ccdc 2>/dev/null && [ -w /var/log/ccdc ]; then
  LOGF="/var/log/ccdc/$(date '+%Y-%m')-main.log"
fi

log() {
  [ -n "$LOGF" ] && printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LOGF"
  return 0
}
header() { printf '\n== %s ==\n' "$*"; log "== $*"; }
info() { printf '[ ] %s\n' "$*"; log "INFO: $*"; }
ok() { printf '[+] %s\n' "$*"; log "OK: $*"; }
warn() { printf '[!] %s\n' "$*"; log "WARN: $*"; WARNS=$((WARNS + 1)); }

have() { command -v "$1" >/dev/null 2>&1; }

# Warn and carry on; never require root.
check_root() {
  if [ "$(id -u 2>/dev/null)" != 0 ]; then
    warn "Not running as root; results may be incomplete"
  fi
}
# ---------------------------------------------------------------------------

CONFIG="/etc/ssh/sshd_config"
PIDF="/var/run/sshd.pid"
BACKUP="/root/ccdc-ssh-backup.$(date '+%Y%m%d-%H%M%S')"
MARKER="/var/run/ccdc-ssh-ok"
REVERT_SECS=180

# What we want. Password auth stays on (the scoring bot uses it).
# Left out on purpose: crypto tuning, host keys, MaxStartups, AllowUsers, GSSAPI.
# UsePAM is not set: the Tiny Core OpenSSH is built without PAM.
OPTIONS="PermitRootLogin no
PasswordAuthentication yes
GSSAPIAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication no
AuthorizedKeysFile none
AuthorizedKeysCommand none
HostbasedAuthentication no
IgnoreRhosts yes
KbdInteractiveAuthentication no
DisableForwarding yes
PermitTunnel no
PermitUserEnvironment no
PermitUserRC no
AcceptEnv LANG LC_*
StrictModes yes
MaxAuthTries 4
LoginGraceTime 30
LogLevel VERBOSE
Subsystem sftp internal-sftp"

WORK="$(mktemp -d)"
# shellcheck disable=SC2317  # called through the trap
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

lower() { tr '[:upper:]' '[:lower:]'; }

INSTALLED=0
RELOADED=0
IS_ROOT=0
[ "$(id -u 2>/dev/null)" = 0 ] && IS_ROOT=1

# Reload, never restart: existing sessions must survive.
# The Tiny Core init script has no reload, so signal sshd directly.
reload_sshd() {
  [ -r "$PIDF" ] && kill -HUP "$(cat "$PIDF")" 2>/dev/null
}

# Put the saved configuration back
restore_backup() {
  cat "$BACKUP/sshd_config" >"$CONFIG"
}

finish() {
  header "Summary"
  if [ "$IS_ROOT" = 0 ]; then
    info "Audit only: run as root to apply the hardening"
  fi
  if [ "$RELOADED" = 1 ]; then
    echo "AUTO-REVERT in ${REVERT_SECS}s. To keep the change, log in from ANOTHER terminal:"
    echo "  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no USER@HOST"
    echo "and then, as root:  touch $MARKER"
  fi
  [ "$INSTALLED" = 1 ] && echo "Backup (restore from here if needed): $BACKUP"
  echo "SUMMARY: installed=$INSTALLED reloaded=$RELOADED auto_revert=$((RELOADED * REVERT_SECS))s warnings=$WARNS"
  exit 0
}

# Everything below runs in a subshell: exit only ends the subshell, not the
# caller's shell.
main() {

check_root

# ---- 1. preflight ---------------------------------------------------------
header "Preflight"

if ! have sshd; then
  warn "sshd not found (tce-load -wi openssh), nothing to harden"
  finish
fi
if [ ! -f "$CONFIG" ]; then
  warn "$CONFIG does not exist (start the openssh service once), nothing to harden"
  finish
fi
ok "Found $(command -v sshd) and $CONFIG"

# Effective configuration before we touch anything. Needs root (host keys).
HAVE_T=0
if sshd -T -f "$CONFIG" >"$WORK/before" 2>"$WORK/before.err"; then
  HAVE_T=1
else
  warn "sshd -T failed ($(head -n 1 "$WORK/before.err")), effective values unknown"
fi

PORTS=""
if [ "$HAVE_T" = 1 ]; then
  PORTS="$(grep '^port ' "$WORK/before" | cut -d' ' -f2 | sort -u | tr '\n' ' ')"
fi
if [ -z "$PORTS" ]; then
  PORTS="$(grep -i '^[[:space:]]*Port[[:space:]]' "$CONFIG" | awk '{print $2}' | tr '\n' ' ')"
fi
[ -n "$PORTS" ] || PORTS="22"
info "Configured port(s): $PORTS"

if grep -i '^[[:space:]]*Match[[:space:]]' "$CONFIG" >/dev/null 2>&1; then
  info "$CONFIG has Match blocks, they are removed"
fi
if [ "$HAVE_T" = 1 ] && grep '^passwordauthentication no' "$WORK/before" >/dev/null; then
  warn "password logins are OFF right now: this turns them on and keys off. If nobody knows a password, wait for the auto-revert"
fi

# ---- 2. backup, build, validate, install (root only) ----------------------
header "Apply hardening"

if [ "$IS_ROOT" = 0 ]; then
  info "Not root: would apply these settings, nothing changed"
  printf '%s\n' "$OPTIONS" | while read -r line; do info "  $line"; done
  finish
fi

# 2a. backup. Do not touch anything if we cannot keep the original.
if ! { mkdir -p "$BACKUP" 2>/dev/null && chmod 700 "$BACKUP" && cp -p "$CONFIG" "$BACKUP/sshd_config" 2>/dev/null; }; then
  warn "Could not back up to $BACKUP, refusing to change anything"
  finish
fi
ok "Backup in $BACKUP"

# 2b. candidate = header + lines we keep from the old file + our options.
# Kept: Port, ListenAddress, AddressFamily, HostKey from above any Match.
sed '/^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]/q' "$CONFIG" |
  grep -i -E '^[[:space:]]*(Port|ListenAddress|AddressFamily|HostKey)[[:space:]]' >"$WORK/keep"
if ! grep -i '^[[:space:]]*Port[[:space:]]' "$WORK/keep" >/dev/null; then
  # Port came from the default: pin the effective one
  for p in $PORTS; do echo "Port $p"; done >>"$WORK/keep"
fi
printf '%s\n' "$OPTIONS" >"$WORK/ours"
echo "# Managed by CCDC ssh-harden, original in $BACKUP" >"$WORK/head"

# 2c. validate
cat "$WORK/head" "$WORK/keep" "$WORK/ours" >"$WORK/candidate"
if ! sshd -t -f "$WORK/candidate" 2>"$WORK/err"; then
  warn "sshd rejected the new configuration, nothing changed:"
  sed 's/^/    /' "$WORK/err"
  finish
fi
ok "Candidate passes sshd -t"

# 2d. install. cat keeps the owner and mode of the existing file.
if ! cat "$WORK/candidate" >"$CONFIG" 2>/dev/null; then
  warn "Could not write $CONFIG"
  finish
fi
if sshd -t -f "$CONFIG" 2>"$WORK/err"; then
  INSTALLED=1
  ok "Installed $CONFIG"
else
  warn "Installed config failed sshd -t, restoring the backup:"
  sed 's/^/    /' "$WORK/err"
  restore_backup
  finish
fi

# ---- 3. reload -------------------------------------------------------------
header "Reload"

if reload_sshd; then
  RELOADED=1
  ok "sshd reloaded via SIGHUP to pid in $PIDF (existing sessions are not dropped)"
else
  warn "Could not reload sshd: the new file is installed but not active, reload it by hand. Backup: $BACKUP"
fi

# ---- 4. auto-revert unless a new login is confirmed -------------------------
# The one background process this script leaves behind: a single sleep, then
# it restores the backup unless someone proved they can still get in.
if [ "$RELOADED" = 1 ]; then
  rm -f "$MARKER"
  (
    trap '' HUP # must outlive the SSH session that started it
    sleep "$REVERT_SECS"
    [ -e "$MARKER" ] && exit 0
    restore_backup
    reload_sshd
    log "WARN: ssh-harden: no $MARKER after ${REVERT_SECS}s, restored $BACKUP"
  ) </dev/null >/dev/null 2>&1 &
  info "Auto-revert in ${REVERT_SECS}s unless $MARKER exists"
fi

# ---- 5. verify effective values ---------------------------------------------
header "Effective configuration"

if sshd -T -f "$CONFIG" >"$WORK/after.raw" 2>/dev/null; then
  # sshd -T prints a trailing space after some values
  sed 's/[[:space:]]*$//' "$WORK/after.raw" >"$WORK/after"
  # AcceptEnv is printed as one line per pattern, so it is not compared
  grep -v '^AcceptEnv' "$WORK/ours" >"$WORK/want"
  while read -r key val; do
    want="$(printf '%s' "$key" | lower) $val"
    if grep -i -x -F -- "$want" "$WORK/after" >/dev/null 2>&1; then
      ok "$key $val"
    else
      got="$(grep -i "^$key " "$WORK/after" | head -n 1)"
      warn "$key is not '$val' (effective: ${got:-unknown}), something overrides it"
    fi
  done <"$WORK/want"
else
  info "Skipped, could not read the effective configuration"
fi

finish

}

( main )
