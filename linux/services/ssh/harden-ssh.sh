#!/bin/sh
# status:  draft
# risk:    lockout
# tested:  never (container runs only, see testing/README.md)
#
# Rewrites the SSH SERVER config (sshd_config) from a known-good block, then
# validates it, reloads sshd and checks the effective values with sshd -T.
# The client (ssh_config) is services/any/harden-ssh-client.sh.
#
# WHAT STOPS WORKING: public key logins, root login and all forwarding.
# Password logins stay on, and so do the port, listen address and host keys.
# Drop-ins in sshd_config.d are left on disk but are no longer read (no Include).
# The old config and banner are backed up to /root/ccdc-ssh-backup.<time>/.
# An undo script is printed at the end.
# Not root: shows what it would set, changes nothing.
#
# Asks: "Rewrite <config> ...? (y/N)". --apply answers yes.
#
#   sh harden-ssh.sh [--apply]

PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
export PATH
LC_ALL=C
export LC_ALL

WARNS=0
info() { printf '[ ] %s\n' "$*"; }
ok() { printf '[+] %s\n' "$*"; }
warn() {
  printf '[!] %s\n' "$*"
  WARNS=$((WARNS + 1))
}

APPLY=0
[ "$1" = "--apply" ] && APPLY=1

# y/N from the console. No console and no --apply: the answer is no.
confirm() {
  [ "$APPLY" = 1 ] && return 0
  if ! (: </dev/tty >/dev/tty) 2>/dev/null; then
    warn "No console to ask on, nothing changed (run with --apply to skip the question)"
    return 1
  fi
  printf '%s (y/N): ' "$1" >/dev/tty
  ans=""
  read -r ans </dev/tty
  case "$ans" in y | Y | yes | YES) return 0 ;; esac
  return 1
}

# Password auth stays on: the scoring engine logs in with it.
# Left out on purpose: crypto, host keys, ports, AllowUsers.
OPTIONS="PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
UsePAM yes
PubkeyAuthentication no
AuthorizedKeysFile none
AuthorizedKeysCommand none
HostbasedAuthentication no
IgnoreRhosts yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
GSSAPIAuthentication no
DisableForwarding yes
PermitTunnel no
PermitUserEnvironment no
PermitUserRC no
StrictModes yes
Banner /etc/ssh/sshd_banner
MaxAuthTries 4
LoginGraceTime 30
LogLevel VERBOSE
Subsystem sftp internal-sftp"

BANNER="/etc/ssh/sshd_banner"
SSH_BANNER_TEXT="Legal Notice

This device is the property of our company. By continuing to use this device, you acknowledge and consent to the following:

This device is only to be used for authorized use by authorized users. You consent to the unrestricted monitoring, interception, recording, and searching of all communications and data transiting, travelling to or from, or stored on this system by our company or by any person or entity authorized by our company at any time or for any purpose. You consent, without restriction, to all communications and data transiting, travelling to or from, or stored on this system being disclosed by our company or by any person or entity authorized by our company to any entity, including the government, at any time or for any purpose. You acknowledge without exception that you have no reasonable expectation of privacy regarding your use of this system including for work-related use or any personal use. These acknowledgements and consents cover all uses of the system including work-related and personal use without exception."

WORK="$(mktemp -d 2>/dev/null)" || {
  WORK="/tmp/ccdc-harden-ssh.$$"
  mkdir -m 700 "$WORK" || exit 1
}
trap 'rm -rf "$WORK"' EXIT
trap 'exit 1' HUP INT TERM

IS_ROOT=0
[ "$(id -u)" = 0 ] && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || warn "Not root: dry run, nothing will change"

# ---- 1. find the SSH server -------------------------------------------------
echo "== SSH server =="

# A file is OpenSSH sshd if its binary carries the OpenSSH version string. We
# grep it instead of running it: it may be a planted binary.
is_sshd() { [ -f "$1" ] && grep 'OpenSSH_' "$1" >/dev/null 2>&1; }

# The running daemon decides what matters, not what is on PATH: it may run
# from another path, with another config, or from a binary since replaced.
# /proc/<pid>/exe is the binary that is actually running, even if deleted.
SSHD=""
PID=""
# 1. The listener from ss/netstat (ss lists every owner: "sshd",pid=812 and "systemd",pid=1).
PIDS="$({
  ss -ltnp 2>/dev/null | tr ',' '\n' | sed -n 's/^pid=\([0-9][0-9]*\).*/\1/p'
  netstat -ltnp 2>/dev/null | sed -n 's/.* \([0-9][0-9]*\)\/.*/\1/p'
} | sort -u)"
for p in $PIDS; do
  if is_sshd "/proc/$p/exe"; then
    PID="$p"
    break
  fi
done
# 2. No ss/netstat: an OpenSSH process whose parent is not OpenSSH is the
# listener (sessions are children of it, sshd or sshd-session).
if [ -z "$PID" ]; then
  for d in /proc/[0-9]*; do
    is_sshd "$d/exe" || continue
    pp="$(sed 's/.*) //' "$d/stat" 2>/dev/null | cut -d' ' -f2)"
    is_sshd "/proc/$pp/exe" && continue
    PID="${d#/proc/}"
    break
  done
fi
# The path it was started as. A reload (HUP) re-runs this file, not the running
# copy, so it has to be the same binary. "sshd: /usr/sbin/sshd -D [listener]" on newer sshd.
if [ -n "$PID" ]; then
  SSHD="$(tr '\0' ' ' <"/proc/$PID/cmdline" 2>/dev/null | sed 's/^sshd: //' | cut -d' ' -f1)"
  if ! cmp -s "/proc/$PID/exe" "$SSHD"; then
    warn "sshd pid $PID runs $(readlink "/proc/$PID/exe"), but $SSHD on disk is not that binary (replaced, deleted or relinked)"
    warn "A reload would re-run $SSHD and can kill sshd. Nothing changed. Check that file, then restart sshd by hand"
    echo "SUMMARY: server=$SSHD changed=0 warnings=$WARNS"
    exit 1
  fi
fi
# 3. Nothing running (socket activation, stopped, or not root): the usual places.
if [ -z "$SSHD" ]; then
  for f in "$(command -v sshd 2>/dev/null)" /usr/sbin/sshd /usr/local/sbin/sshd; do
    if is_sshd "$f"; then
      SSHD="$f"
      break
    fi
  done
fi

if [ -z "$SSHD" ]; then
  if command -v ssh >/dev/null 2>&1; then
    info "No SSH server here, only the ssh client. Nothing to do."
    info "For the client run services/any/harden-ssh-client.sh"
  else
    info "No SSH server or client here. Nothing to do."
  fi
  echo "SUMMARY: server=none changed=0 warnings=$WARNS"
  exit 0
fi

# The config the running daemon was started with (-f), or the default. Newer
# sshd rewrites its argv into one string ("sshd: /usr/sbin/sshd -D -f /x [listener]").
CONFIG="/etc/ssh/sshd_config"
if [ -n "$PID" ]; then
  f="$(tr '\0' ' ' <"/proc/$PID/cmdline" 2>/dev/null | sed -n 's/.* -f \([^ ]*\).*/\1/p')"
  [ -n "$f" ] && CONFIG="$f"
fi
ok "sshd: $SSHD${PID:+ (listening, pid $PID)}"
ok "config: $CONFIG"
if [ ! -f "$CONFIG" ]; then
  warn "$CONFIG does not exist, nothing changed"
  exit 1
fi

if [ "$IS_ROOT" = 0 ]; then
  info "Would set:"
  printf '%s\n' "$OPTIONS" | sed 's/^/      /'
  info "Would install $BANNER (root:root, mode 0644; immutable when supported)"
  info "Would make $CONFIG immutable when supported"
  echo "SUMMARY: server=$SSHD changed=0 (dry run) warnings=$WARNS"
  exit 0
fi

# ---- 2. build the new config ------------------------------------------------
echo
echo "== New config =="

if ! "$SSHD" -T -f "$CONFIG" >"$WORK/before" 2>"$WORK/err"; then
  warn "The current config does not load, so it cannot be checked afterwards. Nothing changed:"
  sed 's/^/      /' "$WORK/err"
  exit 1
fi

# Keep where it listens and its host keys exactly as they are now. Taken from
# the effective config, so values that came from drop-ins are kept too.
grep -E '^(port|listenaddress|addressfamily|hostkey) ' "$WORK/before" >"$WORK/pins"
info "Kept: $(cut -d' ' -f1,2 "$WORK/pins" | tr '\n' ' ')"

# An option this sshd version does not know is skipped, one at a time.
: >"$WORK/ours"
printf '%s\n' "$OPTIONS" >"$WORK/options"
while read -r opt; do
  cat "$WORK/pins" >"$WORK/one"
  echo "$opt" >>"$WORK/one"
  if "$SSHD" -t -f "$WORK/one" </dev/null >/dev/null 2>&1; then
    echo "$opt" >>"$WORK/ours"
  else
    warn "This sshd does not accept '$opt', skipped"
  fi
done <"$WORK/options"

{
  echo "# Written by CCDC harden-ssh. No Include, no Match: this file is all of it."
  cat "$WORK/pins" "$WORK/ours"
} >"$WORK/candidate"
if ! "$SSHD" -t -f "$WORK/candidate" 2>"$WORK/err"; then
  warn "sshd rejects the new config, nothing changed:"
  sed 's/^/      /' "$WORK/err"
  exit 1
fi
ok "New config passes sshd -t"
if ! grep -Fqx 'Banner /etc/ssh/sshd_banner' "$WORK/ours"; then
  warn "sshd did not accept the Banner directive; nothing changed"
  exit 1
fi

if ! confirm "Rewrite $CONFIG and install $BANNER: key/root logins OFF, password logins ON?"; then
  info "Nothing changed"
  echo "SUMMARY: server=$SSHD changed=0 warnings=$WARNS"
  exit 0
fi

# ---- 3. back up and install -------------------------------------------------
echo
echo "== Install =="

# Immutability is optional. Always set root ownership and mode 0644.
# Try chattr only when it is available and supported by this filesystem.
IMMUTABLE_SUPPORTED=0
if command -v chattr >/dev/null 2>&1; then
  CHECK="$(mktemp /etc/ssh/.sshd-banner-check.XXXXXX)" || exit 1
  if chattr +i "$CHECK" 2>"$WORK/err"; then
    if chattr -i "$CHECK" && rm -f "$CHECK"; then
      IMMUTABLE_SUPPORTED=1
    else
      warn "Unable to clear immutable flag on $CHECK; clean up manually"
      exit 1
    fi
  else
    warn "chattr +i unavailable on /etc/ssh; proceeding without immutability"
    rm -f "$CHECK"
  fi
else
  info "chattr not installed; proceeding without immutability"
fi
if [ -L "$CONFIG" ]; then
  warn "$CONFIG is a symlink; refusing to change its target's immutability"
  exit 1
fi
if [ -L "$BANNER" ] || { [ -e "$BANNER" ] && [ ! -f "$BANNER" ]; }; then
  warn "$BANNER is not a regular file (or is a symlink); nothing changed"
  exit 1
fi

BACKUP="/root/ccdc-ssh-backup.$(date '+%Y%m%d-%H%M%S').$$"
if ! mkdir -m 700 "$BACKUP" 2>/dev/null || ! cp -p "$CONFIG" "$BACKUP/sshd_config"; then
  warn "Could not back up to $BACKUP, refusing to change anything"
  exit 1
fi
BANNER_EXISTED=0
BANNER_IMMUTABLE=0
if [ -e "$BANNER" ]; then
  BANNER_EXISTED=1
  if ! cp -p "$BANNER" "$BACKUP/sshd_banner"; then
    warn "Could not back up $BANNER, refusing to change anything"
    exit 1
  fi
  if command -v lsattr >/dev/null 2>&1; then
    attributes="$(lsattr -d "$BANNER" 2>/dev/null)" || attributes=""
    case "${attributes%% *}" in *i*) BANNER_IMMUTABLE=1 ;; esac
  fi
  if [ "$BANNER_IMMUTABLE" = 1 ] && [ "$IMMUTABLE_SUPPORTED" = 0 ]; then
    warn "Existing banner is immutable but cannot safely clear/reapply its flag; nothing changed"
    exit 1
  fi
fi
# Capture existing immutable state so a rerun can update an already-protected
# config and rollback/undo can restore the original state.
CONFIG_IMMUTABLE=0
if command -v lsattr >/dev/null 2>&1; then
  attributes="$(lsattr -d "$CONFIG" 2>/dev/null)" || attributes=""
  case "${attributes%% *}" in *i*) CONFIG_IMMUTABLE=1 ;; esac
fi
if [ "$CONFIG_IMMUTABLE" = 1 ] && [ "$IMMUTABLE_SUPPORTED" = 0 ]; then
  warn "Existing config is immutable but cannot safely clear/reapply its flag; nothing changed"
  exit 1
fi
ok "Backup: $BACKUP"

# Restore the banner's original contents and immutable state if anything fails.
restore_banner() {
  if command -v chattr >/dev/null 2>&1; then chattr -i "$BANNER" 2>/dev/null || :; fi
  if [ "$BANNER_EXISTED" = 1 ]; then
    if ! cp -p "$BACKUP/sshd_banner" "$BANNER"; then
      warn "Failed restoring banner from $BACKUP/sshd_banner"
      return 1
    fi
    if [ "$BANNER_IMMUTABLE" = 1 ]; then
      chattr +i "$BANNER" || return 1
    fi
  else
    rm -f "$BANNER" || return 1
  fi
}

# Copy the banner while temporarily clearing the old immutable bit if needed.
# Mode 0644 allows only root to write once immutable is cleared.
if [ "$BANNER_IMMUTABLE" = 1 ] && ! chattr -i "$BANNER"; then
  warn "Cannot clear old banner's immutable bit; nothing changed"
  exit 1
fi
umask 077
if ! printf '%s\n' "$SSH_BANNER_TEXT" >"$BANNER" ||
  ! chown 0:0 "$BANNER" ||
  ! chmod 0644 "$BANNER"; then
  warn "Could not install banner; restoring previous banner"
  restore_banner || warn "Banner rollback failed; manual recovery required"
  exit 1
fi
# Apply immutable flag when supported; failure is nonfatal.
BANNER_IMMUTABLE_NEW=0
if [ "$IMMUTABLE_SUPPORTED" = 1 ]; then
  if chattr +i "$BANNER"; then
    BANNER_IMMUTABLE_NEW=1
  else
    warn "Could not mark $BANNER immutable; continuing with root-only write permissions"
  fi
fi
if [ "$(stat -c '%u:%g:%a' "$BANNER" 2>/dev/null)" != '0:0:644' ]; then
  warn "Banner ownership or permissions incorrect; restoring banner"
  restore_banner || warn "Banner rollback failed"
  exit 1
fi
if [ "$BANNER_IMMUTABLE_NEW" = 1 ]; then
  ok "Installed immutable banner: $BANNER (root:root, 0644, chattr +i)"
else
  ok "Installed banner: $BANNER (root:root, 0644; immutability skipped)"
fi

# Which systemd unit runs sshd: ssh on Debian/Ubuntu, sshd elsewhere.
UNIT=""
for u in ssh.service sshd.service; do
  systemctl is-active "$u" >/dev/null 2>&1 && UNIT="$u" && break
done
SOCKET=""
for u in ssh.socket sshd.socket; do
  systemctl is-active "$u" >/dev/null 2>&1 && SOCKET="$u" && break
done

# Socket activation runs one sshd per connection: nothing to reload, and a
# HUP there would hit someone's session.
reload() {
  if [ -n "$UNIT" ]; then
    systemctl reload "$UNIT"
  elif [ -z "$SOCKET" ] && [ -n "$PID" ]; then
    kill -HUP "$PID" # started by hand, outside systemd
  fi
}

# Persist a complete undo script (config + previous banner and its attributes).
# This is intentionally a separate root-only file, so recovery is one command.
cat >"$BACKUP/undo.sh" <<EOF
#!/bin/sh
set -e
command -v chattr >/dev/null 2>&1 && chattr -i '$BANNER' 2>/dev/null || :
EOF
if [ "$BANNER_EXISTED" = 1 ]; then
  printf "cp -p '%s/sshd_banner' '%s'\n" "$BACKUP" "$BANNER" >>"$BACKUP/undo.sh"
  if [ "$BANNER_IMMUTABLE" = 1 ]; then
    printf "chattr +i '%s'\n" "$BANNER" >>"$BACKUP/undo.sh"
  fi
else
  printf "rm -f '%s'\n" "$BANNER" >>"$BACKUP/undo.sh"
fi
cat >>"$BACKUP/undo.sh" <<EOF
command -v chattr >/dev/null 2>&1 && chattr -i '$CONFIG' 2>/dev/null || :
EOF
printf "cp -p '%s/sshd_config' '%s'\n" "$BACKUP" "$CONFIG" >>"$BACKUP/undo.sh"
if [ "$CONFIG_IMMUTABLE" = 1 ]; then
  printf "chattr +i '%s'\n" "$CONFIG" >>"$BACKUP/undo.sh"
fi
if [ -n "$UNIT" ]; then
  printf "systemctl reload '%s'\n" "$UNIT" >>"$BACKUP/undo.sh"
elif [ -z "$SOCKET" ] && [ -n "$PID" ]; then
  printf "kill -HUP '%s'\n" "$PID" >>"$BACKUP/undo.sh"
fi
chmod 0700 "$BACKUP/undo.sh"
UNDO="sh $BACKUP/undo.sh"

restore() {
  # An immutable config must be unlocked before copying its backup.
  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$CONFIG" 2>/dev/null || :
  fi
  if ! cp -p "$BACKUP/sshd_config" "$CONFIG"; then
    warn "Failed restoring config from $BACKUP/sshd_config"
  fi
  if [ "$CONFIG_IMMUTABLE" = 1 ] && ! chattr +i "$CONFIG"; then
    warn "Failed restoring original config immutable attribute"
  fi
  if ! restore_banner; then
    warn "Failed restoring banner; manual recovery required"
  fi
  reload || warn "Reload of restored config failed"
  warn "Restored config and banner from $BACKUP"
}

# Temporarily unlock an existing protected config for the validated rewrite.
if [ "$CONFIG_IMMUTABLE" = 1 ] && ! chattr -i "$CONFIG"; then
  warn "Cannot clear existing config immutable bit; restoring banner"
  restore_banner || warn "Banner rollback failed"
  exit 1
fi
# cp onto the existing file keeps its owner, mode and SELinux label.
if ! cp "$WORK/candidate" "$CONFIG" || ! "$SSHD" -t -f "$CONFIG" 2>"$WORK/err"; then
  warn "Installing $CONFIG failed:"
  sed 's/^/      /' "$WORK/err"
  restore
  exit 1
fi
ok "Installed $CONFIG"

# Reload, never restart: open sessions stay up.
if [ -n "$UNIT" ]; then
  how="systemctl reload $UNIT"
elif [ -n "$SOCKET" ]; then
  how="none needed, $SOCKET starts sshd per connection with the new file"
elif [ -n "$PID" ]; then
  how="SIGHUP to pid $PID (not run by systemd)"
else
  how="none, sshd is not running; it uses the new file when started"
fi
if ! reload; then
  warn "Reload failed ($how)"
  restore
  exit 1
fi
# sshd re-execs on reload and keeps its pid. Gone = it died on the reload.
# Under socket activation PID is a per-connection sshd that may simply end.
sleep 1
if [ -n "$PID" ] && { [ -n "$UNIT" ] || [ -z "$SOCKET" ]; } && ! kill -0 "$PID" 2>/dev/null; then
  warn "sshd (pid $PID) DIED after the reload"
  restore
  if [ -n "$UNIT" ]; then
    systemctl start "$UNIT"
  else
    "$SSHD" -f "$CONFIG"
  fi
  warn "Started sshd again on the old config, check it is listening"
  exit 1
fi
ok "Reload: $how"

# ---- 4. check the effective values -----------------------------------------
echo
echo "== Effective config =="

# sshd -T prints a trailing space after some values
if "$SSHD" -T -f "$CONFIG" >"$WORK/after.raw" 2>/dev/null; then
  sed 's/[[:space:]]*$//' "$WORK/after.raw" >"$WORK/after"
  while read -r key val; do
    k="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')"
    if grep -i -x -F "$k $val" "$WORK/after" >/dev/null; then
      ok "$key $val"
    elif grep "^$k " "$WORK/after" >/dev/null; then
      warn "$key is not '$val' (effective: $(grep "^$k " "$WORK/after" | head -n 1))"
    fi
    # Not printed at all: an alias (ChallengeResponseAuthentication) or not built in (UsePAM).
  done <"$WORK/ours"
else
  warn "sshd -T failed after the install, check by hand"
fi

# Protect sshd_config only after validation and successful daemon reload.
# Failure to apply immutability is nonfatal, just as for the banner.
if [ "$IMMUTABLE_SUPPORTED" = 1 ]; then
  if chattr +i "$CONFIG"; then
    ok "Protected config: $CONFIG (chattr +i)"
  else
    warn "Could not mark $CONFIG immutable; continuing with its existing permissions"
  fi
else
  info "Config immutability skipped: $CONFIG"
fi

echo
if command -v lsattr >/dev/null 2>&1; then
  info "Config attributes: $(lsattr -d "$CONFIG" 2>/dev/null || echo unavailable)"
  info "Banner attributes: $(lsattr -d "$BANNER" 2>/dev/null || echo unavailable)"
else
  info "Banner installed (lsattr unavailable)"
fi
info "Test a password login now from this console:  ssh USER@127.0.0.1"
info "Undo:  $UNDO"
echo "SUMMARY: server=$SSHD changed=1 backup=$BACKUP warnings=$WARNS"
