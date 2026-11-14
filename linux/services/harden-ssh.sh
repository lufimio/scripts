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
# The old file is copied to /root/ccdc-ssh-backup.<time>/ and the undo command
# is printed at the end.
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
warn() { printf '[!] %s\n' "$*"; WARNS=$((WARNS + 1)); }

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
MaxAuthTries 4
LoginGraceTime 30
LogLevel VERBOSE
Subsystem sftp internal-sftp"

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

if ! confirm "Rewrite $CONFIG: key logins and root login OFF, password logins stay ON?"; then
  info "Nothing changed"
  echo "SUMMARY: server=$SSHD changed=0 warnings=$WARNS"
  exit 0
fi

# ---- 3. back up and install -------------------------------------------------
echo
echo "== Install =="

BACKUP="/root/ccdc-ssh-backup.$(date '+%Y%m%d-%H%M%S')"
if ! mkdir -m 700 "$BACKUP" 2>/dev/null || ! cp -p "$CONFIG" "$BACKUP/sshd_config"; then
  warn "Could not back up to $BACKUP, refusing to change anything"
  exit 1
fi
ok "Backup: $BACKUP/sshd_config"

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

UNDO="cp -p $BACKUP/sshd_config $CONFIG"
if [ -n "$UNIT" ]; then
  UNDO="$UNDO && systemctl reload $UNIT"
elif [ -z "$SOCKET" ] && [ -n "$PID" ]; then
  UNDO="$UNDO && kill -HUP $PID"
fi

restore() {
  cp -p "$BACKUP/sshd_config" "$CONFIG"
  reload
  warn "Restored $CONFIG from the backup"
}

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

echo
info "Test a password login now from this console:  ssh USER@127.0.0.1"
info "Undo:  $UNDO"
echo "SUMMARY: server=$SSHD changed=1 backup=$BACKUP warnings=$WARNS"
