#!/bin/sh
# status:  wip
# risk:    service-impact
# tested:  never
#
# One job: change Splunk's configuration in ONE batch with ONE restart:
#   1. new password for every local Splunk user you give one (the hash is
#      written into $SPLUNK_HOME/etc/passwd while Splunk is stopped, so the old
#      passwords are not needed and no user is removed or renamed)
#   2. disable the PostgreSQL sidecar ([postgres] disabled = true in server.conf)
#   3. disable unused apps (Secure Gateway, Pipeline Builders, o11y, SPL2)
# Looking (run-as user, code-exec surfaces, capabilities) is NOT done here.
#
# WHAT STOPS WORKING: Splunk Web (8000) and management (8089) are down for the
# restart, about a minute. Edge Processor, OpAmp and SPL2 pipelines stop.
# Anything that logs in with an old Splunk password (including the scoring
# engine) fails until its credentials are updated, e.g. on the Quotient PCR tab.
# Not touched: ports, ssl, allowRemoteLogin, usernames, roles, SSH.
#
# Not root: shows what it would change, changes nothing.
# Backup: tar of everything changed in /root/ccdc-splunk-backup.<time>/. The
# script restores it itself if Splunk does not come back or the login fails.
# The undo command is printed at the end.
#
# Asks:
#   "New password for Splunk user <name> (blank = leave it)"   hidden, twice
#   "Stop Splunk, change N password(s), disable ...? (y/N)"
#
#   sh services/systemd/harden-splunk.sh

# shellcheck disable=SC2009,SC2012,SC2016,SC2116,SC2086,SC2018,SC2019  # ls owner, word lists, ASCII names
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
export PATH
LC_ALL=C
export LC_ALL

WARNS=0
info() { printf '[ ] %s\n' "$*"; }
ok() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; WARNS=$((WARNS + 1)); }
have() { command -v "$1" >/dev/null 2>&1; }

TTY_OK=0
if (: </dev/tty >/dev/tty) 2>/dev/null; then TTY_OK=1; fi

tty_restore() {
  [ "$TTY_OK" = 1 ] && stty echo </dev/tty 2>/dev/null
  return 0
}

# ask_secret "question": typed text is not shown and not stored anywhere.
ask_secret() {
  REPLY=""
  [ "$TTY_OK" = 1 ] || return 1
  printf '%s: ' "$1" >/dev/tty
  stty -echo </dev/tty 2>/dev/null
  read -r REPLY </dev/tty
  rc=$?
  tty_restore
  printf '\n' >/dev/tty
  return $rc
}

# confirm "what will change": true only if the user types y.
confirm() {
  if [ "$TTY_OK" != 1 ]; then
    warn "No console to ask on; skipped: $1"
    return 1
  fi
  printf '%s (y/N): ' "$1" >/dev/tty
  ans=""
  read -r ans </dev/tty
  case "$ans" in y | Y | yes | YES | Yes) return 0 ;; esac
  return 1
}

HASHES=""   # temp file: "user hash" lines (hashes only, never passwords)
NEWPW=""    # temp file: new passwd file while it is being built
cleanup() {
  [ -n "$HASHES" ] && rm -f "$HASHES"
  [ -n "$NEWPW" ] && rm -f "$NEWPW"
  tty_restore
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# sha512-crypt hash of the password on stdin (what Splunk 7+ stores).
hash_pw() {
  if have openssl && printf 'x\n' | openssl passwd -6 -stdin >/dev/null 2>&1; then
    openssl passwd -6 -stdin
  elif have mkpasswd; then
    mkpasswd -m sha-512 -s
  else
    return 1
  fi
}

# Run the splunk CLI as the user that owns the install.
splunk() {
  if [ "$OWNER" != root ] && [ "$(id -u)" = 0 ] && have su; then
    su -s /bin/sh -c "$S/bin/splunk $*" "$OWNER" </dev/null
  else
    "$S/bin/splunk" "$@" </dev/null
  fi
}

svc_stop() {
  if [ -n "$UNIT" ]; then systemctl stop "$UNIT" </dev/null; else splunk stop; fi
}
svc_start() {
  if [ -n "$UNIT" ]; then
    systemctl start "$UNIT" </dev/null
  else
    splunk start --accept-license --answer-yes --no-prompt
  fi
}

# Prints the HTTP status of the management port for admin-ish login $VU/$VPW.
# The password goes to curl through a pipe, not the argument list.
probe() {
  esc="$(printf '%s' "$VPW" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  printf 'user = "%s:%s"\n' "$VU" "$esc" |
    curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 -K - \
      https://127.0.0.1:8089/services/authentication/current-context 2>/dev/null
}

# Put everything back from the backup tar and start again.
rollback() {
  warn "Rolling back from $BK/etc.tar"
  svc_stop >/dev/null 2>&1
  tar xf "$BK/etc.tar" -C "$S" || warn "Restore failed, do it by hand: tar xf $BK/etc.tar -C $S"
  for f in $CREATED; do rm -f "$f"; done
  svc_start >/dev/null 2>&1 || warn "Splunk did not start after the rollback"
}

main() {
  echo "Splunk configuration hardening"
  ROOT=1
  if [ "$(id -u 2>/dev/null)" != 0 ]; then
    ROOT=0
    warn "Not running as root; results may be incomplete. Nothing will be changed."
  fi

  # ---- 1. find the install from the running splunkd, else /opt/splunk -------
  echo "== Discover =="
  S=""
  RUNNING=0
  for p in /proc/[0-9]*; do
    exe="$(readlink "$p/exe" 2>/dev/null)"
    case "$exe" in
      */bin/splunkd) S="${exe%/bin/splunkd}"; RUNNING=1; break ;;
    esac
  done
  if [ -z "$S" ] && [ -x /opt/splunk/bin/splunk ]; then S=/opt/splunk; fi
  if [ -z "$S" ]; then
    warn "No Splunk found (no running splunkd, no /opt/splunk). Nothing to do."
    return 0
  fi
  PW="$S/etc/passwd"
  LOCALD="$S/etc/system/local"
  if [ ! -r "$PW" ]; then
    warn "Cannot read $PW; run as root or check the install"
    return 0
  fi
  OWNER="$(ls -ld "$PW" | awk '{print $3}')"
  UNIT=""
  if have systemctl && systemctl cat Splunkd.service >/dev/null 2>&1; then UNIT=Splunkd; fi
  info "Splunk home: $S (running=$RUNNING, file owner=$OWNER, systemd unit=${UNIT:-none})"

  USERS="$(awk -F: '$2 != "" {print $2}' "$PW")"
  info "Local Splunk users: $(echo $USERS)"

  PG_DONE=0
  if grep -s '^\[postgres\]' "$LOCALD/server.conf" >/dev/null; then
    if grep -s -i '^disabled *= *true' "$LOCALD/server.conf" >/dev/null; then
      PG_DONE=1
      ok "[postgres] already disabled in local/server.conf"
    else
      warn "[postgres] stanza already in local/server.conf without disabled = true; fix it by hand"
      PG_DONE=1
    fi
  fi

  APPS=""
  for d in "$S"/etc/apps/*; do
    [ -d "$d" ] || continue
    n="$(basename "$d")"
    lower="$(echo "$n" | tr 'A-Z' 'a-z')"
    case "$lower" in
      *secure*gateway* | *pipeline* | *o11y* | *observ* | *spl2* | *edge*processor*) ;;
      *) continue ;;
    esac
    if grep -s -i '^state *= *disabled' "$d/local/app.conf" >/dev/null; then
      info "App already disabled: $n"
    else
      APPS="$APPS $n"
    fi
  done
  info "Apps to disable:${APPS:- none}"

  # ---- 2. dry run when not root ---------------------------------------------
  if [ "$ROOT" = 0 ]; then
    echo "== Would change (as root) =="
    info "Ask for a new password per user, then stop Splunk and rewrite their hashes in $PW"
    [ "$PG_DONE" = 0 ] && info "Append [postgres] disabled = true to $LOCALD/server.conf"
    for a in $APPS; do info "Disable app $a (local/app.conf: state = disabled)"; done
    echo "SUMMARY: changed=0 warnings=$WARNS (dry run)"
    return 0
  fi
  if [ "$TTY_OK" != 1 ]; then
    warn "No console to ask on; nothing changed"
    echo "SUMMARY: changed=0 warnings=$WARNS"
    return 0
  fi
  if ! printf 'x\n' | hash_pw >/dev/null 2>&1; then
    warn "Cannot hash passwords: install openssl (1.1.1 or newer) or whois (mkpasswd). Passwords skipped."
    NOHASH=1
  else
    NOHASH=0
  fi

  # ---- 3. questions ----------------------------------------------------------
  echo "== Passwords =="
  HASHES="$(mktemp 2>/dev/null)" || HASHES="/tmp/ccdc-splunk-h.$$"
  : >"$HASHES"
  chmod 600 "$HASHES"
  NCH=0
  VU=""
  VPW=""
  if [ "$NOHASH" = 0 ]; then
    for u in $USERS; do
      ask_secret "New password for Splunk user $u (blank = leave it)" || break
      p1="$REPLY"
      [ -n "$p1" ] || continue
      ask_secret "Again" || break
      if [ "$REPLY" != "$p1" ]; then
        warn "Passwords for $u did not match; left unchanged"
        continue
      fi
      h="$(printf '%s\n' "$p1" | hash_pw)"
      case "$h" in
        '$6$'*) ;;
        *) warn "Hashing failed for $u; left unchanged"; continue ;;
      esac
      printf '%s %s\n' "$u" "$h" >>"$HASHES"
      NCH=$((NCH + 1))
      if [ -z "$VU" ]; then VU="$u"; VPW="$p1"; fi
    done
  fi
  [ "$NCH" -gt 0 ] || info "No passwords will be changed"

  PLAN="change $NCH password(s)"
  [ "$PG_DONE" = 0 ] && PLAN="$PLAN, disable the postgres sidecar"
  [ -n "$APPS" ] && PLAN="$PLAN, disable apps:$APPS"
  if [ "$NCH" = 0 ] && [ "$PG_DONE" = 1 ] && [ -z "$APPS" ]; then
    ok "Nothing to change"
    echo "SUMMARY: changed=0 warnings=$WARNS"
    return 0
  fi
  if ! confirm "Stop Splunk (Web and 8089 go down for about a minute), $PLAN, then start it"; then
    info "Nothing changed"
    echo "SUMMARY: changed=0 warnings=$WARNS"
    return 0
  fi

  # ---- 4. back up, refuse to go on if it fails -------------------------------
  echo "== Backup =="
  BK="/root/ccdc-splunk-backup.$(date '+%Y%m%d%H%M%S')"
  FILES="etc/passwd"
  CREATED=""
  [ -f "$LOCALD/server.conf" ] && FILES="$FILES etc/system/local/server.conf"
  [ ! -f "$LOCALD/server.conf" ] && CREATED="$LOCALD/server.conf"
  for a in $APPS; do
    if [ -f "$S/etc/apps/$a/local/app.conf" ]; then
      FILES="$FILES etc/apps/$a/local/app.conf"
    else
      CREATED="$CREATED $S/etc/apps/$a/local/app.conf"
    fi
  done
  if ! (umask 077 && mkdir -p "$BK" && tar cf "$BK/etc.tar" -C "$S" $FILES) 2>/dev/null; then
    warn "Backup to $BK failed. Nothing changed."
    echo "SUMMARY: changed=0 warnings=$WARNS"
    return 0
  fi
  ok "Backed up: $FILES"

  # ---- 5. stop, edit, start --------------------------------------------------
  echo "== Change =="
  if [ "$RUNNING" = 1 ]; then
    svc_stop >/dev/null 2>&1 || warn "Stop reported an error; continuing only if splunkd is gone"
    for p in /proc/[0-9]*; do
      case "$(readlink "$p/exe" 2>/dev/null)" in
        */bin/splunkd) warn "splunkd is still running; not editing. Nothing changed."; return 0 ;;
      esac
    done
  fi

  if [ "$NCH" -gt 0 ]; then
    NEWPW="$(mktemp 2>/dev/null)" || NEWPW="/tmp/ccdc-splunk-p.$$"
    # First file is the hashes, second the passwd file; field 3 is the hash.
    awk -F: 'BEGIN { OFS = ":" }
      NR == FNR { split($0, a, " "); h[a[1]] = a[2]; next }
      ($2 in h) { $3 = h[$2] }
      { print }' "$HASHES" "$PW" >"$NEWPW"
    if [ -s "$NEWPW" ] && [ "$(wc -l <"$NEWPW")" = "$(wc -l <"$PW")" ]; then
      cat "$NEWPW" >"$PW" && ok "Rewrote $NCH hash(es) in $PW"
    else
      warn "New passwd file looks wrong; left $PW alone"
      NCH=0
      VU=""
    fi
  fi

  if [ "$PG_DONE" = 0 ]; then
    mkdir -p "$LOCALD"
    printf '\n[postgres]\ndisabled = true\n' >>"$LOCALD/server.conf"
    chown "$OWNER" "$LOCALD/server.conf" 2>/dev/null
    ok "Added [postgres] disabled = true"
  fi

  for a in $APPS; do
    mkdir -p "$S/etc/apps/$a/local"
    printf '\n[install]\nstate = disabled\n' >>"$S/etc/apps/$a/local/app.conf"
    chown "$OWNER" "$S/etc/apps/$a/local" "$S/etc/apps/$a/local/app.conf" 2>/dev/null
    ok "Disabled app $a"
  done

  if [ "$RUNNING" = 1 ]; then
    svc_start >/dev/null 2>&1 || warn "Start reported an error; checking anyway"
  else
    info "Splunk was not running before; left stopped"
  fi

  # ---- 6. check from the system ----------------------------------------------
  echo "== Check =="
  if [ "$RUNNING" = 1 ]; then
    if ! have curl; then
      warn "curl is missing (install curl): cannot check the login or that Splunk is up"
    else
      # Any HTTP answer means splunkd is up; 000 means no answer yet. Wait up to 3 minutes.
      probe_user="${VU:-admin}"
      VU="$probe_user"
      code=000
      i=0
      while [ "$i" -lt 36 ] && [ "$code" = 000 ]; do
        code="$(probe)"
        [ "$code" = 000 ] && sleep 5
        i=$((i + 1))
      done
      if [ "$code" = 000 ]; then
        warn "Splunk management port did not answer after the restart"
        rollback
        echo "SUMMARY: changed=0 warnings=$WARNS (rolled back)"
        return 0
      fi
      if [ "$NCH" -gt 0 ]; then
        if [ "$code" = 200 ]; then
          ok "Login as $VU with the new password works (HTTP 200)"
        else
          warn "Login as $VU with the new password returned HTTP $code"
          rollback
          echo "SUMMARY: changed=0 warnings=$WARNS (rolled back)"
          return 0
        fi
      else
        ok "Management port answers (HTTP $code)"
      fi
    fi
    if ps -ef 2>/dev/null | grep '[p]ostgres' >/dev/null; then
      warn "A postgres process is still running"
    else
      ok "No postgres process"
    fi
    eff="$(splunk btool server list postgres 2>/dev/null | grep -i '^disabled')"
    case "$eff" in
      *true*) ok "Effective [postgres] $eff" ;;
      *) warn "Effective [postgres] disabled is not true (got: ${eff:-nothing})" ;;
    esac
    for a in $APPS; do
      eff="$(splunk btool app list install --app="$a" 2>/dev/null | grep -i '^state')"
      case "$eff" in
        *disabled*) ok "App $a: $eff" ;;
        *) warn "App $a is not disabled (got: ${eff:-nothing})" ;;
      esac
    done
  fi

  # ---- report ----------------------------------------------------------------
  echo "== Next =="
  info "Update every changed credential the scoring engine uses (Quotient PCR) and watch the checks."
  info "Undo: systemctl stop ${UNIT:-Splunkd}; tar xf $BK/etc.tar -C $S; rm -f$CREATED; start Splunk again"
  echo "SUMMARY: passwords=$NCH postgres=$([ "$PG_DONE" = 0 ] && echo disabled || echo unchanged) apps=$(echo $APPS | wc -w | tr -d ' ') warnings=$WARNS"
  return 0
}

( main )
