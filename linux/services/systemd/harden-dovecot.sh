#!/bin/sh
# status:  wip
# risk:    service-impact
# tested:  never
#
# Box: Ubuntu 22.04 Email box (.15).
# JOB: Harden Dovecot: TLS, auth mechanisms, limit protocols. Back up
#      /etc/dovecot, validate with doveconf -n, reload.
# WHAT MUST KEEP WORKING: IMAP/POP3 logins with AD usernames (audit the
#      SSSD/LDAP/PAM backend first); ports 110, 143, 993, 995; stored mail.
# Pattern: services/systemd/harden-ssh.sh (backup, validate, reload, check the
# effective value, print the undo).
#
# Asks: nothing (non-interactive). Optional env var, default OFF:
#   ENFORCE_TLS=1  disable_plaintext_auth=yes (plain logins on 110/143 refused
#                  unless TLS; localhost, e.g. webmail on this box, is exempt).
#   ENFORCE_TLS=2  also ssl=required (STARTTLS/TLS mandatory for everyone, even
#                  localhost; webmail must use TLS to IMAP). HIGH break risk.
#   Only enable after confirming the scorer uses TLS. Watch Quotient 2-3 cycles.
#
# Design: all changes go into ONE drop-in, /etc/dovecot/conf.d/99-harden.conf,
# so undo is "rm the file + reload". Nothing in the existing config is edited.
# The auth backend (passdb/userdb) and auth_username_format are NEVER touched.
# Rolls back automatically if doveconf fails, dovecot dies, or a login-banner
# probe on a listening port stops answering.

PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export PATH
set -f

ENFORCE_TLS=${ENFORCE_TLS:-0}
TS=$(date +%Y%m%d-%H%M%S)
BAKDIR=/root/bak
BK="$BAKDIR/dovecot-$TS.tar.gz"          # service: dovecot + TLS certs
BKA="$BAKDIR/dovecot-auth-$TS.tar.gz"    # auth: PAM/SSSD/Kerberos/NSS
DROP=/etc/dovecot/conf.d/99-harden.conf
ITEMS=0
WARNS=0
NEED_RESTART=0

say()  { printf '%s\n' "$*"; }
ok()   { ITEMS=$((ITEMS+1)); say "[+] $*"; }
warn() { WARNS=$((WARNS+1)); say "[!] $*"; }
info() { say "[*] $*"; }
finish() { say "SUMMARY: items=$ITEMS warnings=$WARNS"; exit "${1:-0}"; }

if [ "$(id -u)" != 0 ]; then
  warn "Not running as root; cannot harden"
  finish 1
fi
command -v doveconf >/dev/null 2>&1 || { warn "dovecot/doveconf not installed"; finish 1; }
TMP=$(mktemp -d 2>/dev/null) || { warn "mktemp failed"; finish 1; }
trap 'rm -rf "$TMP"' EXIT

TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout 10"

mk_bak() { # outfile paths(relative to /)...: archive only paths that exist
  out=$1; shift; list=""
  for p in "$@"; do [ -e "/$p" ] && list="$list $p"; done
  tar czf "$out" -C / $list 2>/dev/null && chmod 600 "$out"
}

has() { case " $1 " in *" $2 "*) return 0 ;; esac; return 1; }
have_setting() { grep -q "^$1 = " "$TMP/all.txt"; }
CONF="$TMP/99-harden.conf"; WANT="$TMP/want.txt"; : >"$CONF"; : >"$WANT"
want() { # name value : append to drop-in if effective value differs
  if ! have_setting "$1"; then info "$1 not supported by this Dovecot, skipped"; return 0; fi
  cur=$(doveconf -h "$1" 2>/dev/null)
  if [ "$cur" = "$2" ]; then info "$1 already '$2'"; return 0; fi
  printf '%s = %s\n' "$1" "$2" >>"$CONF"
  printf '%s=%s\n' "$1" "$2" >>"$WANT"
  ok "$1: '$cur' -> '$2'"
}

reload_dovecot() {
  if [ "$NEED_RESTART" = 1 ]; then
    systemctl restart dovecot >/dev/null 2>&1
  elif systemctl is-active --quiet dovecot 2>/dev/null; then
    systemctl reload dovecot >/dev/null 2>&1 || doveadm reload >/dev/null 2>&1
  else
    systemctl start dovecot >/dev/null 2>&1
  fi
}
rollback() {
  warn "ROLLING BACK: removing $DROP and restoring /etc/dovecot from $BK"
  rm -f "$DROP"
  tar xzf "$BK" -C / etc/dovecot || warn "tar restore failed, restore manually"
  systemctl restart dovecot >/dev/null 2>&1
}
listening() { ss -H -tln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"; }

probe_imap()  { printf 'a1 LOGOUT\r\n' | nc -w 5 127.0.0.1 "$1" 2>/dev/null | head -1 | grep -q 'OK'; }
probe_pop3()  { printf 'QUIT\r\n' | nc -w 5 127.0.0.1 "$1" 2>/dev/null | head -1 | grep -q '^+OK'; }
probe_imaps() { printf 'a1 LOGOUT\r\n' | $TO openssl s_client -connect 127.0.0.1:"$1" -quiet 2>/dev/null | head -1 | grep -q 'OK'; }
probe_pop3s() { printf 'QUIT\r\n' | $TO openssl s_client -connect 127.0.0.1:"$1" -quiet 2>/dev/null | head -1 | grep -q '^+OK'; }

audit_listeners() { # warns on non-loopback dovecot listeners outside 110/143/993/995
  ss -H -tlnp 2>/dev/null | grep -E 'dovecot|imap-login|pop3-login|doveadm|managesieve|submission|lmtp' >"$TMP/dlisten.txt"
  while read -r st rq sq la pa rest; do
    port=${la##*:}; addr=${la%:*}
    case "$addr" in 127.*|'[::1]'|::1) continue ;; esac
    case "$port" in 110|143|993|995) ;; *) warn "unexpected Dovecot listener on $la (extra service, e.g. doveadm/managesieve?)";; esac
  done <"$TMP/dlisten.txt"
}

# ---------------------------------------------------------------- preflight
say "== Preflight =="
doveconf -a >"$TMP/all.txt" 2>/dev/null
if ! doveconf -n >/dev/null 2>"$TMP/pre.txt"; then
  warn "doveconf -n ALREADY fails; refusing to change anything:"
  sed 's/^/    /' "$TMP/pre.txt"
  finish 1
fi
mkdir -p "$BAKDIR" && chmod 700 "$BAKDIR"
if mk_bak "$BK" etc/dovecot etc/ssl; then
  ok "service backup (dovecot, ssl) -> $BK"
else
  warn "backup failed; aborting without changes"; finish 1
fi
mk_bak "$BKA" etc/pam.d etc/sssd etc/krb5.conf etc/nsswitch.conf && ok "auth backup (pam.d, sssd, krb5, nsswitch) -> $BKA" || warn "auth backup failed"
# move a previous run's drop-in aside so effective values are the ORIGINAL ones
if [ -f "$DROP" ]; then
  mv "$DROP" "$BAKDIR/99-harden.conf.$TS" && info "previous drop-in moved to $BAKDIR/99-harden.conf.$TS"
  doveconf -a >"$TMP/all.txt" 2>/dev/null
fi
doveconf -n >"$BAKDIR/dovecot-n-$TS.txt" 2>/dev/null
info "version: $(dovecot --version 2>/dev/null)"
if systemctl is-active --quiet dovecot 2>/dev/null; then info "dovecot is active"; else warn "dovecot is NOT active before changes"; fi
systemctl is-enabled --quiet dovecot 2>/dev/null || warn "dovecot is not enabled at boot (systemctl enable dovecot)"

# ---------------------------------------------------------------- auth backend audit
say ""; say "== Auth backend audit (read only) =="
doveconf -n | awk '/^(passdb|userdb)[ {]/{b=1} b{print "    " $0} /^}/{b=0}'
drivers=$(doveconf -n | awk '/^(passdb|userdb)[ {]/{b=1} b&&$1=="driver"{print $3} /^}/{b=0}' | sort -u | tr '\n' ' ')
info "auth drivers in use: ${drivers:-none found}"
info "auth_username_format='$(doveconf -h auth_username_format)' auth_mechanisms='$(doveconf -h auth_mechanisms)' (NOT modified)"
for d in $drivers; do
  case "$d" in
    pam)
      if [ -f /etc/pam.d/dovecot ]; then info "PAM service file /etc/pam.d/dovecot present"
      else warn "no /etc/pam.d/dovecot: PAM falls back to 'other' stack"; fi
      if grep -Eqs '^auth[[:space:]]+(sufficient|\[success=[^]]*\])[[:space:]]+pam_permit' /etc/pam.d/dovecot /etc/pam.d/common-auth; then
        warn "PAM auth stack has a 'sufficient pam_permit' line: ANY password may be accepted"
      fi
      if systemctl is-active --quiet sssd 2>/dev/null; then info "sssd active"
      elif systemctl is-active --quiet winbind 2>/dev/null; then info "winbind active"
      else warn "PAM in use but neither sssd nor winbind active: AD logins will fail"; fi
      info "passwd entries visible to NSS: $(getent passwd 2>/dev/null | wc -l) (AD users may not enumerate; test: id <aduser>)"
      ;;
    ldap)
      info "LDAP passdb; config: $(doveconf -n | grep -E 'args *=.*ldap' | head -1)"
      ;;
  esac
done
bad=$(doveconf -n | grep -nE 'nopassword|allow_all_users|auth_master_user_separator|driver = static|driver = passwd-file|result_success')
if [ -n "$bad" ]; then warn "auth config lines worth reviewing (possible backdoor/bypass):"; printf '%s\n' "$bad" | sed 's/^/    /'; fi
if doveconf -n | grep -qE 'script-login|mail_executable|login_executable|sieve_(pipe|filter|execute)_bin_dir'; then
  warn "script-login / executable / sieve pipe settings present (command execution path):"
  doveconf -n | grep -E 'script-login|mail_executable|login_executable|sieve_(pipe|filter|execute)_bin_dir' | sed 's/^/    /'
fi
lt=$(doveconf -h login_trusted_networks 2>/dev/null)
[ -n "$lt" ] && warn "login_trusted_networks='$lt' (hosts here can forward client IP / bypass checks); left unchanged"
fu=$(doveconf -h first_valid_uid 2>/dev/null)
[ "$fu" = 0 ] && warn "first_valid_uid=0: uid 0 can log in over IMAP/POP3"
sv=$(find /home /var/lib/dovecot /etc/dovecot -maxdepth 5 \( -name '*.sieve' -o -name '.dovecot.sieve' \) 2>/dev/null)
if [ -n "$sv" ]; then
  for f in $sv; do
    grep -qE 'pipe|execute|filter|redirect|vnd\.dovecot' "$f" 2>/dev/null && warn "sieve script with pipe/execute/redirect: $f"
  done
fi
dpkg -V dovecot-core dovecot-imapd dovecot-pop3d >"$TMP/dpkgv.txt" 2>/dev/null
grep -v ' c /' "$TMP/dpkgv.txt" >"$TMP/dpkgv2.txt"
if [ -s "$TMP/dpkgv2.txt" ]; then warn "dovecot package files modified vs dpkg:"; sed 's/^/    /' "$TMP/dpkgv2.txt"; fi
audit_listeners
warn "REMINDER: Red Team can spray AD usernames over IMAP/POP3 and lock scored accounts. Know the AD lockout threshold and how to unlock fast (ask the AD person)"

# ---------------------------------------------------------------- build drop-in
say ""; say "== Building $DROP =="

# 1. protocols: keep imap, pop3 (+lmtp if used); drop everything else
cur=$(doveconf -h protocols)
des=""
for p in imap pop3; do
  if has "$cur" "$p" || [ -x "/usr/lib/dovecot/$p" ]; then des="$des $p"; fi
done
has "$cur" lmtp && des="$des lmtp"
des=${des# }
for p in $cur; do
  case "$p" in imap|pop3|lmtp) ;; *) warn "dropping unused protocol '$p' from protocols";; esac
done
if [ -n "$des" ] && [ "$cur" != "$des" ]; then
  want protocols "$des"
  NEED_RESTART=1
else
  info "protocols already '$cur'"
fi

# 2. TLS
cf=$(doveconf -h ssl_cert 2>/dev/null); cf=${cf#<}
kf=$(doveconf -hP ssl_key 2>/dev/null); kf=${kf#<}
certok=0
[ -n "$cf" ] && [ -r "$cf" ] && certok=1
[ -n "$kf" ] && [ ! -r "$kf" ] && certok=0
info "ssl_cert=$cf ssl_key=${kf:-?} readable=$certok"
case "$cf" in *snakeoil*|*dovecot.pem) info "self-signed default cert in use (fine for scoring; replace only if time allows)";; esac
sslcur=$(doveconf -h ssl 2>/dev/null)
if [ "$certok" = 1 ]; then
  target=""
  [ "$sslcur" = no ] && target=yes
  [ "$ENFORCE_TLS" = 2 ] && target=required
  [ -n "$target" ] && want ssl "$target"
  mp=$(doveconf -h ssl_min_protocol 2>/dev/null)
  if have_setting ssl_min_protocol; then
    case "$mp" in TLSv1.2|TLSv1.3) info "ssl_min_protocol already $mp";; *) want ssl_min_protocol TLSv1.2;; esac
  else
    want ssl_protocols '!SSLv2 !SSLv3 !TLSv1 !TLSv1.1'
  fi
  want ssl_prefer_server_ciphers yes
else
  warn "no readable ssl_cert/ssl_key: NOT touching any TLS setting (setting ssl=yes with a missing cert would stop Dovecot)"
fi
if [ "$ENFORCE_TLS" -ge 1 ] 2>/dev/null; then
  want disable_plaintext_auth yes
  warn "ENFORCE_TLS=$ENFORCE_TLS: plaintext logins on 110/143 now need TLS (localhost exempt). Verify the scorer on Quotient for 2-3 cycles"
else
  [ "$(doveconf -h disable_plaintext_auth)" = yes ] || warn "disable_plaintext_auth=no: plaintext passwords accepted on 110/143. Enable with ENFORCE_TLS=1 once the scorer is confirmed TLS-capable"
fi

# 3. auth hygiene
am=$(doveconf -h auth_mechanisms); badm=0
for m in $am; do case "$m" in plain|login) ;; *) badm=1;; esac; done
[ "$badm" = 1 ] && want auth_mechanisms 'plain login'
want auth_debug no
want auth_debug_passwords no
want auth_verbose_passwords no
want auth_verbose yes
want mail_debug no
want verbose_ssl no

# 4. connection limits: only lower an absurdly high per-user value (default 10 is fine)
mu=$(doveconf -h mail_max_userip_connections 2>/dev/null)
if [ "${mu:-0}" -gt 50 ] 2>/dev/null; then want mail_max_userip_connections 20
else info "mail_max_userip_connections=$mu (ok; login process limits left at defaults, they are sane unless raised)"; fi

# 5. world-accessible Postfix<->Dovecot sockets (e.g. community guide's mode 0666)
sock_fix() { # path service-name
  s=$1
  [ -S "$s" ] || return 0
  perm=$(ls -ld "$s" | cut -c1-10)
  oth=$(printf '%s' "$perm" | cut -c8-10)
  if [ "$oth" != "---" ]; then
    warn "$s is accessible to 'other' ($perm); restricting to postfix:postfix 0660"
    cat >>"$CONF" <<EOT
service $2 {
  unix_listener $s {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOT
    ITEMS=$((ITEMS+1))
  else
    info "$s perms ok ($perm)"
  fi
}
sock_fix /var/spool/postfix/private/auth auth
sock_fix /var/spool/postfix/private/dovecot-lmtp lmtp
for s in /run/dovecot/auth-master; do
  if [ -S "$s" ]; then
    o=$(ls -ld "$s" | cut -c8-10)
    [ "$o" != "---" ] && warn "$s is accessible to other users ($o); review service auth { unix_listener auth-master }"
  fi
done

# ---------------------------------------------------------------- install + validate
say ""; say "== Validate and reload =="
if [ -s "$CONF" ]; then
  { printf '# Managed by harden-dovecot.sh (%s). Remove this file to undo.\n' "$TS"; cat "$CONF"; } >"$DROP"
  chmod 644 "$DROP"
  info "wrote $DROP"
else
  info "nothing to change in config"
fi
if ! doveconf -n >/dev/null 2>"$TMP/post.txt"; then
  warn "doveconf -n FAILED with the drop-in:"
  sed 's/^/    /' "$TMP/post.txt"
  rm -f "$DROP"
  warn "drop-in removed; config unchanged"
  finish 1
fi
ok "doveconf -n parses cleanly"

# effective-value check (catches overrides from later includes such as local.conf)
while IFS='=' read -r n v; do
  [ -n "$n" ] || continue
  e=$(doveconf -h "$n" 2>/dev/null)
  if [ "$e" = "$v" ]; then ok "effective $n = $e"
  else warn "effective $n = '$e', wanted '$v' (overridden later, e.g. conf.d/*.conf after 99 or local.conf)"; fi
done <"$WANT"

if [ -s "$CONF" ]; then
  reload_dovecot
  sleep 2
  if ! systemctl is-active --quiet dovecot 2>/dev/null; then
    warn "dovecot not active after reload"
    rollback; sleep 2; finish 1
  fi
  fp=$(doveconf -h protocols)
  fail=0
  if has "$fp" imap; then
    listening 143 || { warn "143 not listening"; fail=1; }
    listening 993 || warn "993 not listening (ssl disabled or no cert?)"
  fi
  if has "$fp" pop3; then
    listening 110 || { warn "110 not listening"; fail=1; }
    listening 995 || warn "995 not listening (ssl disabled or no cert?)"
  fi
  if command -v nc >/dev/null 2>&1; then
    listening 143 && { if probe_imap 143; then ok "IMAP 143 banner ok"; else warn "IMAP 143 gave no OK banner"; fail=1; fi; }
    listening 110 && { if probe_pop3 110; then ok "POP3 110 banner ok"; else warn "POP3 110 gave no +OK banner"; fail=1; fi; }
  else
    info "nc not installed: skipped plaintext banner probes"
  fi
  if command -v openssl >/dev/null 2>&1; then
    listening 993 && { if probe_imaps 993; then ok "IMAPS 993 TLS handshake + banner ok"; else warn "IMAPS 993 TLS probe failed"; fail=1; fi; }
    listening 995 && { if probe_pop3s 995; then ok "POP3S 995 TLS handshake + banner ok"; else warn "POP3S 995 TLS probe failed"; fail=1; fi; }
  fi
  if [ "$fail" = 1 ]; then rollback; sleep 2; finish 1; fi
fi
audit_listeners

# ---------------------------------------------------------------- filesystem fixes (after service is confirmed healthy)
say ""; say "== Mail store permissions =="
mf=$(find /var/mail -maxdepth 1 -type f \( -perm -004 -o -perm -002 \) 2>/dev/null)
for f in $mf; do
  chmod o-rwx "$f" && ok "removed world access from mailbox $f"
done
md=$(find /home -maxdepth 4 -type d -name Maildir \( -perm -004 -o -perm -001 \) 2>/dev/null)
for d in $md; do
  chmod -R o-rwx "$d" && ok "removed world access from $d (recursive)"
done
[ -z "$mf$md" ] && info "no world-accessible mailboxes found"
cw=$(find /etc/dovecot -type f -perm -004 2>/dev/null | while read -r f; do grep -lE '^[[:space:]]*(dnpass|password|pass)[[:space:]]*=' "$f" 2>/dev/null; done)
[ -n "$cw" ] && warn "world-readable Dovecot config files containing credentials (chmod 640, group dovecot, after checking nothing breaks): $cw"

say ""
say "Next: test AD logins exactly as the scorer does (prompts for password):"
say "    doveadm auth test <aduser>"
say "    openssl s_client -connect localhost:993 -quiet   (then: a1 LOGIN <aduser> <pw>)"
say "Find sprayers:  grep -E 'auth failed|Aborted login' /var/log/mail.log | grep -oE 'rip=[0-9.]+' | sort | uniq -c | sort -rn | head"
say "Undo hardening only:                     rm -f $DROP && systemctl reload dovecot"
say "Restore SERVICE only (dovecot config):   tar xzf $BK -C / etc/dovecot && doveconf -n >/dev/null && systemctl restart dovecot"
say "Restore TLS certs if damaged:            tar xzf $BK -C / etc/ssl"
say "Restore AUTH only (PAM/SSSD/krb5):       tar xzf $BKA -C / && systemctl restart sssd dovecot"
say "Packages broken/replaced?                apt install --reinstall dovecot-core dovecot-imapd dovecot-pop3d; dpkg -V dovecot-core"
finish 0
