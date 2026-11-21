#!/bin/sh
# status:  wip
# risk:    service-impact
# tested:  never
#
# Box: Ubuntu 22.04 Email box (.15).
# JOB: Harden Postfix: close open relay, restrict smtpd rules, disable VRFY,
#      TLS options. Back up /etc/postfix, validate with postfix check, reload.
# WHAT MUST KEEP WORKING: SMTP delivery and relay for the local domain and AD
#      users; existing mail; ports 25, 465, 587.
# Pattern: services/systemd/harden-ssh.sh (backup, validate, reload, check the
# effective value, print the undo).
#
# Asks: nothing (non-interactive). Optional env vars, all default OFF because
#       they can break the scorer or webmail:
#   ENFORCE_TLS=1        smtpd_tls_auth_only=yes (AUTH only after STARTTLS).
#                        Breaks plaintext AUTH from the scorer or from webmail
#                        configured without TLS. Watch Quotient 2-3 cycles.
#   STRICT_MYNETWORKS=1  mynetworks = loopback only. Breaks the scorer if it
#                        relays from a network currently in mynetworks.
#
# What it does automatically:
#   - backs up /etc/postfix, sets relay/recipient hardening, disables VRFY,
#     TLS >=1.2 + opportunistic STARTTLS (never required on 25), anti-abuse
#     limits, SMTP smuggling fix, removes overly broad mynetworks entries
# What it only REPORTS (never changes): persistence/backdoor indicators
#   (bcc, aliases pipes, .forward, odd master.cf services, milters, XCLIENT).
# Rolls back automatically if postfix check fails or port 25 stops answering.

PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export PATH
set -f

ENFORCE_TLS=${ENFORCE_TLS:-0}
STRICT_MYNETWORKS=${STRICT_MYNETWORKS:-0}
TS=$(date +%Y%m%d-%H%M%S)
BAKDIR=/root/bak
BK="$BAKDIR/postfix-$TS.tar.gz"          # service: postfix + TLS certs
BKA="$BAKDIR/postfix-auth-$TS.tar.gz"    # auth: PAM/SSSD/Kerberos/NSS
ITEMS=0
WARNS=0

say()  { printf '%s\n' "$*"; }
ok()   { ITEMS=$((ITEMS+1)); say "[+] $*"; }
warn() { WARNS=$((WARNS+1)); say "[!] $*"; }
info() { say "[*] $*"; }
finish() { say "SUMMARY: items=$ITEMS warnings=$WARNS"; exit "${1:-0}"; }

if [ "$(id -u)" != 0 ]; then
  warn "Not running as root; cannot harden"
  finish 1
fi

command -v postconf >/dev/null 2>&1 || { warn "postfix/postconf not installed"; finish 1; }
TMP=$(mktemp -d 2>/dev/null) || { warn "mktemp failed"; finish 1; }
trap 'rm -rf "$TMP"' EXIT

mk_bak() { # outfile paths(relative to /)...: archive only paths that exist
  out=$1; shift; list=""
  for p in "$@"; do [ -e "/$p" ] && list="$list $p"; done
  tar czf "$out" -C / $list 2>/dev/null && chmod 600 "$out"
}

pget() { postconf -h "$1" 2>/dev/null; }
have_param() { grep -q "^$1 = " "$TMP/defaults.txt"; }
listening() { ss -H -tln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"; }

pset() { # name value : set only if different, count it
  cur=$(pget "$1")
  if [ "$cur" = "$2" ]; then info "$1 already '$2'"; return 0; fi
  if postconf -e "$1=$2" 2>/dev/null; then ok "$1: '$cur' -> '$2'"
  else warn "failed to set $1"; fi
}
pset_max() { # name value : numeric limit; skip if already stricter (non-zero and <= value)
  cur=$(pget "$1")
  if [ "${cur:-0}" -gt 0 ] 2>/dev/null && [ "$cur" -le "$2" ]; then
    info "$1 already $cur (<= $2)"; return 0
  fi
  pset "$1" "$2"
}

reload_postfix() {
  if systemctl is-active --quiet postfix 2>/dev/null; then
    systemctl reload postfix >/dev/null 2>&1 || postfix reload >/dev/null 2>&1
  else
    systemctl start postfix >/dev/null 2>&1 || postfix start >/dev/null 2>&1
  fi
}
rollback() {
  warn "ROLLING BACK /etc/postfix from $BK"
  tar xzf "$BK" -C / etc/postfix || warn "tar restore failed, restore manually"
  reload_postfix || systemctl restart postfix
}
smtp_probe() { # 0 ok, 1 no answer, 2 cannot test
  command -v nc >/dev/null 2>&1 || return 2
  printf 'EHLO harden.test\r\nQUIT\r\n' | nc -w 5 127.0.0.1 25 2>/dev/null | grep -q '^250'
}

# ---------------------------------------------------------------- preflight
say "== Preflight =="
postconf -d >"$TMP/defaults.txt" 2>/dev/null
postfix check >"$TMP/pre.txt" 2>&1; PRE_RC=$?
if [ "$PRE_RC" -ne 0 ]; then
  warn "postfix check ALREADY failing before changes (auto-rollback on check failure disabled):"
  sed 's/^/    /' "$TMP/pre.txt"
fi
mkdir -p "$BAKDIR" && chmod 700 "$BAKDIR"
if mk_bak "$BK" etc/postfix etc/aliases etc/ssl; then
  ok "service backup (postfix, aliases, ssl) -> $BK"
else
  warn "backup failed; aborting without changes"; finish 1
fi
mk_bak "$BKA" etc/pam.d etc/sssd etc/krb5.conf etc/nsswitch.conf && ok "auth backup (pam.d, sssd, krb5, nsswitch) -> $BKA" || warn "auth backup failed"
postconf -M >"$TMP/master.txt" 2>/dev/null
info "version: $(pget mail_version), myhostname=$(pget myhostname), mydestination=$(pget mydestination)"

# ---------------------------------------------------------------- relay
say ""; say "== Open relay / smtpd restrictions =="
pset smtpd_relay_restrictions 'permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'

rr=$(pget smtpd_recipient_restrictions)
case "$rr" in *check_relay_domains*) warn "smtpd_recipient_restrictions uses check_relay_domains (obsolete/unsafe): $rr";; esac
case "$rr" in *permit_mx_backup*) warn "smtpd_recipient_restrictions has permit_mx_backup (relay abuse risk): $rr";; esac
if printf '%s' "$rr" | tr ',' ' ' | tr -s ' ' '\n' | grep -qx 'permit'; then
  warn "bare 'permit' in smtpd_recipient_restrictions (rules after it are skipped): $rr"
fi
rd=$(pget relay_domains)
if [ -n "$rd" ] && [ "$rd" != '$mydestination' ]; then
  warn "relay_domains is non-default: '$rd' (we relay FOR these domains; confirm intended)"
fi

# mynetworks: remove clearly overly broad IPv4 entries (/0../15), warn on wide ones
mn=$(pget mynetworks)
info "mynetworks = $mn"
if [ "$STRICT_MYNETWORKS" = 1 ]; then
  pset mynetworks '127.0.0.0/8 [::1]/128'
else
  new=""; broad=""
  for n in $(printf '%s' "$mn" | tr ',' ' '); do
    case "$n" in
      127.*|'[::1]'*|'[::ffff:127.'*|'[') new="$new $n"; continue ;;
      '['*) new="$new $n"; continue ;;
    esac
    p=${n#*/}
    if [ "$p" = "$n" ]; then new="$new $n"; continue; fi
    case "$p" in ''|*[!0-9]*) new="$new $n"; continue ;; esac
    if [ "$p" -lt 16 ]; then broad="$broad $n"; continue; fi
    if [ "$p" -lt 24 ]; then warn "mynetworks entry $n is wide (/$p); anything in it can relay. Narrow it if the scorer does not need it"; fi
    new="$new $n"
  done
  if [ -n "$broad" ]; then
    new=${new# }
    [ -n "$new" ] || new='127.0.0.0/8 [::1]/128'
    warn "removing overly broad mynetworks entries:$broad"
    pset mynetworks "$new"
  fi
fi

# per-service overrides in master.cf that undo the global settings
postconf -P >"$TMP/svcparams.txt" 2>/dev/null
while IFS= read -r line; do
  case "$line" in
    *smtpd_relay_restrictions*)
      case "$line" in *reject*|*defer*) ;; *) warn "master.cf override weakens relay rules: $line";; esac ;;
    *mynetworks*|*receive_override_options*|*smtpd_milters*|*content_filter*)
      warn "master.cf -o override to review: $line" ;;
  esac
done <"$TMP/svcparams.txt"

# ---------------------------------------------------------------- abuse reduction
say ""; say "== Abuse reduction =="
pset disable_vrfy_command yes
pset smtpd_helo_required yes
pset smtpd_banner '$myhostname ESMTP'
pset_max smtpd_client_connection_count_limit 25
pset_max smtpd_client_connection_rate_limit 60
cur=$(pget message_size_limit)
if [ "${cur:-0}" -gt 0 ] 2>/dev/null && [ "$cur" -le 10485760 ]; then
  info "message_size_limit already $cur"
else
  pset message_size_limit 10485760
fi
sasl=$(pget smtpd_sasl_auth_enable)
if [ "$sasl" = yes ]; then
  case "$(pget smtpd_sasl_security_options)" in
    *noanonymous*) ;;
    *) pset smtpd_sasl_security_options noanonymous ;;
  esac
fi

# SMTP smuggling (CVE-2023-51764). Only on patched builds that know the parameter.
if have_param smtpd_forbid_bare_newline; then
  pset smtpd_forbid_bare_newline normalize
  pset smtpd_forbid_bare_newline_exclusions '$mynetworks'
else
  warn "smtpd_forbid_bare_newline unsupported: postfix not patched for CVE-2023-51764 (apt install --only-upgrade postfix)"
fi

# ---------------------------------------------------------------- TLS
say ""; say "== TLS (opportunistic; never required on port 25) =="
if grep -q '^smtpd_tls_protocols = .*>=' "$TMP/defaults.txt"; then
  TLSP='>=TLSv1.2'
else
  TLSP='!SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
fi
pset smtpd_tls_protocols "$TLSP"
pset smtpd_tls_mandatory_protocols "$TLSP"
pset smtp_tls_protocols "$TLSP"
pset smtp_tls_mandatory_protocols "$TLSP"
pset smtpd_tls_exclude_ciphers 'aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, SRP, DSS'
have_param tls_preempt_cipherlist && pset tls_preempt_cipherlist yes

cert=$(pget smtpd_tls_cert_file); key=$(pget smtpd_tls_key_file)
certok=0
[ -n "$cert" ] && [ -r "$cert" ] && [ -n "$key" ] && [ -r "$key" ] && certok=1
lvl=$(pget smtpd_tls_security_level)
case "$lvl" in
  may) info "smtpd_tls_security_level already may" ;;
  encrypt|dane-only) warn "smtpd_tls_security_level=$lvl forces TLS on port 25; the scorer may not support it. Left unchanged, verify Quotient" ;;
  *)
    if [ "$certok" = 1 ]; then pset smtpd_tls_security_level may
    else warn "no readable smtpd_tls_cert_file/key_file ('$cert'); STARTTLS not enabled"; fi ;;
esac
[ -z "$(pget smtp_tls_security_level)" ] && pset smtp_tls_security_level may

if [ "$ENFORCE_TLS" = 1 ]; then
  pset smtpd_tls_auth_only yes
  warn "ENFORCE_TLS=1: AUTH now requires STARTTLS. Check Quotient SMTP and webmail sending for 2-3 cycles"
else
  [ "$(pget smtpd_tls_auth_only)" = yes ] || info "smtpd_tls_auth_only=no (plaintext AUTH allowed). Run with ENFORCE_TLS=1 once the scorer is confirmed TLS-capable"
fi

# ---------------------------------------------------------------- audit (report only)
say ""; say "== Audit: persistence / backdoor indicators (report only) =="
for p in always_bcc recipient_bcc_maps sender_bcc_maps mailbox_command mailbox_command_maps \
         content_filter receive_override_options smtpd_milters non_smtpd_milters \
         smtpd_authorized_xclient_hosts smtpd_authorized_xforward_hosts smtpd_authorized_verp_clients; do
  have_param "$p" || continue
  v=$(pget "$p")
  [ -n "$v" ] && warn "$p is set: '$v'  (remove with: postconf -X $p)"
done
for p in transport_maps virtual_alias_maps virtual_mailbox_maps canonical_maps \
         sender_canonical_maps recipient_canonical_maps relocated_maps luser_relay; do
  v=$(pget "$p")
  [ -n "$v" ] || continue
  info "$p = $v"
  for m in $(printf '%s' "$v" | tr ',' ' '); do
    f=${m#*:}
    if [ -f "$f" ] && [ -r "$f" ]; then
      info "  active entries in $f:"
      grep -v '^[[:space:]]*#' "$f" | grep -v '^[[:space:]]*$' | head -15 | sed 's/^/      /'
    fi
  done
done
if [ -f /etc/aliases ]; then
  hits=$(grep -nE '^[[:space:]]*[^#[:space:]].*(\||:include:)|^[[:space:]]*[^#[:space:]][^:]*:[[:space:]]*(.*,)?[[:space:]]*/' /etc/aliases)
  if [ -n "$hits" ]; then warn "/etc/aliases has pipes, :include: or file targets:"; printf '%s\n' "$hits" | sed 's/^/    /'; fi
fi
fw=$(find /home /root /var/lib -maxdepth 4 -name .forward 2>/dev/null)
[ -n "$fw" ] && warn ".forward files present (review/remove): $fw"
ww=$(find /etc/postfix ! -type l -perm -002 2>/dev/null)
[ -n "$ww" ] && warn "world-writable files under /etc/postfix: $ww"

# master.cf: unexpected inet listeners and pipe transports
while read -r name type priv unpriv chroot wake maxp cmd rest; do
  [ -n "$name" ] || continue
  if [ "$type" = inet ]; then
    case "$name" in smtp|submission|smtps|465|587) ;; *) warn "unexpected inet service in master.cf: $name ($cmd)";; esac
  fi
  if [ "$cmd" = pipe ]; then
    case "$name" in maildrop|uucp|ifmail|bsmtp|scalemail-backend|mailman) ;; *) warn "non-default pipe transport in master.cf: $name";; esac
  fi
done <"$TMP/master.txt"

dpkg -V postfix >"$TMP/dpkgv.txt" 2>/dev/null
grep -v ' c /' "$TMP/dpkgv.txt" >"$TMP/dpkgv2.txt"
if [ -s "$TMP/dpkgv2.txt" ]; then warn "postfix package files modified vs dpkg:"; sed 's/^/    /' "$TMP/dpkgv2.txt"; fi
[ -g /usr/sbin/postdrop ] || warn "/usr/sbin/postdrop is not setgid (fix: postfix set-permissions)"
[ -g /usr/sbin/postqueue ] || warn "/usr/sbin/postqueue is not setgid (fix: postfix set-permissions)"
[ -u /usr/sbin/postdrop ] && warn "/usr/sbin/postdrop has setuid bit (unexpected)"
info "queue: $(postqueue -p 2>/dev/null | tail -1)"

# ---------------------------------------------------------------- validate + reload
say ""; say "== Validate and reload =="
postfix check >"$TMP/post.txt" 2>&1; POST_RC=$?
if [ "$POST_RC" -ne 0 ]; then
  sed 's/^/    /' "$TMP/post.txt"
  if [ "$PRE_RC" -eq 0 ]; then
    warn "postfix check FAILED after changes"
    rollback
    finish 1
  fi
  warn "postfix check still failing (was failing before too); NOT reloading"
  say "Undo (service): tar xzf $BK -C / etc/postfix && systemctl reload postfix"
  finish 1
fi
ok "postfix check passed"
reload_postfix || warn "reload command returned an error"
sleep 2

if ! listening 25; then
  warn "port 25 not listening after reload"
  rollback; sleep 2
  finish 1
fi
smtp_probe; rc=$?
case $rc in
  0) ok "local SMTP probe: EHLO answered 250" ;;
  2) info "nc not installed: skipped local SMTP probe (test with: swaks --to user@domain --server localhost)" ;;
  *) warn "SMTP did not answer EHLO on 127.0.0.1:25 after reload"; rollback; sleep 2; finish 1 ;;
esac
if command -v nc >/dev/null 2>&1; then
  v=$(printf 'VRFY root\r\nQUIT\r\n' | nc -w 5 127.0.0.1 25 2>/dev/null | grep -E '^(252|250|502|550)' | head -1)
  info "VRFY response: ${v:-none}"
fi

# ---------------------------------------------------------------- effective values
say ""; say "== Effective config =="
postconf -n | grep -E '^(smtpd_relay_restrictions|smtpd_recipient_restrictions|mynetworks|disable_vrfy_command|smtpd_helo_required|smtpd_banner|smtpd_tls_security_level|smtpd_tls_protocols|smtpd_tls_auth_only|smtpd_forbid_bare_newline)' | sed 's/^/    /'
for p in 25 465 587; do
  if listening "$p"; then ok "port $p listening"
  else
    if [ "$p" = 25 ]; then warn "port 25 not listening"
    else warn "port $p NOT listening (smtps/submission not enabled in master.cf; scored ports must keep working, verify with team)"; fi
  fi
done

say ""
say "Next: from Kali run  swaks --to victim@gmail.com --from t@yourdomain --server <public .15>  (expect 554 5.7.1 Relay access denied)"
say "Then check Quotient SMTP for 2-3 cycles before enabling ENFORCE_TLS / STRICT_MYNETWORKS."
say "Restore SERVICE only (postfix config):  tar xzf $BK -C / etc/postfix && postfix check && systemctl reload postfix"
say "Restore aliases / TLS certs if damaged:  tar xzf $BK -C / etc/aliases etc/ssl && newaliases"
say "Restore AUTH only (PAM/SSSD/krb5):       tar xzf $BKA -C / && systemctl restart sssd"
say "Restore everything:                      run the SERVICE and AUTH lines above"
say "Packages broken/replaced?                apt install --reinstall postfix; dpkg -V postfix"
finish 0
