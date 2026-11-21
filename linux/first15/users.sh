#!/bin/sh
# status: draft
# risk: lockout
# os: Linux with local passwd/shadow and validated sudo or OpenDoas
# tested: never
# Creates sysadmin, grants password-required administration, and locks all other
# local passwords and shells (including root and service accounts). May break
# jobs/services that invoke login shells. Does NOT configure SSH/PAM, revoke
# keys, block every SSH subsystem, manage directory users, or end sessions.
# Asks: action (harden/restore), run ID, new password (hidden), confirmation of
# prepare, confirmation of verified login before locking, confirmation of restore.
# CFK automation: an explicitly selected protocol on descriptor 3 replaces
# console questions. No secrets in arguments, logs, or target plaintext files.
# Do not run concurrently with other account or privilege-policy editors.
# sysadmin's login shell preference is zsh, then bash, then sh.

PATH=/run/wrappers/bin:/run/current-system/sw/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL

info() { printf '[ ] %s\n' "$*"; }
ok() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

ask() {
  REPLY=$2
  [ "$TTY_OK" = 1 ] || return 1
  printf '%s [%s]: ' "$1" "$2" >/dev/tty
  ans=''
  read -r ans </dev/tty || return 1
  [ -n "$ans" ] && REPLY=$ans
  return 0
}
tty_restore() {
  [ "$TTY_OK" = 1 ] && stty echo </dev/tty 2>/dev/null
  return 0
}
ask_secret() {
  REPLY=''
  [ "$TTY_OK" = 1 ] || return 1
  printf '%s: ' "$1" >/dev/tty
  stty -echo </dev/tty 2>/dev/null || return 1
  read -r REPLY </dev/tty
  rc=$?
  tty_restore
  printf '\n' >/dev/tty
  return "$rc"
}
confirm() {
  if ! ask "$1 (y/N)" ''; then
    warn "No console; skipped: $1"
    return 1
  fi
  case "$REPLY" in y | Y | yes | YES | Yes) return 0 ;; esac
  return 1
}
fail() {
  warn "$*"
  exit 1
}

select_comparator() {
  if have cmp; then
    FILE_COMPARE='cmp'
  elif have busybox && busybox cmp -s /dev/null /dev/null </dev/null >/dev/null 2>&1; then
    FILE_COMPARE='BusyBox cmp'
  elif have diff; then
    FILE_COMPARE='diff'
  elif have busybox && busybox diff /dev/null /dev/null </dev/null >/dev/null 2>&1; then
    FILE_COMPARE='BusyBox diff'
  elif have od && have awk; then
    FILE_COMPARE='od + awk'
  else
    fail 'Install diffutils (cmp or diff), or od plus awk; cannot safely compare account files'
  fi
  if [ "$FILE_COMPARE" != cmp ]; then
    warn "Standalone cmp unavailable; using $FILE_COMPARE. Install diffutils for standalone cmp"
  fi
}

files_equal() {
  case "$FILE_COMPARE" in
    cmp) cmp -s "$1" "$2" >/dev/null 2>&1 ;;
    'BusyBox cmp') busybox cmp -s "$1" "$2" >/dev/null 2>&1 ;;
    diff) diff "$1" "$2" >/dev/null 2>&1 ;;
    'BusyBox diff') busybox diff "$1" "$2" >/dev/null 2>&1 ;;
    'od + awk')
      # POSIX byte dumps avoid checksum collisions and text-only comparison
      # pitfalls (empty files, NUL bytes, and missing final newlines). Explicit
      # error records propagate either od failure without needing pipefail.
      {
        od -A n -v -t x1 "$1" 2>/dev/null || printf '%s\n' CCDC_COMPARE_ERROR
        printf '%s\n' CCDC_COMPARE_NEXT
        od -A n -v -t x1 "$2" 2>/dev/null || printf '%s\n' CCDC_COMPARE_ERROR
      } | awk '
        $0=="CCDC_COMPARE_ERROR" { bad=1; next }
        $0=="CCDC_COMPARE_NEXT" { second=1; next }
        !second { lines[++n]=$0; next }
        { m++; if (("x" $0)!=("x" lines[m])) bad=1 }
        END { exit (bad || n!=m) }
      '
      ;;
    *) return 1 ;;
  esac
}

hash_password() {
  if have openssl; then
    HASH=$(printf '%s\n' "$PASSWORD" | openssl passwd -6 -stdin 2>/dev/null)
    case "$HASH" in "\$6\$"*) return 0 ;; esac
  fi
  if have mkpasswd; then
    HASH=$(printf '%s\n' "$PASSWORD" | mkpasswd -m sha-512 -s 2>/dev/null)
    case "$HASH" in "\$6\$"*) return 0 ;; esac
    HASH=$(printf '%s\n' "$PASSWORD" | mkpasswd -P 0 -m sha512 2>/dev/null)
    case "$HASH" in "\$6\$"*) return 0 ;; esac
  fi
  if have busybox; then
    HASH=$(printf '%s\n' "$PASSWORD" | busybox mkpasswd -P 0 -m sha512 2>/dev/null)
    case "$HASH" in "\$6\$"*) return 0 ;; esac
  fi
  return 1
}

private_directory() {
  [ ! -L "$1" ] || fail "Refusing symlink directory: $1"
  if [ ! -d "$1" ]; then mkdir -m 700 "$1" || fail "Cannot create $1"; fi
  # Only fixed, validated backup paths reach this; numeric ls works on old Linux.
  # shellcheck disable=SC2012
  ls -ldn "$1" | awk '$3 != 0 || substr($1, 5, 6) != "------" { bad=1 } END { exit bad }' || fail "Not a private root-owned directory: $1"
}

account_files() {
  FILES='passwd shadow group'
  [ ! -e /etc/gshadow ] || FILES="$FILES gshadow"
}

validate_databases() {
  awk -F: 'NF != 7 || $1 == "" || seen[$1]++ || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ { bad=1 } END { exit (bad || NR==0) }' "$1/passwd" || return 1
  awk -F: 'NF != 9 || $1 == "" || seen[$1]++ { bad=1 } END { exit (bad || NR==0) }' "$1/shadow" || return 1
  awk -F: 'NF != 4 || $1 == "" || seen[$1]++ || $3 !~ /^[0-9]+$/ { bad=1 } END { exit (bad || NR==0) }' "$1/group" || return 1
  if [ -f "$1/gshadow" ]; then
    awk -F: 'NF != 4 || $1 == "" || seen[$1]++ { bad=1 } END { exit bad }' "$1/gshadow" || return 1
  fi
  # Every local account must have exactly one shadow entry, and vice versa.
  awk -F: 'NR==FNR { p[$1]=1; next } { if (!($1 in p)) bad=1; delete p[$1] } END { for (u in p) bad=1; exit bad }' "$1/passwd" "$1/shadow"
}

find_login_shell() {
  for preferred_shell in zsh bash sh; do
    if [ -r /etc/shells ]; then
      # Use registered paths, including shells outside the usual bin folders.
      while read -r shell_path _ || [ -n "$shell_path" ]; do
        case "$shell_path" in
          /*/"$preferred_shell") ;;
          *) continue ;;
        esac
        case "$shell_path" in *:*) continue ;; esac
        if [ -f "$shell_path" ] && [ -x "$shell_path" ]; then
          printf '%s\n' "$shell_path"
          return 0
        fi
      done </etc/shells
    else
      # Minimal systems may not have /etc/shells at all.
      for shell_path in "$(command -v "$preferred_shell" 2>/dev/null || :)" \
        "/bin/$preferred_shell" "/usr/bin/$preferred_shell" "/usr/local/bin/$preferred_shell"; do
        case "$shell_path" in /*) ;; *) continue ;; esac
        case "$shell_path" in *:*) continue ;; esac
        if [ -f "$shell_path" ] && [ -x "$shell_path" ]; then
          printf '%s\n' "$shell_path"
          return 0
        fi
      done
    fi
  done
  return 1
}

preflight() {
  for tool in awk cat chmod chown cp date grep id ls mkdir mv rm rmdir; do
    have "$tool" || fail "Install $tool; no account changes made"
  done
  account_files
  for name in $FILES; do
    [ -f "/etc/$name" ] && [ ! -L "/etc/$name" ] && [ -w "/etc/$name" ] || fail "Need a regular writable /etc/$name"
  done
  for name in passwd shadow group gshadow; do
    if [ -e "/etc/$name.lock" ] || [ -L "/etc/$name.lock" ]; then
      lock_pid=$(cat "/etc/$name.lock" 2>/dev/null)
      if [ -n "$lock_pid" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
        warn "Removing stale lock /etc/$name.lock (pid $lock_pid is gone)"
        rm -f "/etc/$name.lock"
      else
        fail "Account editor lock exists: /etc/$name.lock"
      fi
    fi
  done
  if [ -e "$BASE" ] || [ -L "$BASE" ]; then
    private_directory "$BASE"
    if [ -e "$BASE/active" ] || [ -L "$BASE/active" ]; then
      lock_pid=$(cat "$BASE/active/pid" 2>/dev/null)
      if [ -n "$lock_pid" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
        warn "Removing stale lock $BASE/active (pid $lock_pid is gone)"
        rm -f "$BASE/active/pid"
        rmdir "$BASE/active" || fail "Cannot remove stale lock $BASE/active"
      else
        fail "Another run is active (or stale lock at $BASE/active)"
      fi
    fi
  fi
  validate_databases /etc || fail 'Malformed, duplicate, or unmatched local account records; no changes made'
  awk -F: '$1=="root" && $3==0 { found++ } END { exit (found!=1) }' /etc/passwd || fail 'Need a conventional local root account for sudo/doas'
  [ -d /var/lib ] && [ ! -L /var/lib ] && [ -w /var/lib ] || fail 'Need a real writable /var/lib for protected backups'
  count=$(awk -F: '$1=="sysadmin" { n++ } END { print n+0 }' /etc/passwd)
  if [ "$count" = 1 ]; then
    uid=$(awk -F: '$1=="sysadmin" { print $3 }' /etc/passwd)
    [ "$uid" -ne 0 ] || fail 'Existing sysadmin has UID 0; refusing to repurpose it'
    awk -F: -v uid="$uid" '$3==uid && $1!="sysadmin" { bad=1 } END { exit bad }' /etc/passwd || fail 'sysadmin shares its UID with another local account'
  elif id sysadmin >/dev/null 2>&1; then
    fail 'sysadmin exists outside the local passwd database'
  else
    [ -d /home ] && [ ! -L /home ] || fail 'Need a real /home directory to create sysadmin'
    [ ! -e /home/sysadmin ] && [ ! -L /home/sysadmin ] || fail '/home/sysadmin already exists without a local sysadmin account'
  fi
  LOGIN_SHELL=$(find_login_shell) || fail 'No usable login shell; install/register zsh, bash or sh'
  info "sysadmin login shell: $LOGIN_SHELL (preference: zsh, bash, sh)"
  NOLOGIN=''
  for candidate in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin /bin/false /usr/bin/false; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then NOLOGIN=$candidate; break; fi
  done
  [ -n "$NOLOGIN" ] || fail 'Install nologin or false; no account changes made'
  ADMIN=''
  if have sudo && have visudo && [ -f /etc/sudoers ] && [ ! -L /etc/sudoers ]; then
    ADMIN=sudo
    POLICY=sudoers
    visudo -c -f /etc/sudoers </dev/null >/dev/null 2>&1 || fail 'Existing sudo configuration is invalid'
  elif have doas; then
    ADMIN=doas
    POLICY=doas.conf
    [ ! -L /etc/doas.conf ] || fail 'Refusing symlink /etc/doas.conf'
    if [ -e /etc/doas.conf ]; then
      [ -f /etc/doas.conf ] || fail 'Not a regular /etc/doas.conf'
      # shellcheck disable=SC2012
      ls -ln /etc/doas.conf | awk '$3!=0 || substr($1,6,1)=="w" || substr($1,9,1)=="w" { bad=1 } END { exit bad }' || fail 'doas.conf must be root-owned and not group/other writable'
      doas -C /etc/doas.conf </dev/null >/dev/null 2>&1 || fail 'Need OpenDoas with working -C validation'
    else
      doas -C /dev/null </dev/null >/dev/null 2>&1 || fail 'Need OpenDoas with working -C validation'
    fi
  else
    fail 'Install sudo plus visudo, or OpenDoas with -C validation; no changes made'
  fi
  if [ -e /sys/fs/selinux/enforce ]; then
    have chcon || fail 'Install chcon to preserve SELinux labels'
    [ -f "/etc/$POLICY" ] || fail 'Create and label the privilege-policy file before using this script on SELinux'
    if [ "$count" = 0 ]; then have restorecon || fail 'Install restorecon to label the new home directory'; fi
  fi
  saved_password=$PASSWORD
  PASSWORD=preflight-only
  hash_password || fail 'Install openssl with SHA-512 crypt, or mkpasswd; no changes made'
  PASSWORD=$saved_password
  unset saved_password HASH
  epoch=$(date +%s 2>/dev/null) || fail 'Need date with epoch-seconds support'
  case "$epoch" in '' | *[!0-9]*) fail 'Need date with epoch-seconds support' ;; esac
  DAY=$((epoch / 86400))
  info "Administrator policy: $ADMIN; disabled shell: $NOLOGIN"
}

take_locks() {
  private_directory "$BASE"
  mkdir -m 700 "$BASE/active" 2>/dev/null || fail "Another run is active (or stale lock at $BASE/active); inspect before removing it"
  printf '%s\n' "$$" >"$BASE/active/pid" || fail "Cannot write lock PID"
  LOCKED=1
  for name in passwd shadow group gshadow; do
    if (set -C; printf '%s\n' "$$" >"/etc/$name.lock") 2>/dev/null; then
      LOCKFILES="$LOCKFILES /etc/$name.lock"
    else
      fail "Account editor lock exists: /etc/$name.lock; no changes made"
    fi
  done
}

policy_valid() {
  if [ "$ADMIN" = sudo ]; then
    visudo -c -f "$1" </dev/null >/dev/null 2>&1
  else
    doas -C "$1" </dev/null >/dev/null 2>&1
  fi
}

load_run() {
  [ -d "$RUN" ] && [ ! -L "$RUN" ] || fail "No backup at $RUN"
  for dir in original expected work; do
    [ -d "$RUN/$dir" ] && [ ! -L "$RUN/$dir" ] || fail "Incomplete backup: $RUN/$dir"
    private_directory "$RUN/$dir"
  done
  private_directory "$RUN"
  [ -f "$RUN/admin" ] && [ ! -L "$RUN/admin" ] || fail 'Invalid backup metadata'
  ADMIN=$(cat "$RUN/admin") || fail 'Cannot read backup metadata'
  case "$ADMIN" in sudo) POLICY=sudoers ;; doas) POLICY=doas.conf ;; *) fail 'Invalid admin metadata' ;; esac
  FILES='passwd shadow group'
  [ ! -f "$RUN/original/gshadow" ] || FILES="$FILES gshadow"
  NAMES="$FILES $POLICY"
  for name in $FILES; do
    [ -f "$RUN/original/$name" ] && [ ! -L "$RUN/original/$name" ] || fail "Missing original $name"
  done
}

# Copy on the destination filesystem, preserve metadata and SELinux context,
# then rename. The protected source snapshot is never consumed.
replace_file() {
  src=$1
  dest=$2
  stage="/etc/.ccdc-users-$$"
  mkdir -m 700 "$stage" || return 1
  STAGE=$stage
  cp -p "$src" "$stage/replacement" || return 1
  if [ -e /sys/fs/selinux/enforce ]; then
    chcon --reference="$dest" "$stage/replacement" || return 1
  fi
  mv -f "$stage/replacement" "$dest" || return 1
  rmdir "$stage" || return 1
  STAGE=''
}

clear_stage() {
  if [ -n "$STAGE" ]; then
    rm -f "$STAGE/replacement"
    rmdir "$STAGE" 2>/dev/null
    STAGE=''
  fi
}

matches_snapshot() {
  snap=$1
  item=$2
  if [ -f "$snap/$item.absent" ]; then
    [ ! -e "/etc/$item" ] && [ ! -L "/etc/$item" ]
  else
    [ -f "/etc/$item" ] && [ ! -L "/etc/$item" ] && files_equal "/etc/$item" "$snap/$item"
  fi
}

restore_original() {
  # Check ALL files before restoring ANY; never discard later unrelated edits.
  for name in $NAMES; do
    if ! matches_snapshot "$RUN/expected" "$name" && ! matches_snapshot "$RUN/work" "$name" && ! matches_snapshot "$RUN/original" "$name"; then
      warn "Concurrent edit detected in /etc/$name; restore refused. Compare with $RUN/original manually"
      return 1
    fi
  done
  validate_databases "$RUN/original" || return 1
  if [ -f "$RUN/original/$POLICY" ]; then policy_valid "$RUN/original/$POLICY" || return 1; fi
  for name in $NAMES; do
    if [ -f "$RUN/original/$name.absent" ]; then
      if [ -e "/etc/$name" ]; then
        mv "/etc/$name" "$RUN/removed-$name-$$" || return 1
      fi
    else
      replace_file "$RUN/original/$name" "/etc/$name" || return 1
      files_equal "$RUN/original/$name" "/etc/$name" || return 1
    fi
  done
  printf '%s\n' restored >"$RUN/state" || return 1
  ok "Restored old password hashes, shells, account databases and $POLICY from $RUN"
  info 'Any home directory created for sysadmin is retained; no user files were deleted'
}

install_work() {
  validate_databases "$RUN/work" || fail 'Candidate account databases failed validation'
  policy_valid "$RUN/work/$POLICY" || fail 'Candidate administrator policy failed validation'
  for name in $NAMES; do
    matches_snapshot "$RUN/expected" "$name" || fail "Concurrent edit to /etc/$name; refusing installation"
  done
  DIRTY=1
  printf '%s\n' changing >"$RUN/state" || fail 'Cannot record transaction state'
  for name in $NAMES; do
    matches_snapshot "$RUN/expected" "$name" || fail "Concurrent edit to /etc/$name during installation"
    replace_file "$RUN/work/$name" "/etc/$name" || fail "Installing /etc/$name failed"
    files_equal "$RUN/work/$name" "/etc/$name" || fail "Installed /etc/$name differs from candidate"
  done
  validate_databases /etc || fail 'Installed account databases failed validation'
  policy_valid "/etc/$POLICY" || fail 'Installed administrator policy failed validation'
  for name in $NAMES; do
    cp -p "/etc/$name" "$RUN/expected/$name" || fail 'Cannot record installed state'
    if [ -f "$RUN/expected/$name.absent" ]; then rm -f "$RUN/expected/$name.absent"; fi
  done
}

next_id() {
  next=$(awk -F: '{ used[$3]=1 } END { for (n=1000; n<60000; n++) if (!(n in used)) { print n; exit } exit 1 }' "/etc/$1") || return 1
  while [ "$next" -lt 60000 ]; do
    if awk -F: -v n="$next" '$3==n { found=1 } END { exit !found }' "/etc/$1"; then
      next=$((next + 1))
      continue
    fi
    if ! have getent || ! getent "$1" "$next" >/dev/null 2>&1; then printf '%s\n' "$next"; return 0; fi
    next=$((next + 1))
  done
  return 1
}

prepare() {
  preflight
  take_locks
  [ ! -e "$RUN" ] && [ ! -L "$RUN" ] || fail 'Run ID already exists; use a new run ID'
  mkdir -m 700 "$RUN" "$RUN/original" "$RUN/expected" "$RUN/work" || fail 'Cannot create backup directories'
  NAMES="$FILES $POLICY"
  printf '%s\n' "$ADMIN" >"$RUN/admin" || fail 'Cannot write backup metadata'
  for name in $NAMES; do
    if [ -f "/etc/$name" ]; then
      cp -p "/etc/$name" "$RUN/original/$name" || fail "Backup failed: $name"
      cp -p "/etc/$name" "$RUN/expected/$name" || fail "Snapshot failed: $name"
      cp -p "/etc/$name" "$RUN/work/$name" || fail "Candidate copy failed: $name"
    else
      : >"$RUN/original/$name.absent" || fail 'Backup failed'
      : >"$RUN/expected/$name.absent" || fail 'Snapshot failed'
      : >"$RUN/work/$name" || fail 'Candidate creation failed'
    fi
  done
  # Detect an editor that ignored the locks while the snapshots were copied.
  for name in $NAMES; do
    if ! matches_snapshot "$RUN/original" "$name" || ! matches_snapshot "$RUN/expected" "$name"; then
      fail "Concurrent edit while backing up /etc/$name"
    fi
  done
  hash_password || fail 'Password hashing failed'
  uid=$(awk -F: '$1=="sysadmin" { print $3 }' /etc/passwd)
  NEW_HOME=0
  if [ -z "$uid" ]; then
    uid=$(next_id passwd) || fail 'No available local UID'
    gid=$(awk -F: '$1=="sysadmin" { print $3 }' /etc/group)
    if [ -z "$gid" ]; then
      if have getent && getent group sysadmin >/dev/null 2>&1; then fail 'sysadmin group exists outside local group database'; fi
      gid=$(next_id group) || fail 'No available local GID'
      printf 'sysadmin:x:%s:\n' "$gid" >>"$RUN/work/group" || fail 'Cannot build group candidate'
      if [ -f "$RUN/work/gshadow" ]; then printf 'sysadmin:!::\n' >>"$RUN/work/gshadow" || fail 'Cannot build gshadow candidate'; fi
    fi
    [ "$gid" -ne 0 ] || fail 'Refusing root group as sysadmin primary group'
    printf 'sysadmin:x:%s:%s:System administrator:/home/sysadmin:%s\n' "$uid" "$gid" "$LOGIN_SHELL" >>"$RUN/work/passwd" || fail 'Cannot build passwd candidate'
    printf 'sysadmin:%s:%s:0:99999:7:::\n' "$HASH" "$DAY" >>"$RUN/work/shadow" || fail 'Cannot build shadow candidate'
    NEW_HOME=1
  else
    awk -F: -v shell="$LOGIN_SHELL" 'BEGIN { OFS=":" } $1=="sysadmin" { $2="x"; $7=shell } { print }' /etc/passwd >"$RUN/passwd.data" || fail 'Cannot build passwd candidate'
    cat "$RUN/passwd.data" >"$RUN/work/passwd" || fail 'Cannot write passwd candidate'
    # Pass only the HASH (not plaintext) to awk via its environment, not argv.
    CCDC_HASH=$HASH awk -F: -v day="$DAY" 'BEGIN { OFS=":" } $1=="sysadmin" { $2=ENVIRON["CCDC_HASH"]; $3=day; $4=0; $5=99999; $6=7; $7=""; $8=""; $9="" } { print }' /etc/shadow >"$RUN/shadow.data" || fail 'Cannot build shadow candidate'
    cat "$RUN/shadow.data" >"$RUN/work/shadow" || fail 'Cannot write shadow candidate'
  fi
  unset HASH PASSWORD
  if [ "$ADMIN" = sudo ]; then
    printf '\n# CCDC sysadmin policy (restore using the associated run backup)\nDefaults:sysadmin authenticate, timestamp_timeout=0, !rootpw, !targetpw, !runaspw\nsysadmin ALL = (ALL) PASSWD: ALL\n' >>"$RUN/work/$POLICY" || fail 'Cannot build sudo policy'
    chmod 440 "$RUN/work/$POLICY" || fail 'Cannot protect sudo policy'
  else
    printf '\n# CCDC sysadmin policy; last matching rule wins, no nopass or persist\npermit sysadmin as root\n' >>"$RUN/work/$POLICY" || fail 'Cannot build doas policy'
    # OpenDoas -C runs as the caller; sysadmin must be able to read this policy
    # for the noninteractive policy check. It contains no credentials.
    chmod 644 "$RUN/work/$POLICY" || fail 'Cannot protect doas policy'
  fi
  install_work
  if [ "$NEW_HOME" = 1 ]; then
    mkdir -m 700 /home/sysadmin || fail 'Cannot create home; restoring original accounts'
    chown "$uid:$gid" /home/sysadmin || fail 'Cannot set home ownership; restoring original accounts'
    if [ -e /sys/fs/selinux/enforce ]; then
      restorecon /home/sysadmin </dev/null || fail 'Cannot label new home; restoring original accounts'
    fi
  fi
  [ "$(id -u sysadmin 2>/dev/null)" = "$uid" ] || fail 'Effective sysadmin UID does not match local configuration'
  [ "$(awk -F: '$1=="sysadmin" { print $7 }' /etc/passwd)" = "$LOGIN_SHELL" ] || fail 'Installed sysadmin shell does not match selected login shell'
  printf '%s\n' prepared >"$RUN/state" || fail 'Cannot record prepared state'
  DIRTY=0
  ok "sysadmin prepared; shell: $LOGIN_SHELL; backup: $RUN"
  info "Console undo: run user-hardening.sh as root, choose restore, and enter $RUN_ID"
}

lock_others() {
  take_locks
  load_run
  [ "$(cat "$RUN/state")" = prepared ] || fail 'Run must be prepared and its sysadmin login verified first'
  NOLOGIN=''
  for candidate in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin /bin/false /usr/bin/false; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then NOLOGIN=$candidate; break; fi
  done
  [ -n "$NOLOGIN" ] || fail 'No nologin/false executable'
  for name in $NAMES; do cp -p "$RUN/expected/$name" "$RUN/work/$name" || fail 'Cannot copy prepared snapshot'; done
  awk -F: -v shell="$NOLOGIN" 'BEGIN { OFS=":" } $1!="sysadmin" { $2="x"; $7=shell } { print }' "$RUN/expected/passwd" >"$RUN/passwd.data" || fail 'Cannot build disabled shells'
  cat "$RUN/passwd.data" >"$RUN/work/passwd" || fail 'Cannot write disabled shells'
  awk -F: 'BEGIN { OFS=":" } $1!="sysadmin" && $2 !~ /^[!*]/ { $2="!" $2 } { print }' "$RUN/expected/shadow" >"$RUN/shadow.data" || fail 'Cannot build password locks'
  cat "$RUN/shadow.data" >"$RUN/work/shadow" || fail 'Cannot write password locks'
  install_work
  awk -F: -v shell="$NOLOGIN" '$1!="sysadmin" && ($7!=shell || $2!="x") { bad=1 } END { exit bad }' /etc/passwd || fail 'Shell/shadow-routing verification failed'
  awk -F: '$1!="sysadmin" && $2 !~ /^[!*]/ { bad=1 } END { exit bad }' /etc/shadow || fail 'Password-lock verification failed'
  printf '%s\n' hardened >"$RUN/state" || fail 'Cannot record hardened state'
  DIRTY=0
  awk -F: '$1!="sysadmin" { printf "[+] Locked password and shell: %s (uid %s)\n", $1, $3 }' /etc/passwd
  warn 'SSH/PAM, alternate SSH subsystems and external identities were not changed; existing sessions remain'
}

verify_admin() {
  [ "$(id -un)" = sysadmin ] || fail 'Verification must use a fresh sysadmin login'
  if have sudo; then
    sudo -k </dev/null >/dev/null 2>&1 || fail 'Cannot invalidate sudo timestamp'
    if sudo -n /bin/sh -c 'test "$(id -u)" = 0' </dev/null >/dev/null 2>&1; then
      fail 'sysadmin can use sudo without a password; refusing to lock other accounts'
    fi
    printf '%s\n' "$PASSWORD" | sudo -S -p '' /bin/sh -c 'test "$(id -u)" = 0' >/dev/null 2>&1 || fail 'Password-authenticated sudo failed'
    ok 'Fresh sysadmin login and password-required sudo verified'
  elif have doas; then
    result=$(doas -C /etc/doas.conf /bin/sh </dev/null 2>/dev/null) || fail 'Cannot verify doas policy'
    [ "$result" = permit ] || fail 'doas must permit sysadmin with a password (no nopass/persist)'
    ok 'Fresh sysadmin login and password-required doas policy verified (not an interactive doas execution)'
  else
    fail 'No administrator tool available'
  fi
  unset PASSWORD
  printf 'CCDC_USERS_VERIFIED\n'
}

cleanup() {
  status=$?
  # An interrupted copy must not leave the staging directory blocking rollback.
  clear_stage
  if [ "$DIRTY" = 1 ]; then
    warn 'Operation failed; attempting to restore the original pre-run accounts and passwords'
    if ! restore_original; then warn "AUTOMATIC RESTORE FAILED: console recovery required from $RUN/original"; fi
  fi
  clear_stage
  for path in $LOCKFILES; do rm -f "$path"; done
  [ "$LOCKED" = 0 ] || { rm -f "$BASE/active/pid"; rmdir "$BASE/active" 2>/dev/null; }
  tty_restore
  unset PASSWORD REPLY
  printf 'SUMMARY: action=%s status=%s backup=%s\n' "$ACTION" "$status" "$RUN"
}

main() {
  set +x
  umask 077
  unset CCDC_ELEVATION_PASSWORD
  BASE=/var/lib/ccdc-user-hardening
  RUN=''
  ACTION=none
  PASSWORD=''
  DIRTY=0
  LOCKED=0
  LOCKFILES=''
  STAGE=''
  TTY_OK=0
  if (: </dev/tty >/dev/tty) 2>/dev/null; then TTY_OK=1; fi
  trap cleanup 0
  trap 'exit 1' 1 2 3 15
  if [ "${CCDC_INPUT_FD:-}" = 3 ]; then
    IFS= read -r ACTION <&3 || fail 'Missing controller action'
    IFS= read -r RUN_ID <&3 || fail 'Missing controller run ID'
    case "$ACTION" in
      prepare | verify) IFS= read -r PASSWORD <&3 || fail 'Missing password' ;;
      preflight | lock | restore) ;;
      *) fail 'Unknown controller action' ;;
    esac
  else
    if [ "$(id -u)" != 0 ]; then
      warn 'Not running as root; results may be incomplete. DRY RUN: would create sysadmin, grant admin access, and lock other local accounts; nothing changed'
      return 0
    fi
    ask 'Action: harden or restore' harden || { warn 'No console; nothing changed'; return 0; }
    ACTION=$REPLY
    ask 'Run ID (run- followed by letters, digits, underscores or hyphens)' "run-$(date '+%Y%m%d%H%M%S')" || fail 'No console'
    RUN_ID=$REPLY
  fi
  case "$RUN_ID" in run-?*) ;; *) fail 'Invalid run ID' ;; esac
  case "$RUN_ID" in *[!A-Za-z0-9_-]*) fail 'Invalid run ID' ;; esac
  [ "${#RUN_ID}" -le 80 ] || fail 'Run ID too long'
  RUN="$BASE/$RUN_ID"
  printf '\n== Local user accounts: %s ==\n' "$ACTION"
  case "$ACTION" in
    verify) [ -n "$PASSWORD" ] || fail 'Empty password'; verify_admin; return ;;
    harden | prepare | preflight | lock | restore) ;;
    *) fail 'Unknown action' ;;
  esac
  if [ "$(id -u)" != 0 ]; then
    warn 'Not root; results may be incomplete. DRY RUN: would create sysadmin, grant admin access, or restore/lock local accounts. Nothing changed'
    return 1
  fi
  select_comparator
  case "$ACTION" in
    preflight) preflight; ok 'Preflight passed; no account changes made' ;;
    prepare) [ -n "$PASSWORD" ] || fail 'Empty password'; prepare ;;
    lock) lock_others ;;
    restore)
      if [ "${CCDC_INPUT_FD:-}" != 3 ]; then
        confirm "Restore account databases, passwords, shells and admin policy from $RUN; later account edits will cause refusal" || return 0
      fi
      take_locks
      load_run
      restore_original || fail 'Restore failed; use the protected original snapshots from the console'
      ;;
    harden)
      have stty || fail 'Install stty to enter a password safely'
      ask_secret 'New sysadmin password' || fail 'Cannot read password'
      PASSWORD=$REPLY
      REPLY=''
      [ -n "$PASSWORD" ] || fail 'Empty password'
      confirm 'Create/prepare sysadmin with password-required admin access; then lock ALL other local passwords and shells, including root and service accounts' || return 0
      prepare
      info 'Before continuing, verify sysadmin login and password-required sudo/doas from another console. Current sessions are not terminated'
      if ! confirm "New sysadmin login and administration verified; now lock ALL other accounts? Backup: $RUN"; then
        warn 'Other accounts were NOT locked; sysadmin remains prepared with its new password and admin policy'
        return 0
      fi
      # prepare holds our locks; release them before the second transaction.
      for path in $LOCKFILES; do rm -f "$path"; done
      LOCKFILES=''
      rm -f "$BASE/active/pid"
      rmdir "$BASE/active" || fail 'Cannot release prepare lock'
      LOCKED=0
      lock_others
      ;;
  esac
}

( main )
