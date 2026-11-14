#!/usr/bin/env bash
# Controller only: one entry point for local-user hardening and recovery.
# Never run this script on a target. Target code is portable POSIX sh.
set +x
set -euo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKER="$ROOT/users.sh"
CFK_PATH="$ROOT/../../../centralized_tooling/cfk/cfk.sh"
INVENTORY="${CCDC_HOSTS:-$ROOT../../../centralized_tooling/cfk/hosts.yml}"
STATE=''
PASSWORD=''
SUCCEEDED=0
FAILED=0
INVENTORY_FAILURES=0
SOURCE_INVENTORY=''
SOURCE_ENABLED=0
SOURCE_CANDIDATE=''

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}
confirm() {
  local answer=''
  if ! {
    printf '%s (y/N): ' "$1" >/dev/tty
    IFS= read -r answer </dev/tty
  } 2>/dev/null; then
    printf 'No console; nothing authorized.\n' >&2
    return 1
  fi
  [[ "$answer" == y || "$answer" == Y || "$answer" == yes ]]
}
cleanup() {
  local rc=$?
  [[ -z "$SOURCE_CANDIDATE" ]] || rm -f "$SOURCE_CANDIDATE"
  unset PASSWORD login_password
  [[ -z "$STATE" ]] || printf '\nRun records and credentials: %s\n' "$STATE"
  if ((rc != 0)); then
    printf 'Interrupted/failed: inspect journal.tsv and target backups before retrying. Do not blindly start a new run.\n' >&2
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

usage() {
  printf '%s\n' \
    'Usage: harden-users.sh [--password STRING | --password-stdin | --unique-passwords] [@lin|HOST]' \
    '       harden-users.sh --restore RUN_DIRECTORY' \
    'Without a password option, a random EFF-wordlist password is generated.' \
    '--unique-passwords generates a different Word-Word-Word27 password for each eligible host.' \
    '--password-stdin reads one line from stdin followed by EOF (safer than argv).'
}

PASSWORD_SOURCE=random
PASSWORD_MODE=shared
TARGET=@lin
TARGET_SET=0
RESTORE_DIRECTORY=''
while (($# > 0)); do
  case "$1" in
  --password)
    (($# >= 2)) || die '--password requires a value'
    [[ "$PASSWORD_SOURCE" == random ]] || die 'Specify only one password option'
    PASSWORD=$2
    PASSWORD_SOURCE=argument
    shift 2
    ;;
  --password-stdin)
    [[ "$PASSWORD_SOURCE" == random ]] || die 'Specify only one password option'
    PASSWORD_SOURCE=stdin
    shift
    ;;
  --unique-passwords)
    [[ "$PASSWORD_MODE" == shared ]] || die 'Specify --unique-passwords only once'
    PASSWORD_MODE=unique
    shift
    ;;
  --restore)
    (($# >= 2)) && [[ -n "$2" ]] || die '--restore requires a run directory'
    [[ -z "$RESTORE_DIRECTORY" ]] || die 'Specify --restore only once'
    RESTORE_DIRECTORY=$2
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  -*) die 'Unknown option; use --help for usage' ;;
  *)
    ((TARGET_SET == 0)) || die 'Specify only one target'
    TARGET=$1
    TARGET_SET=1
    shift
    ;;
  esac
done
[[ "$PASSWORD_MODE" != unique || "$PASSWORD_SOURCE" == random ]] || die '--unique-passwords cannot be combined with --password or --password-stdin'
if [[ -n "$RESTORE_DIRECTORY" ]]; then
  [[ "$PASSWORD_SOURCE" == random && "$PASSWORD_MODE" == shared && "$TARGET_SET" == 0 ]] || die '--restore cannot be combined with a target or password option'
elif [[ "$PASSWORD_SOURCE" != random ]]; then
  if [[ "$PASSWORD_SOURCE" == stdin ]]; then
    if ! IFS= read -r PASSWORD; then
      [[ -n "$PASSWORD" ]] || die 'No password received on stdin'
    fi
    extra=''
    if IFS= read -r extra || [[ -n "$extra" ]]; then
      die 'Password input must contain exactly one line followed by EOF'
    fi
    unset extra
  fi
  [[ -n "$PASSWORD" ]] || die 'Password must not be empty'
  [[ "$PASSWORD" != *$'\r'* && "$PASSWORD" != *$'\n'* ]] || die 'Password must not contain carriage returns or newlines'
  if [[ "$PASSWORD_SOURCE" == argument ]]; then
    printf 'WARNING: --password can expose the password in shell history/process listings; prefer --password-stdin.\n' >&2
  fi
fi

for tool in bash yq jq base64 ssh sshpass python3 timeout mktemp; do
  command -v "$tool" >/dev/null 2>&1 || die "Install $tool on the controller"
done
[[ -r "$WORKER" ]] || die "Missing target script: $WORKER"

journal() {
  printf '%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" >>"$STATE/journal.tsv"
}

# CFK owns SSH/inventory handling. Secrets go through fd 3, never SCRIPT_ARGS.
remote() {
  local host=$1 action=$2 inventory=$3 root=${4:-1}
  local output login_password
  output=$(mktemp "$STATE/$host-$action.XXXXXXXX.log") || return 1
  login_password=$(jq -r --arg h "$host" '.[$h].pass' "$inventory")
  {
    if [[ "$root" == 1 ]]; then printf '%s\n' "$login_password"; fi
    printf '%s\n' "$action" "$RUN_ID"
    case "$action" in prepare | verify) printf '%s\n' "$PASSWORD" ;; esac
  } | CCDC_HOSTS="$inventory" CCDC_INPUT_FD=3 CCDC_INPUT_ROOT="$root" \
    CCDC_POSIX_SH=1 CCDC_PASSWORD_ONLY=1 CCDC_SUDO=0 \
    timeout 120 bash "$CFK_PATH" "$host" "$WORKER" 3<&0 </dev/null >"$output" 2>&1
  local rc=$?
  cat "$output"
  if ((rc == 0)) && [[ "$action" == verify ]]; then
    grep -Fx 'CCDC_USERS_VERIFIED' "$output" >/dev/null || rc=1
  fi
  return "$rc"
}

set_working_user() {
  local host=$1
  jq --arg h "$host" --slurpfile passwords "$STATE/passwords.json" \
    '.[$h].user = "sysadmin" | .[$h].pass = $passwords[0][$h]' \
    "$STATE/inventory.json" >"$STATE/inventory.next"
  mv "$STATE/inventory.next" "$STATE/inventory.json"
}

password_for_host() {
  [[ -f "$STATE/passwords.json" && ! -L "$STATE/passwords.json" && -O "$STATE/passwords.json" ]] || return 1
  jq -er --arg h "$1" '.[$h] | select(type == "string" and length > 0 and (test("[\\r\\n]") | not))' "$STATE/passwords.json"
}

set_original_user() {
  local host=$1
  jq --arg h "$host" --slurpfile original "$STATE/original-inventory.json" \
    '.[$h] = $original[0][$h]' "$STATE/inventory.json" >"$STATE/inventory.next"
  mv "$STATE/inventory.next" "$STATE/inventory.json"
}

inventory_to_json() {
  if yq --version 2>&1 | grep -qi mikefarah; then
    yq -o=json '.' "$1"
  else
    yq -c '.' "$1"
  fi
}

json_to_inventory() {
  if yq --version 2>&1 | grep -qi mikefarah; then
    yq -P -o=yaml '.' "$1"
  else
    yq -y '.' "$1"
  fi
}

track_source_inventory() {
  SOURCE_INVENTORY=$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$1") || return 1
  [[ "$SOURCE_INVENTORY" != *$'\n'* && "$SOURCE_INVENTORY" != *$'\r'* ]] || return 1
  [[ -f "$SOURCE_INVENTORY" && ! -L "$SOURCE_INVENTORY" && -O "$SOURCE_INVENTORY" && -w "$SOURCE_INVENTORY" ]] || {
    printf 'Source inventory must be a writable regular file owned by you, not a symlink.\n' >&2
    return 1
  }
  printf '%s\n' "$SOURCE_INVENTORY" >"$STATE/source-inventory-path" || return 1
  cp "$SOURCE_INVENTORY" "$STATE/source-inventory.expected" || return 1
  SOURCE_ENABLED=1
}

backup_source_inventory() {
  local backup
  [[ -f "$SOURCE_INVENTORY" && ! -L "$SOURCE_INVENTORY" && -O "$SOURCE_INVENTORY" && -w "$SOURCE_INVENTORY" ]] || return 1
  python3 - "$SOURCE_INVENTORY" "$STATE/source-inventory.expected" <<'PY' || return 1
import pathlib
import sys
if pathlib.Path(sys.argv[1]).is_symlink():
    raise SystemExit("Source inventory became a symlink; refusing changes")
if pathlib.Path(sys.argv[1]).read_bytes() != pathlib.Path(sys.argv[2]).read_bytes():
    raise SystemExit("Source inventory changed unexpectedly; refusing to overwrite it")
PY
  backup=$(mktemp "${SOURCE_INVENTORY}.backup.${RUN_ID}.XXXXXXXX") || return 1
  cp "$STATE/source-inventory.expected" "$backup" || return 1
  chmod 600 "$backup" || return 1
  printf '%s\n' "$backup" >>"$STATE/source-inventory-backups" || return 1
  printf 'Source inventory backup: %s\n' "$backup"
}

write_source_inventory() {
  local host=$1 candidate
  inventory_to_json "$STATE/source-inventory.expected" >"$STATE/source-inventory.json" || return 1
  # Change credentials only, preserving every other host and field. Refuse to
  # attach credentials to an address different from the host actually changed.
  jq -e --arg h "$host" --slurpfile working "$STATE/inventory.json" '
    if has($h) and ($working[0] | has($h)) and
       (.[$h].ip == $working[0][$h].ip) and
       ((.[$h].port // 22 | tostring) == ($working[0][$h].port // 22 | tostring))
    then .[$h].user = $working[0][$h].user | .[$h].pass = $working[0][$h].pass
    else error("Inventory host/address mismatch; refusing credential update") end
  ' "$STATE/source-inventory.json" >"$STATE/source-inventory.next.json" || return 1
  candidate=$(mktemp "${SOURCE_INVENTORY}.update.XXXXXXXX") || return 1
  SOURCE_CANDIDATE=$candidate
  if ! json_to_inventory "$STATE/source-inventory.next.json" >"$candidate"; then
    rm -f "$candidate"
    SOURCE_CANDIDATE=''
    return 1
  fi
  # Validate the serializer's round trip before replacing the real inventory.
  if ! inventory_to_json "$candidate" >"$STATE/source-inventory.check.json"; then
    rm -f "$candidate"
    SOURCE_CANDIDATE=''
    return 1
  fi
  if ! python3 - "$SOURCE_INVENTORY" "$STATE/source-inventory.expected" "$candidate" \
    "$STATE/source-inventory.next.json" "$STATE/source-inventory.check.json" <<'PY'
import json
import os
import pathlib
import sys
import tempfile

source, expected, candidate, intended, parsed = map(pathlib.Path, sys.argv[1:])
if json.loads(intended.read_text()) != json.loads(parsed.read_text()):
    raise SystemExit("Inventory serialization changed values; refusing update")
data = candidate.read_bytes()
snapshot = expected.read_bytes()
next_expected = None
try:
    with tempfile.NamedTemporaryFile(dir=expected.parent, prefix="inventory-expected-", delete=False) as out:
        next_expected = pathlib.Path(out.name)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    if source.is_symlink() or source.stat().st_uid != os.geteuid() or source.read_bytes() != snapshot:
        raise SystemExit("Source inventory changed unexpectedly; update refused")
    os.chmod(candidate, 0o600)
    with candidate.open("rb+") as out:
        os.fsync(out.fileno())
    os.replace(candidate, source)
    os.replace(next_expected, expected)
    next_expected = None
finally:
    if next_expected is not None:
        next_expected.unlink()
PY
  then
    rm -f "$candidate"
    SOURCE_CANDIDATE=''
    return 1
  fi
  SOURCE_CANDIDATE=''
}

persist_source_inventory() {
  local host=$1
  [[ "$SOURCE_ENABLED" == 1 ]] || return 0
  if write_source_inventory "$host"; then
    journal "$host" SOURCE_INVENTORY_UPDATED
    printf 'Inventory updated: %s (%s)\n' "$SOURCE_INVENTORY" "$host"
  else
    INVENTORY_FAILURES=$((INVENTORY_FAILURES + 1))
    journal "$host" SOURCE_INVENTORY_UPDATE_FAILED
    printf 'WARNING: could not update source inventory for %s; use %s/inventory.json. Continuing with other hosts.\n' "$host" "$STATE" >&2
  fi
}

report_password_results() {
  # Terminal reporting contains statuses only; the password values in the
  # full report go into protected JSON, not terminal output or logs.
  python3 - "$STATE" "$PASSWORD_MODE" <<'PY'
import csv
import datetime
import json
import os
import pathlib
import sys

state = pathlib.Path(sys.argv[1])
hosts = json.loads((state / "original-inventory.json").read_text(encoding="utf-8"))
password_file = state / "passwords.json"
passwords = json.loads(password_file.read_text(encoding="utf-8")) if password_file.exists() else {}
events = {host: [] for host in hosts}
with (state / "journal.tsv").open(encoding="utf-8") as source:
    for row in csv.reader(source, delimiter="\t"):
        if len(row) == 3 and row[1] in events:
            events[row[1]].append(row[2])
failure_stages = {
    "PREPARE_FAILED_INSPECT_BACKUP": "prepare",
    "LOGIN_OR_ADMIN_VERIFICATION_FAILED": "login/admin verification",
    "LOCK_FAILED_INSPECT_BACKUP": "account locking",
    "FINAL_LOGIN_FAILED": "final verification",
}
results = []
for host in sorted(hosts):
    history = events[host]
    stage = next((failure_stages[e] for e in history if e in failure_stages), None)
    if "HARDENED_VERIFIED" in history:
        password_status, hardening, recovery = "VERIFIED", "SUCCEEDED", "NOT_NEEDED"
    elif "PREPARE_STARTED" not in history:
        password_status, recovery = "NOT_ATTEMPTED", "NOT_NEEDED"
        hardening = "SKIPPED" if "PREFLIGHT_FAILED" in history else "NOT_ATTEMPTED"
        stage = "preflight" if "PREFLIGHT_FAILED" in history else None
    elif "RESTORED" in history:
        password_status, hardening, recovery = "ROLLED_BACK", "FAILED", "RESTORED"
    else:
        password_status, hardening = "UNKNOWN", "FAILED"
        recovery = "REQUIRED_OR_NO_BACKUP" if "RECOVERY_REQUIRED_OR_NO_BACKUP" in history else "REQUIRED"
    inventory_events = [e for e in history if e.startswith("SOURCE_INVENTORY_")]
    inventory = "UNCHANGED"
    if inventory_events:
        inventory = "UPDATED" if inventory_events[-1] == "SOURCE_INVENTORY_UPDATED" else "UPDATE_FAILED"
    results.append({
        "host": host,
        "assigned_password": passwords.get(host),
        "password_status": password_status,
        "password_verified_during_run": "LOCK_STARTED" in history or "HARDENED_VERIFIED" in history,
        "hardening_status": hardening,
        "failure_stage": stage,
        "recovery_status": recovery,
        "inventory_status": inventory,
    })
report = {
    "run_id": (state / "run-id").read_text().strip(),
    "password_mode": sys.argv[2],
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "note": "Hardening-run snapshot. assigned_password is the proposed NEW password, not necessarily the current credential. ROLLED_BACK means original state was restored; UNKNOWN requires recovery. Later restores are recorded in journal.tsv.",
    "hosts": results,
}
path = state / "password-results.json"
fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as destination:
    json.dump(report, destination, indent=2)
    destination.write("\n")
    destination.flush()
    os.fsync(destination.fileno())
print("\n== Per-host password results (password values are not printed) ==")
for result in results:
    print("{host}: password={password_status} hardening={hardening_status} stage={stage} recovery={recovery_status} inventory={inventory_status}".format(
        stage=result["failure_stage"] or "-", **result))
print(f"Passwords and full status report saved privately: {path}")
PY
}

load_hosts() {
  jq -e 'type == "object" and length > 0 and all(to_entries[];
        (.key | test("^[A-Za-z0-9_][A-Za-z0-9_.-]*$")) and
        (.value.os == "lin") and
        (.value.ip | type == "string" and length > 0) and
        (.value.user | type == "string" and length > 0) and
        (.value.pass | type == "string" and length > 0 and (test("[\\r\\n]") | not)))' \
    "$STATE/inventory.json" >/dev/null || die 'Invalid selected inventory; hostnames must be simple names and passwords must be single-line'
  mapfile -t HOSTS < <(jq -r 'keys[]' "$STATE/inventory.json")
}

restore_run() {
  [[ $# == 1 ]] || die 'Usage: harden-users.sh --restore RUN_DIRECTORY'
  STATE=$(cd -- "$1" && pwd) || die 'Cannot open run directory'
  [[ ! -L "$1" && -O "$STATE" ]] || die 'Run directory must be owned by you and not a symlink'
  [[ -f "$STATE/run-id" && ! -L "$STATE/run-id" ]] || die 'Missing run ID'
  IFS= read -r RUN_ID <"$STATE/run-id"
  [[ "$RUN_ID" =~ ^run-[A-Za-z0-9_-]+$ ]] || die 'Invalid run ID'
  for file in inventory.json original-inventory.json journal.tsv; do
    [[ -f "$STATE/$file" && ! -L "$STATE/$file" && -O "$STATE/$file" ]] || die "Missing/untrusted $file"
  done
  chmod 700 "$STATE"
  chmod 600 "$STATE/inventory.json" "$STATE/original-inventory.json" "$STATE/journal.tsv"
  load_hosts
  printf 'Restore run %s on: %s\n' "$RUN_ID" "${HOSTS[*]}"
  confirm 'Restore original passwords, shells, accounts, privilege policy and source-inventory credentials? Later edits will cause refusal; created homes are retained' || return 0
  if [[ -f "$STATE/source-inventory-path" && ! -L "$STATE/source-inventory-path" ]]; then
    SOURCE_INVENTORY=$(cat "$STATE/source-inventory-path")
    if [[ ! -f "$STATE/source-inventory.expected" ]] || ! backup_source_inventory; then
      INVENTORY_FAILURES=$((INVENTORY_FAILURES + 1))
      printf 'WARNING: source inventory backup/check failed; restoring targets only. Update the source inventory manually.\n' >&2
    else
      SOURCE_ENABLED=1
    fi
  elif [[ -n "${CCDC_HOSTS:-}" ]]; then
    if track_source_inventory "$CCDC_HOSTS" && backup_source_inventory; then
      SOURCE_ENABLED=1
    else
      SOURCE_ENABLED=0
      INVENTORY_FAILURES=$((INVENTORY_FAILURES + 1))
      printf 'WARNING: cannot back up the supplied source inventory; restoring targets only.\n' >&2
    fi
  else
    SOURCE_ENABLED=0
    printf 'WARNING: no usable source-inventory tracking for this old run; only its working inventory will be updated.\n' >&2
  fi
  for host in "${HOSTS[@]}"; do
    if ! awk -F '\t' -v host="$host" '$2==host && $3=="PREPARE_STARTED" { found=1 } END { exit !found }' "$STATE/journal.tsv"; then
      printf 'SKIP: %s was never prepared by this run\n' "$host"
      continue
    fi
    # A sysadmin-ready host might still have its original login available.
    # Try the journal's working credentials, then the protected originals.
    journal "$host" RESTORE_STARTED
    if remote "$host" restore "$STATE/inventory.json" || remote "$host" restore "$STATE/original-inventory.json"; then
      set_original_user "$host"
      journal "$host" RESTORED
      SUCCEEDED=$((SUCCEEDED + 1))
      persist_source_inventory "$host"
    else
      journal "$host" RESTORE_REQUIRES_CONSOLE
      printf 'RECOVERY REQUIRED: %s; target backup /var/lib/ccdc-user-hardening/%s\n' "$host" "$RUN_ID" >&2
      FAILED=$((FAILED + 1))
    fi
  done
  printf '\nSUMMARY: restored=%d failed=%d inventory-failures=%d\n' "$SUCCEEDED" "$FAILED" "$INVENTORY_FAILURES"
  ((FAILED == 0 && INVENTORY_FAILURES == 0))
}

if [[ -n "$RESTORE_DIRECTORY" ]]; then
  restore_run "$RESTORE_DIRECTORY"
  exit $?
fi
[[ -r "$INVENTORY" ]] || die "Cannot read inventory: $INVENTORY"

# Use a private persistent directory, NOT a throwaway secret-bearing temp file.
STATE_BASE="${XDG_STATE_HOME:-$HOME/.local/state}/cfk/user-hardening"
mkdir -p "$STATE_BASE"
[[ -O "$STATE_BASE" && ! -L "$STATE_BASE" ]] || die 'Untrusted state directory'
chmod 700 "$STATE_BASE"
RUN_ID="run-$(date -u '+%Y%m%d%H%M%S')-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
STATE="$STATE_BASE/$RUN_ID"
mkdir -m 700 "$STATE"
printf '%s\n' "$RUN_ID" >"$STATE/run-id"
: >"$STATE/journal.tsv"

track_source_inventory "$INVENTORY" || die 'Cannot safely track the source inventory; no accounts changed'
inventory_json=$(inventory_to_json "$STATE/source-inventory.expected")
jq -e 'type == "object"' <<<"$inventory_json" >/dev/null || die 'Inventory must be a mapping'
jq --arg target "$TARGET" 'with_entries(select(
    .value.os == "lin" and ($target == "@lin" or .key == $target)))' \
  <<<"$inventory_json" >"$STATE/original-inventory.json"
unset inventory_json
cp "$STATE/original-inventory.json" "$STATE/inventory.json"
load_hosts
printf 'Selected hosts: %s\n' "${HOSTS[*]}"
printf 'WARNING: root and ALL other local passwords/shells will be locked. Services/jobs using login shells can break.\n'
printf 'SSH/PAM are unchanged; existing sessions, some subsystems and directory accounts are NOT disabled.\n'
confirm "Create/prepare sysadmin with password-required admin access, lock all other local accounts on these hosts, and update $SOURCE_INVENTORY" || exit 0
backup_source_inventory || die 'Source inventory backup failed; no accounts changed'

READY_HOSTS=()
for host in "${HOSTS[@]}"; do
  if remote "$host" preflight "$STATE/original-inventory.json"; then
    journal "$host" PREFLIGHT_OK
    READY_HOSTS+=("$host")
  else
    journal "$host" PREFLIGHT_FAILED
    FAILED=$((FAILED + 1))
    printf 'SKIP: %s failed preflight; continuing with other hosts.\n' "$host" >&2
  fi
done
if ((${#READY_HOSTS[@]} == 0)); then
  report_password_results
  printf '\nSUMMARY: hardened=0 failed=%d not-completed=0\n' "$FAILED"
  printf 'No hosts passed preflight; no account changes made.\n' >&2
  exit 1
fi

generate_password() {
  local wordlist_url=https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --connect-timeout 5 --max-time 45 \
      "$wordlist_url" -o "$STATE/eff-large-wordlist.txt" || die 'EFF wordlist download failed; no accounts changed'
  elif command -v wget >/dev/null 2>&1; then
    wget --timeout=15 --tries=1 -O "$STATE/eff-large-wordlist.txt" \
      "$wordlist_url" || die 'EFF wordlist download failed; no accounts changed'
  else
    die 'Install curl or wget; no accounts changed'
  fi

  python3 - "$STATE/eff-large-wordlist.txt" "$STATE" "$PASSWORD_MODE" "${READY_HOSTS[@]}" <<'PY'
import json
import os
import pathlib
import re
import secrets
import sys

entries = {}
with open(sys.argv[1], encoding="ascii") as source:
    for line in source:
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r"[1-6]{5}", fields[0]):
            raise SystemExit("Invalid EFF wordlist row; no accounts changed")
        code, word = fields
        if code in entries or not re.fullmatch(r"[a-z]+(?:[-'][a-z]+)*", word):
            raise SystemExit("Invalid/duplicate EFF wordlist entry; no accounts changed")
        entries[code] = word
if len(entries) != 7776 or len(set(entries.values())) != 7776:
    raise SystemExit("Incomplete EFF wordlist; expected 7,776 unique entries")
# Alphabetic entries keep exactly three hyphen-separated words in the output.
words = [word for word in entries.values() if re.fullmatch(r"[a-z]+", word)]
if len(words) < 7000:
    raise SystemExit("Too few alphabetic EFF entries")
def new_password():
    return "-".join(secrets.choice(words).capitalize() for _ in range(3)) + f"{secrets.randbelow(100):02d}"

def save_secret(path, text):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as destination:
        destination.write(text)
        destination.flush()
        os.fsync(destination.fileno())

state = pathlib.Path(sys.argv[2])
mode = sys.argv[3]
passwords = {}
used = set()
shared = new_password() if mode == "shared" else None
for host in sys.argv[4:]:
    if mode == "shared":
        passwords[host] = shared
    else:
        password = new_password()
        while password in used:
            password = new_password()
        used.add(password)
        passwords[host] = password
save_secret(state / "passwords.json", json.dumps(passwords, indent=2) + "\n")
if shared is not None:
    save_secret(state / "master-password", shared + "\n")
PY
}

if [[ "$PASSWORD_SOURCE" == random ]]; then
  generate_password
else
  printf '%s\n' "$PASSWORD" >"$STATE/master-password"
  printf '%s\n' "${READY_HOSTS[@]}" | jq -Rn --rawfile password "$STATE/master-password" \
    'reduce inputs as $host ({}; .[$host] = ($password | rtrimstr("\n")))' >"$STATE/passwords.json"
fi
printf 'Assigned passwords saved privately: %s/passwords.json\n' "$STATE"
if [[ "$PASSWORD_MODE" == shared ]]; then
  printf 'Shared master password saved privately: %s/master-password\n' "$STATE"
fi

for host in "${READY_HOSTS[@]}"; do
  PASSWORD=$(password_for_host "$host") || die "Missing or invalid saved password for $host; refusing to use another host's password"
  # Save recovery credentials BEFORE starting a mutation, including when the
  # inventory already logs in as sysadmin and its old password will go stale.
  set_working_user "$host"
  journal "$host" PREPARE_STARTED
  if ! remote "$host" prepare "$STATE/original-inventory.json"; then
    journal "$host" PREPARE_FAILED_INSPECT_BACKUP
    if remote "$host" restore "$STATE/original-inventory.json" || remote "$host" restore "$STATE/inventory.json"; then
      set_original_user "$host"
      journal "$host" RESTORED
    else
      journal "$host" RECOVERY_REQUIRED_OR_NO_BACKUP
    fi
    FAILED=$((FAILED + 1))
    printf 'FAILED: %s preparation; recovery result is in journal.tsv. Continuing with other hosts.\n' "$host" >&2
    continue
  fi
  journal "$host" SYSADMIN_PREPARED
  if ! remote "$host" verify "$STATE/inventory.json" 0; then
    journal "$host" LOGIN_OR_ADMIN_VERIFICATION_FAILED
    if remote "$host" restore "$STATE/original-inventory.json" || remote "$host" restore "$STATE/inventory.json"; then
      set_original_user "$host"
      journal "$host" RESTORED
    else
      journal "$host" RECOVERY_REQUIRED
    fi
    FAILED=$((FAILED + 1))
    printf 'FAILED: %s login/admin verification; recovery result is in journal.tsv. Continuing with other hosts.\n' "$host" >&2
    continue
  fi
  journal "$host" LOCK_STARTED
  lock_inventory="$STATE/original-inventory.json"
  if [[ "$(jq -r --arg h "$host" '.[$h].user' "$lock_inventory")" == sysadmin ]]; then
    lock_inventory="$STATE/inventory.json"
  fi
  if ! remote "$host" lock "$lock_inventory"; then
    journal "$host" LOCK_FAILED_INSPECT_BACKUP
    # The target attempts rollback itself; try original credentials as well.
    if remote "$host" restore "$STATE/inventory.json" || remote "$host" restore "$STATE/original-inventory.json"; then
      set_original_user "$host"
      journal "$host" RESTORED
    else
      journal "$host" RECOVERY_REQUIRED
    fi
    FAILED=$((FAILED + 1))
    printf 'FAILED: %s account locking; recovery result is in journal.tsv. Continuing with other hosts.\n' "$host" >&2
    continue
  fi
  if remote "$host" verify "$STATE/inventory.json" 0; then
    journal "$host" HARDENED_VERIFIED
    SUCCEEDED=$((SUCCEEDED + 1))
    persist_source_inventory "$host"
  else
    journal "$host" FINAL_LOGIN_FAILED
    if remote "$host" restore "$STATE/inventory.json" || remote "$host" restore "$STATE/original-inventory.json"; then
      set_original_user "$host"
      journal "$host" RESTORED
    else
      journal "$host" RECOVERY_REQUIRED
      printf 'Console recovery required on %s from /var/lib/ccdc-user-hardening/%s\n' "$host" "$RUN_ID" >&2
    fi
    FAILED=$((FAILED + 1))
    printf 'FAILED: %s final verification; recovery result is in journal.tsv. Continuing with other hosts.\n' "$host" >&2
    continue
  fi
done
report_password_results
printf '\nSUMMARY: hardened=%d failed=%d not-completed=%d inventory-failures=%d\n' "$SUCCEEDED" "$FAILED" "$((${#HOSTS[@]} - SUCCEEDED - FAILED))" "$INVENTORY_FAILURES"
printf 'Source inventory: %s\nWorking/recovery inventory: %s/inventory.json\n' "$SOURCE_INVENTORY" "$STATE"
printf 'Restore: bash %q --restore %q\n' "$ROOT/harden-users.sh" "$STATE"
((FAILED == 0 && INVENTORY_FAILURES == 0))
