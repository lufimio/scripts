#!/usr/bin/env bash
# setup.sh - install auditd + outbound connect rule, then run connect_watch in the background (nohup).
# Table output is appended to /var/log/thrunting/outbound_connections.log. Re-runnable.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

WATCH=/usr/local/sbin/connect_watch.sh
OUTDIR=/var/log/thrunting
OUTLOG=$OUTDIR/outbound_connections.log
RULE='-a always,exit -F arch=b64 -S connect -F key=outgoing_connections'
RULE_FILE=/etc/audit/rules.d/outgoing_connections.rules

# Install auditd if missing
if ! command -v auditctl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y auditd
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y audit
    elif command -v yum >/dev/null 2>&1; then
        yum install -y audit
    elif command -v zypper >/dev/null 2>&1; then
        zypper install -y audit
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --noconfirm audit
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache audit
    else
        echo "Unsupported package manager" >&2
        exit 1
    fi
fi

# Ensure auditd is enabled and running
if command -v rc-update >/dev/null 2>&1; then
    rc-update add auditd default 2>/dev/null || true
    rc-service auditd start 2>/dev/null || true
else
    systemctl enable --now auditd 2>/dev/null || service auditd start
fi

# Persist the rule, then apply it immediately if not already loaded
mkdir -p /etc/audit/rules.d
grep -Fxq "$RULE" "$RULE_FILE" 2>/dev/null || echo "$RULE" >> "$RULE_FILE"
loaded=$(auditctl -l)
[[ $loaded == *key=outgoing_connections* ]] || auditctl $RULE
echo "Audit rule installed and applied."

# Install the watcher
install -d -m 700 "$OUTDIR"
cat > "$WATCH" <<'WATCH_EOF'
#!/usr/bin/env bash
# connect_watch.sh - live view of outbound connect() calls from auditd.
# Needs audit rule: -a always,exit -F arch=b64 -S connect -F key=outgoing_connections
# Usage: sudo ./connect_watch.sh [FULL_LOG_FILE]
#   One row per process (pid+exe): all its connects within WINDOW secs are merged, COUNT = number of connects,
#   DEST shows the first destination plus "+N" more. FULL_LOG_FILE (optional) gets every row untruncated,
#   tab-separated with a header, and lists all destinations comma-separated.
# Env: LOG=/path/to/audit.log  WINDOW=secs (default 3)  HEADER=0 (skip header). Needs bash >= 4.3. '!' marks tmp/shm/memfd/deleted exes.

LOG=${LOG:-/var/log/audit/audit.log}
WINDOW=${WINDOW:-3}
OUT=${1:-}
US=$'\x1f' TAB=$'\t'

declare -A sys sa row dst cnt last un   # pending syscalls, sockaddrs, rows, destinations, counts, last-seen, uid->name cache

get() {  # get FIELD LINE -> sets V
  local re="(^| )$1=(\"[^\"]*\"|[^ ]+)"
  V=; [[ $2 =~ $re ]] && V=${BASH_REMATCH[2]//\"/}
}

dest() {  # hex saddr -> ip:port (inet/inet6 only; unix/netlink print nothing). IPv6 forms of IPv4 are shown as IPv4.
  local s=${1^^} a ip
  case ${s:0:4} in
    0200) ip=${s:8:8} ;;
    0A00) a=${s:16:32}
          case $a in
            00000000000000000000000000000000) ip=00000000 ;;                  # ::          -> 0.0.0.0
            00000000000000000000000000000001) ip=7F000001 ;;                  # ::1         -> 127.0.0.1
            00000000000000000000FFFF*|0064FF9B0000000000000000*) ip=${a:24:8} ;;  # ::ffff:a.b.c.d and NAT64 64:ff9b::a.b.c.d
            *) echo "[${a:0:4}:${a:4:4}:${a:8:4}:${a:12:4}:${a:16:4}:${a:20:4}:${a:24:4}:${a:28:4}]:$((16#${s:4:4}))"; return ;;
          esac ;;
    *) return ;;
  esac
  echo "$((16#${ip:0:2})).$((16#${ip:2:2})).$((16#${ip:4:2})).$((16#${ip:6:2})):$((16#${s:4:4}))"
}

title() {  # hex proctitle -> readable command line (sets V); plain text passes through
  V=$1
  [[ $V =~ ^([0-9A-Fa-f]{2})+$ ]] || return
  printf -v V '%b' "$(sed 's/../\\x&/g; s/\\x00/ /g' <<<"$V")"
  V=${V% }
}

record() {  # runs on the PROCTITLE line (last record of an event); uses globals $id $ts $line
  local sl=${sys[$id]} saddr=${sa[$id]} d pid ppid uid exe comm user svc=- par cmd x k now flag= re='([^/]+\.service)'
  unset "sys[$id]" "sa[$id]"
  [[ $saddr ]] || return
  d=$(dest "$saddr"); [[ $d ]] || return

  get pid "$sl";  pid=$V
  get ppid "$sl"; ppid=$V
  get uid "$sl";  uid=$V
  get exe "$sl";  exe=$V
  get comm "$sl"; comm=$V
  get proctitle "$line"; title "$V"; cmd=${V:-$comm}
  [[ $pid =~ ^[0-9]+$ && $uid ]] || return

  user=${un[$uid]:=$(getent passwd "$uid" | cut -d: -f1)}; user=${user:-$uid}

  x=$(readlink "/proc/$pid/exe" 2>/dev/null); exe=${x:-$exe}   # shows "(deleted)" if binary was removed
  case $exe in /tmp/*|/var/tmp/*|/dev/shm/*|/memfd:*|*deleted*) flag='!' ;; esac

  if [[ -r /proc/$pid/cgroup ]]; then                          # systemd unit, best effort
    while read -r x; do
      [[ $x =~ $re ]] && { svc=${BASH_REMATCH[1]}; break; }
    done < "/proc/$pid/cgroup"
  fi
  par=$(tr '\0' ' ' 2>/dev/null <"/proc/$ppid/cmdline"); par=${par:--}

  printf -v now '%(%s)T' -1
  k=${pid}_${exe//[^[:alnum:]]/_}                              # one aggregate per process, not per destination
  if [[ -v last[$k] ]]; then
    cnt[$k]=$(( ${cnt[$k]} + 1 ))
  else
    printf -v x '%(%T)T' "$ts"
    row[$k]="$x$US$user$US$pid$US$ppid$US$flag$exe$US$svc$US$cmd$US$par"
    cnt[$k]=1
  fi
  [[ " ${dst[$k]} " == *" $d "* ]] || dst[$k]+=" $d"           # keep unique destinations
  last[$k]=$now
}

flush() {  # print rows idle longer than WINDOW; "flush all" prints everything
  local k r now t u p pp e s c pr a d
  printf -v now '%(%s)T' -1
  for k in "${!last[@]}"; do
    (( now - ${last[$k]} > WINDOW )) || [[ ${1:-} == all ]] || continue
    r=${row[$k]}
    IFS=$US read -r t u p pp e s c pr <<<"$r"
    read -ra a <<<"${dst[$k]}"
    d=${a[0]}; (( ${#a[@]} > 1 )) && d+=" +$(( ${#a[@]} - 1 ))"
    printf '%-8s %-10.10s %-7s %-7s %-34.34s %-26s %5d  %-20.20s %-50.50s <- %.30s\n' \
      "$t" "$u" "$p" "$pp" "$e" "$d" "${cnt[$k]}" "$s" "$c" "$pr"
    [[ $OUT ]] && printf '%s\t%s\t%s\n' "${r//$US/$TAB}" "${a[*]// /,}" "${cnt[$k]}" >>"$OUT"
    unset "row[$k]" "dst[$k]" "cnt[$k]" "last[$k]"
  done
}

[[ -r $LOG ]] || { echo "Cannot read $LOG (run as root?)" >&2; exit 1; }
if [[ $OUT ]]; then
  [[ -s $OUT ]] || printf 'time\tuser\tpid\tppid\texe\tservice\tcmd\tparent\tdests\tcount\n' >>"$OUT" || exit 1
fi
trap 'flush all; exit' INT TERM

[[ ${HEADER:-1} == 1 ]] && printf '%-8s %-10s %-7s %-7s %-34s %-26s %5s  %-20s %-50s    %s\n' \
  TIME USER PID PPID EXE DEST COUNT SERVICE CMD PARENT

ev='audit\(([0-9]+)\.[0-9]+:([0-9]+)\)'
while true; do
  IFS= read -r -t 1 line; rc=$?
  (( rc == 1 )) && break                       # tail exited; rc>128 is just the 1s timeout
  if (( rc == 0 )) && [[ $line =~ $ev ]]; then
    ts=${BASH_REMATCH[1]} id=${BASH_REMATCH[2]}
    case $line in
      "type=SYSCALL "*)   [[ $line == *'key="outgoing_connections"'* ]] && sys[$id]=$line ;;
      "type=SOCKADDR "*)  [[ -v sys[$id] ]] && { get saddr "$line"; sa[$id]=$V; } ;;
      "type=PROCTITLE "*) [[ -v sys[$id] ]] && record ;;
    esac
  fi
  flush
done < <(tail -F -n0 "$LOG" 2>/dev/null)
flush all
WATCH_EOF
chmod 755 "$WATCH"

# Run it in the background (replaces any copy already running; not persistent across reboots)
pkill -f "$WATCH" || true
[[ -e $OUTLOG ]] && header=0 || header=1     # header only when the log file is new
HEADER=$header nohup "$WATCH" >> "$OUTLOG" 2>&1 < /dev/null &
echo "Watcher running in background (pid $!)."
echo "Output: $OUTLOG"
