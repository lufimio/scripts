#!/usr/bin/env bash
# One-time push of auditd + the custom rules to every "os: lin" host in
# hosts.yml. Not meant to be cron'd -- it installs a persistent daemon,
# then deletes the installer files it staged in /tmp.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="${CCDC_HOSTS:-$ROOT/hosts.yml}"

for tool in yq jq sshpass scp ssh; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing dependency: $tool" >&2; exit 1; }
done
[[ -r "$INVENTORY" ]] || { echo "Cannot read inventory: $INVENTORY" >&2; exit 1; }

# Same yq-flavor handling as ccdc_run.sh (mikefarah/go-yq vs the jq-based yq on Kali).
if yq --version 2>&1 | grep -qi mikefarah; then
    inventory_json="$(yq -o=json '.' "$INVENTORY")"
else
    inventory_json="$(yq -c '.' "$INVENTORY")"
fi

mapfile -t hosts < <(jq -r '
    to_entries[] | select(.value.os == "lin") | .key
' <<<"$inventory_json")

(( ${#hosts[@]} > 0 )) || { echo "No lin hosts found in $INVENTORY" >&2; exit 1; }

echo "Target hosts: ${hosts[*]}"

successes=0
failures=0
for h in "${hosts[@]}"; do
    entry="$(jq -c --arg h "$h" '.[$h]' <<<"$inventory_json")"
    ip="$(jq -r '.ip' <<<"$entry")"
    user="$(jq -r '.user' <<<"$entry")"
    pass="$(jq -r '.pass' <<<"$entry")"
    port="$(jq -r '.port // 22' <<<"$entry")"

    echo
    echo "=== $h ($user@$ip:$port) ==="

    ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$port")

    if ! SSHPASS="$pass" sshpass -e scp "${ssh_opts[@]}" \
            "$ROOT/auditdSetup.sh" "$ROOT/audit.rules" "$user@$ip:/tmp/"; then
        echo "FAILED (scp): $h" >&2
        failures=$((failures + 1))
        continue
    fi

    # sudo -S reads the password from stdin; piped in rather than placed on
    # any command line. No further prompts expected from auditdSetup.sh.
    remote='cd /tmp && chmod +x auditdSetup.sh && sudo -S -p "" -- ./auditdSetup.sh && rm -f auditdSetup.sh audit.rules'
    if printf '%s\n' "$pass" | SSHPASS="$pass" sshpass -e ssh "${ssh_opts[@]}" "$user@$ip" "$remote"; then
        successes=$((successes + 1))
    else
        echo "FAILED (install): $h" >&2
        failures=$((failures + 1))
    fi
done

echo
echo "Completed: $successes succeeded, $failures failed"
(( failures == 0 ))
