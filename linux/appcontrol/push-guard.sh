#!/usr/bin/env bash
# push-guard.sh — push and install ccdc-guard on every "os: lin" host
# in hosts.yml. Follows the same pattern as push-auditd.sh.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="${CCDC_HOSTS:-$ROOT/../centralized_tooling/hosts.yml}"

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
for tool in yq jq sshpass scp ssh; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing dependency: $tool" >&2; exit 1; }
done
[[ -r "$INVENTORY" ]] || { echo "Cannot read inventory: $INVENTORY" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Parse hosts.yml (handle mikefarah/go-yq vs jq-based yq)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Push and install on each host
# ---------------------------------------------------------------------------
successes=0
failures=0

for h in "${hosts[@]}"; do
    entry="$(jq -c --arg h "$h" '.[$h]' <<<"$inventory_json")"
    ip="$(jq -r '.ip'       <<<"$entry")"
    user="$(jq -r '.user'   <<<"$entry")"
    pass="$(jq -r '.pass'   <<<"$entry")"
    port="$(jq -r '.port // 22' <<<"$entry")"

    echo ""
    echo "=== $h ($user@$ip:$port) ==="

    ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$port")
    scp_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -P "$port")

    # Stage the entire appcontrol directory to a temp location on the target
    remote_stage="/tmp/ccdc-guard-pkg"

    # Create the staging directory on the remote host
    if ! printf '%s\n' "$pass" | SSHPASS="$pass" sshpass -e ssh "${ssh_opts[@]}" \
            "$user@$ip" "mkdir -p $remote_stage"; then
        echo "FAILED (mkdir): $h" >&2
        failures=$((failures + 1))
        continue
    fi

    # SCP the whole appcontrol directory contents to the stage directory
    if ! SSHPASS="$pass" sshpass -e scp "${scp_opts[@]}" -r \
            "$ROOT/ccdc_guard" \
            "$ROOT/ccdc-guard" \
            "$ROOT/install.sh" \
            "$user@$ip:$remote_stage/"; then
        echo "FAILED (scp): $h" >&2
        failures=$((failures + 1))
        continue
    fi

    # Run install.sh via sudo, then clean up
    remote_cmd="cd $remote_stage && chmod +x install.sh && sudo -S -p '' -- ./install.sh ; rm -rf $remote_stage"
    if printf '%s\n' "$pass" | SSHPASS="$pass" sshpass -e ssh "${ssh_opts[@]}" \
            "$user@$ip" "$remote_cmd"; then
        successes=$((successes + 1))
        echo "OK: $h"
    else
        echo "FAILED (install): $h" >&2
        failures=$((failures + 1))
    fi
done

echo ""
echo "Completed: $successes succeeded, $failures failed"
(( failures == 0 ))
