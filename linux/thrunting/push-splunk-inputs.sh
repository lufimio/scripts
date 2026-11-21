#!/usr/bin/env bash
# Deploys splunk-inputs.conf to the Splunk Universal Forwarder on every
# "os: lin" host in hosts.yml, then restarts the forwarder.
# One-shot — not meant to be cron'd.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="${CCDC_HOSTS:-$ROOT/../centralized_tooling/hosts.yml}"
INPUTS_CONF="$ROOT/splunk-inputs.conf"

# Default UF install path; override with UF_HOME env var if different
UF_HOME="${UF_HOME:-/opt/splunkforwarder}"
UF_INPUTS="$UF_HOME/etc/system/local/inputs.conf"
UF_BIN="$UF_HOME/bin/splunk"

for tool in yq jq sshpass scp ssh; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing dependency: $tool" >&2; exit 1; }
done
[[ -r "$INVENTORY" ]] || { echo "Cannot read inventory: $INVENTORY" >&2; exit 1; }
[[ -f "$INPUTS_CONF" ]] || { echo "inputs.conf not found: $INPUTS_CONF" >&2; exit 1; }

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
echo "UF path: $UF_HOME"
echo ""

successes=0
failures=0
for h in "${hosts[@]}"; do
    entry="$(jq -c --arg h "$h" '.[$h]' <<<"$inventory_json")"
    ip="$(jq -r '.ip' <<<"$entry")"
    user="$(jq -r '.user' <<<"$entry")"
    pass="$(jq -r '.pass' <<<"$entry")"
    port="$(jq -r '.port // 22' <<<"$entry")"

    echo "=== $h ($user@$ip:$port) ==="

    ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$port")
    scp_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -P "$port")

    if ! SSHPASS="$pass" sshpass -e scp "${scp_opts[@]}" \
            "$INPUTS_CONF" "$user@$ip:/tmp/ccdc-inputs.conf"; then
        echo "FAILED (scp): $h" >&2
        failures=$((failures + 1))
        continue
    fi

    remote="$(cat <<EOF
set -e
# Create local dir if UF is installed
if [ -d '$UF_HOME/etc/system/local' ]; then
    sudo -S -p '' cp /tmp/ccdc-inputs.conf '$UF_INPUTS'
    sudo -S -p '' chown root:root '$UF_INPUTS' 2>/dev/null || true
    sudo -S -p '' chmod 600 '$UF_INPUTS'
    # Restart forwarder
    if systemctl is-active --quiet SplunkForwarder 2>/dev/null; then
        sudo -S -p '' systemctl restart SplunkForwarder
    elif systemctl is-active --quiet splunk 2>/dev/null; then
        sudo -S -p '' systemctl restart splunk
    elif [ -x '$UF_BIN' ]; then
        sudo -S -p '' '$UF_BIN' restart
    else
        echo 'WARNING: Could not restart forwarder — restart manually'
    fi
    echo 'inputs.conf deployed and forwarder restarted'
else
    echo 'WARNING: Splunk UF not found at $UF_HOME — skipping'
fi
rm -f /tmp/ccdc-inputs.conf
EOF
)"
    if printf '%s\n' "$pass" | SSHPASS="$pass" sshpass -e ssh "${ssh_opts[@]}" "$user@$ip" "$remote"; then
        successes=$((successes + 1))
    else
        echo "FAILED (deploy): $h" >&2
        failures=$((failures + 1))
    fi
done

echo ""
echo "Completed: $successes succeeded, $failures failed"
(( failures == 0 ))
