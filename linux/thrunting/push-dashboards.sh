#!/usr/bin/env bash
# Installs the ccdc_soc Splunk app (8 dashboards + props/transforms) on the
# host tagged splunk=true in hosts.yml, or falls back to the first "os: lin"
# host whose name contains "splunk".
#
# Usage:
#   bash push-dashboards.sh                        # auto-detect Splunk host
#   SPLUNK_HOST=splunk01 bash push-dashboards.sh   # explicit target
#   SPLUNK_HOME=/opt/splunk bash push-dashboards.sh
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="${CCDC_HOSTS:-$ROOT/../centralized_tooling/hosts.yml}"
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
APP_NAME="ccdc_soc"
APP_DIR="$SPLUNK_HOME/etc/apps/$APP_NAME"

for tool in yq jq sshpass scp ssh; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing dependency: $tool" >&2; exit 1; }
done
[[ -r "$INVENTORY" ]] || { echo "Cannot read inventory: $INVENTORY" >&2; exit 1; }

DASHBOARD_DIR="$ROOT/splunk/dashboards"
PROPS="$ROOT/splunk/props.conf"
TRANSFORMS="$ROOT/splunk/transforms.conf"
[[ -d "$DASHBOARD_DIR" ]] || { echo "Dashboards not found: $DASHBOARD_DIR" >&2; exit 1; }
[[ -f "$PROPS"          ]] || { echo "props.conf not found: $PROPS" >&2; exit 1; }

if yq --version 2>&1 | grep -qi mikefarah; then
    inventory_json="$(yq -o=json '.' "$INVENTORY")"
else
    inventory_json="$(yq -c '.' "$INVENTORY")"
fi

# Resolve target host: explicit env > splunk=true tag > name contains "splunk"
if [[ -n "${SPLUNK_HOST:-}" ]]; then
    target="$SPLUNK_HOST"
else
    target="$(jq -r '
        to_entries[]
        | select(.value.os == "lin" and (.value.splunk // false))
        | .key
    ' <<<"$inventory_json" | head -1)"
    if [[ -z "$target" ]]; then
        target="$(jq -r '
            to_entries[]
            | select(.value.os == "lin" and (.key | ascii_downcase | contains("splunk")))
            | .key
        ' <<<"$inventory_json" | head -1)"
    fi
fi
[[ -n "$target" ]] || { echo "Cannot find Splunk host — set SPLUNK_HOST=<name>" >&2; exit 1; }

entry="$(jq -c --arg h "$target" '.[$h]' <<<"$inventory_json")"
ip="$(jq -r '.ip'       <<<"$entry")"
user="$(jq -r '.user'   <<<"$entry")"
pass="$(jq -r '.pass'   <<<"$entry")"
port="$(jq -r '.port // 22' <<<"$entry")"

echo "Target: $target ($user@$ip:$port)"
echo "App:    $APP_DIR"
echo ""

ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$port")
scp_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -P "$port")

# ── Stage files ───────────────────────────────────────────────────────────────

echo "Staging files..."

# Dashboards
SSHPASS="$pass" sshpass -e scp "${scp_opts[@]}" \
    "$DASHBOARD_DIR"/*.xml "$user@$ip:/tmp/"

# props + transforms (transforms may not exist — ignore if missing)
files_to_stage=("$PROPS")
[[ -f "$TRANSFORMS" ]] && files_to_stage+=("$TRANSFORMS")
SSHPASS="$pass" sshpass -e scp "${scp_opts[@]}" \
    "${files_to_stage[@]}" "$user@$ip:/tmp/"

# ── Install ───────────────────────────────────────────────────────────────────

remote="$(cat <<EOF
set -e

SPLUNK_HOME='$SPLUNK_HOME'
APP_DIR='\$SPLUNK_HOME/etc/apps/$APP_NAME'

if [ ! -x "\$SPLUNK_HOME/bin/splunk" ]; then
    echo "ERROR: Splunk not found at \$SPLUNK_HOME" >&2; exit 1
fi

sudo -S -p '' mkdir -p \\
    "\$APP_DIR/default/data/ui/views" \\
    "\$APP_DIR/default/data/ui/nav" \\
    "\$APP_DIR/metadata"

# app.conf
sudo -S -p '' tee "\$APP_DIR/default/app.conf" > /dev/null <<'APPCONF'
[launcher]
author = CCDC Blue Team
[package]
id = ccdc_soc
[ui]
is_visible = true
label = CCDC SOC
[app]
build = 1
version = 1.0
APPCONF

# nav (list every dashboard by filename stem)
sudo -S -p '' tee "\$APP_DIR/default/data/ui/nav/default.xml" > /dev/null <<'NAVXML'
<nav search_view="search" color="#3c444d">
  <view name="1_competition_command_center" default="true" />
  <view name="2_network_threat_detection" />
  <view name="4_authentication_credential_security" />
  <view name="8_network_visibility" />
  <view name="9_file_integrity_monitoring" />
  <view name="11_threat_hunting_triage" />
  <view name="10_windows_security" />
  <view name="7_honeypot_cowrie" />
</nav>
NAVXML

# metadata
sudo -S -p '' tee "\$APP_DIR/metadata/default.meta" > /dev/null <<'META'
[]
access = read : [ * ], write : [ admin ]
export = system
META

# dashboards
sudo -S -p '' mv /tmp/*.xml "\$APP_DIR/default/data/ui/views/"

# props / transforms
[ -f /tmp/props.conf    ] && sudo -S -p '' mv /tmp/props.conf    "\$APP_DIR/default/"
[ -f /tmp/transforms.conf ] && sudo -S -p '' mv /tmp/transforms.conf "\$APP_DIR/default/"

sudo -S -p '' chown -R splunk:splunk "\$APP_DIR"

echo "App installed — restarting Splunk..."
sudo -S -p '' "\$SPLUNK_HOME/bin/splunk" restart 2>&1 | tail -3

echo ""
echo "CCDC SOC app live at http://\$(hostname -s):8000/en-US/app/$APP_NAME"
EOF
)"

printf '%s\n' "$pass" | SSHPASS="$pass" sshpass -e ssh "${ssh_opts[@]}" "$user@$ip" "$remote"
