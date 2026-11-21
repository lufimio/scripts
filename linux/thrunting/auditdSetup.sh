#!/bin/bash
set -euo pipefail

# auditD installation
#
#
# Samuel Brucker 2025-2026


# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="$SCRIPT_DIR/audit.rules"
DEST_RULES_FILE="/etc/audit/rules.d/99-custom.rules"
# Rules to be removed for Wazuh compatibility
INCOMPATIBLE_RULE="-a never,task"
# Note: "-e 2" must be at END of file (makes rules immutable until reboot)

# --- Pre-flight Checks ---
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root or with sudo. Please try again."
  exit 1
fi
if [ ! -f "$RULES_FILE" ]; then
  echo "Error: The rules file '$RULES_FILE' was not found in this directory."
  exit 1
fi

# --- Main Execution ---
echo "Starting robust, Wazuh-compatible auditd setup..."

# Step 1: Install auditd
echo "----------------------------------------"
echo "STEP 1: Installing auditd package..."
if command -v apt-get &> /dev/null; then
    apt-get update -y > /dev/null 2>&1
    apt-get install auditd audispd-plugins -y

elif command -v dnf &> /dev/null; then
    dnf install audit audispd-plugins -y

elif command -v yum &> /dev/null; then
    yum install audit audispd-plugins -y

elif command -v apk &> /dev/null; then
    apk add --no-cache audit

else
    echo "❌ Unsupported package manager. Please install auditd manually."
    exit 1
fi
echo "✅ auditd package installed."

# Step 2: Enable the auditd service
echo "----------------------------------------"
echo "STEP 2: Enabling auditd service on boot..."
if command -v rc-update &>/dev/null; then
    rc-update add auditd default > /dev/null 2>&1
else
    systemctl enable auditd > /dev/null 2>&1
fi
echo "✅ auditd service enabled."

# Step 3: Copy the custom rules file
echo "----------------------------------------"
echo "STEP 3: Copying custom rules to $DEST_RULES_FILE..."
cp -f "$RULES_FILE" "$DEST_RULES_FILE"
chmod 640 "$DEST_RULES_FILE"
echo "✅ Rules file copied."

# Step 4: Sanitize all rules files (CRITICAL FOR WAZUH AND FEDORA)
echo "----------------------------------------"
echo "STEP 4: Removing incompatible rules from all rule files..."
# Remove "-a never,task" and "-a task,never" from ALL rules files
# These suppress all syscall auditing and break Wazuh integration
for rules_file in /etc/audit/rules.d/*.rules; do
    [ -f "$rules_file" ] || continue
    sed -i '/^-a never,task$/d' "$rules_file"
    sed -i '/^-a task,never$/d' "$rules_file"
done
# Also remove from our custom rules just in case
sed -i '/^-a never,task$/d' "$DEST_RULES_FILE"
sed -i '/^-a task,never$/d' "$DEST_RULES_FILE"
echo "✅ Rules files sanitized."

# Step 5: Fix SELinux Context (CRITICAL FOR FEDORA/RHEL)
echo "----------------------------------------"
echo "STEP 5: Restoring SELinux context on rules file..."
if command -v restorecon &> /dev/null; then
    restorecon -v "$DEST_RULES_FILE"
    echo "✅ SELinux context restored."
else
    echo "🔎 'restorecon' not found, skipping. (This is normal on non-SELinux systems)."
fi

# Step 6: Explicitly Load Rules (CRITICAL FOR CENTOS 7)
echo "----------------------------------------"
echo "STEP 6: Forcing the kernel to load the new rules now..."
# Check if rules are currently immutable (enabled=2) — requires reboot to change
AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep -oP 'enabled\s+\K\d+' || echo "0")
if [ "$AUDIT_ENABLED" = "2" ]; then
    echo "⚠️  Audit rules are currently immutable (enabled=2)."
    echo "    Rules have been placed in $DEST_RULES_FILE and will load on next reboot."
    echo "    Reboot required for changes to take effect."
else
    augenrules_out=$(augenrules --load 2>&1) || {
        echo "❌ FAILED to load audit rules. There is likely a syntax error in your '$RULES_FILE'."
        echo "$augenrules_out"
        exit 1
    }
    echo "✅ Rules loaded into the kernel successfully."
fi

# Step 7: Restart the daemon and verify
echo "----------------------------------------"
echo "STEP 7: Restarting the auditd daemon and verifying..."
if [ "$AUDIT_ENABLED" = "2" ]; then
    echo "⚠️  Skipping restart — rules are immutable. Reboot to apply changes."
else
    if command -v rc-service &>/dev/null; then
        rc-service auditd restart 2>/dev/null || true
    elif ! systemctl restart auditd 2>/dev/null; then
        # Fedora/RHEL may refuse systemctl restart for auditd — fall back to service command
        echo "systemctl restart failed (common on Fedora), trying 'service auditd restart'..."
        service auditd restart 2>/dev/null || true
    fi
fi
sleep 1 # Give the service a moment to stabilize

auditd_is_active() {
    if command -v rc-service &>/dev/null; then
        rc-service auditd status 2>/dev/null | grep -q started
    else
        systemctl is-active --quiet auditd
    fi
}

if auditd_is_active; then
    RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l)
    echo "✅ Verification successful! The auditd service is active."
    echo "🔎 Rules loaded in kernel: $RULE_COUNT"
    echo "    To inspect rules: sudo auditctl -l"
else
    echo "❌ Verification failed. The auditd service could not be started."
    exit 1
fi

echo ""
if [ "$AUDIT_ENABLED" = "2" ]; then
    echo "⚠️  Setup complete — REBOOT REQUIRED to load new rules."
else
    echo "✅ Auditd setup complete with MITRE ATT&CK mapped rules!"
fi
