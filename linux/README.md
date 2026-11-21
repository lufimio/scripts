# Linux

This is the [new] section of the repo dedicated to Linux.

## File Structure

- `first15`: Contains scripts to be run from Kali during the "first 15" section.

- `services`: Contains scripts that secure services organized by the types of systems they run on. 

## Services

Checklist hardening this stuff, please.

- FTP: vsftpd, ProFTPD, Pure-FTPd
- SSH: sshd, Dropbear, wolfSSH, Apache MINA SSHD, TinySSH
- Telnet: telnetd, utelnetd
- SNMP: snmpd, net-snmp
- SMTP: postfix, exim, OpenSMTPD, Stalwart
- POP3: dovecot, courier-pop3d
- IMAP: dovecot
- Webmail (?)
- TFTP: tftpd-hpa, atftpd
- VNC: TigerVNC, TightVNC
- NFS: rpc.nfsd, rpcbind, lockd
- SMB: smbd, nmbd, winbindd
- DNS: dnsmasq, named (BIND)
- Splunk: Splunkd
- MySQL: mysqld

## Gameplan

### First 15 (From Kali)

0. Fix line endings + install deps
```bash
cd /home/sysadmin/linux # not needed in WRCCDC
find . -type f -name '*.sh' -not -path '*/.git/*' -exec sed -i 's/\r$//' {} + # run in the current dir to fix the line endings for Linux--may not be needed
sudo apt-get update && sudo apt-get install -y jq sshpass
sudo wget -qO /usr/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod +x /usr/bin/yq
chmod 600 centralized_tooling/hosts.yml
chmod +x centralized_tooling/cfk.sh
```

1. Rotate creds on every Linux host
```bash
# cd /home/sysadmin/linux
sudo bash first15/harden-users.sh --password 'complex_pass' @lin # replace complex_pass with the default password
```

2. Inventory, send the yml output to Ronald
```bash
# cd /home/sysadmin/linux
sudo bash centralized_tooling/cfk.sh -q -s @lin first15/audit-inventory yaml | tee inv.yml
# TODO: Run script whcih turns inv.yml into firewall rules, then run those here
nc -l -p 4444 < inv.yml # wget http://172.17.0.2:4444/inv.yml
```

3. Any other first15 scripts the Linux team wants
```bash
# cd /home/sysadmin/linux
sudo bash centralized_tooling/cfk.sh -s @lin first15/harden-perms
sudo bash centralized_tooling/cfk.sh -s @lin first15/harden-ssh --apply
```

4. ccdc-guard--a WDAC-esque thing (NOT TESTED--DON'T RUN)
```bash
# cd /home/sysadmin/linux

# Install ccdc-guard on all lin hosts (Python + fapolicyd, does NOT enable enforcement yet)
sudo bash appcontrol/push-guard.sh

# Build the trust baseline on all hosts (discover packages + running services)
sudo bash centralized_tooling/cfk.sh -s @lin appcontrol/cfk-wrappers/guard-baseline

# Optional: enable audit mode first to watch what would be blocked (safe, no enforcement)
sudo bash centralized_tooling/cfk.sh -s @lin appcontrol/cfk-wrappers/guard-audit
# ... check denials with:
sudo bash centralized_tooling/cfk.sh -s @lin appcontrol/cfk-wrappers/guard-denials

# Enable enforcement (pre-checks all services, auto-rollback if anything breaks)
sudo bash centralized_tooling/cfk.sh -s @lin appcontrol/cfk-wrappers/guard-enforce

# If enforcement breaks something, rollback:
# ccdc-guard rollback     (run on the affected host)

# To approve a new executable (e.g. a patched binary you pushed):
# ccdc-guard approve /path/to/binary
```

5. Hardening scans (NOT TESTED)
```bash
# cd /home/sysadmin/linux

# Strip GTFOBins SUID/SGID bits
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/suidCleanup

# Audit PAM config for suspicious entries (review output manually)
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/pamAudit

# Establish FIM baseline (must run before any `fim check`)
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/fim init
```

5. Splunk setup (one-time)
```bash
# cd /home/sysadmin/linux

# Push inputs.conf to UF on every lin host (index=linux, linux:audit, linux_secure, ccdc_changes)
sudo bash thrunting/push-splunk-inputs.sh

# On the Splunk INDEXER — place props.conf and transforms.conf for field extraction:
#   cp thrunting/splunk/props.conf     /opt/splunk/etc/system/local/props.conf
#   cp thrunting/splunk/transforms.conf /opt/splunk/etc/system/local/transforms.conf
#   systemctl restart Splunkd

# Import all dashboards into Splunk Web:
#   Search & Reporting → Dashboards → Create New Dashboard → Source → paste XML
#   Dashboards are in: thrunting/splunk/dashboards/
#     1_competition_command_center.xml    — big-screen war room (needs Zeek/Suricata/Falco/Wazuh)
#     2_network_threat_detection.xml      — network threats (needs Zeek/Suricata)
#     4_authentication_credential_security.xml — auth events (works with linux_secure)
#     7_honeypot_cowrie.xml               — honeypot (needs Cowrie)
#     8_network_visibility.xml            — network traffic (needs Zeek)
#     9_file_integrity_monitoring.xml     — FIM (works: linux:audit + ccdc_changes added)
#     10_windows_security.xml             — Windows (needs Sysmon)
#     11_threat_hunting_triage.xml        — MAIN THRUNTING WORKBENCH (partially works)
#
# Fully populated with our setup: dashboards 4, 9
# Partially populated: dashboard 11 (Linux auth/process panels work; Zeek/Wazuh panels empty)
# Needs extra tooling: 1, 2, 7, 8, 10
```

6. Thrunting (NOT *REALLY* TESTED)
```bash
# cd /home/sysadmin/linux
sudo bash thrunting/push-auditd.sh
mkdir -p thrunting/logs

# Manual RQ
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/process-hunter
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/persistence-hunter
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/binaryVerify
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/webshellScan
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/securityScannerSetup -m scan
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/securitySweep
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/suidCleanup
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/pamAudit
sudo bash centralized_tooling/cfk.sh -s @lin thrunting/fim check

# Do that crontab *thang*
crontab -e
```
```bash
PATH=/usr/local/bin:/usr/bin:/bin

*/15 * * * * flock -n /tmp/ccdc-proc.lock bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/process-hunter'          >> /home/sysadmin/linux/thrunting/logs/process-hunter.log 2>&1
*/15 * * * * flock -n /tmp/ccdc-pers.lock bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/persistence-hunter'      >> /home/sysadmin/linux/thrunting/logs/persistence-hunter.log 2>&1
*/30 * * * * flock -n /tmp/ccdc-bver.lock bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/binaryVerify'            >> /home/sysadmin/linux/thrunting/logs/binary-verify.log 2>&1
*/30 * * * * flock -n /tmp/ccdc-wsh.lock  bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/webshellScan'            >> /home/sysadmin/linux/thrunting/logs/webshell-scan.log 2>&1
0    *  * * * flock -n /tmp/ccdc-scan.lock bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/securityScannerSetup -m scan' >> /home/sysadmin/linux/thrunting/logs/security-scan.log 2>&1
*/30 * * * * flock -n /tmp/ccdc-sweep.lock bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/securitySweep'          >> /home/sysadmin/linux/thrunting/logs/security-sweep.log 2>&1
*/30 * * * * flock -n /tmp/ccdc-suid.lock  bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/suidCleanup'            >> /home/sysadmin/linux/thrunting/logs/suid-cleanup.log 2>&1
0    *  * * * flock -n /tmp/ccdc-pam.lock   bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/pamAudit'              >> /home/sysadmin/linux/thrunting/logs/pam-audit.log 2>&1
0    *  * * * flock -n /tmp/ccdc-fim.lock   bash -c 'cd /home/sysadmin/linux && centralized_tooling/cfk.sh -s -q @lin thrunting/fim check'             >> /home/sysadmin/linux/thrunting/logs/fim.log 2>&1
```
