0. Fix line endings + install deps
```bash
cd /home/sysadmin/linux
find . -type f -name '*.sh' -not -path '*/.git/*' -exec sed -i 's/\r$//' {} +
sudo apt-get update && sudo apt-get install -y jq sshpass
sudo wget -qO /usr/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod +x /usr/bin/yq
chmod 600 centralized_tooling/hosts.yml
chmod +x centralized_tooling/cfk.sh
```

1. Rotate creds on every Linux host
```bash
# cd /home/sysadmin/linux
sudo bash first15/harden-users.sh --password '...' @lin
```

2. Inventory, send the yml output to Ronald
```bash
# cd /home/sysadmin/linux
sudo bash centralized_tooling/cfk.sh -q -s @lin first15/audit-inventory yaml | tee inv.yml
nc -l -p 4444 # wget http://172.17.0.2:4444/hosts.yml
```

3. Any other first15 scripts the Linux team wants
```bash
# cd /home/sysadmin/linux
sudo bash centralized_tooling/cfk.sh -s @lin first15/harden-perms
sudo bash centralized_tooling/cfk.sh -s @lin first15/harden-ssh --apply
```

4. Thrunting
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
```
