
#!/bin/sh
#
# CCDC Linux Permission Hardening
# POSIX /bin/sh compatible
#

# Display errors instead of silently suppressing them
exec 2>&1

# Require root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

# Safely apply ownership and permissions to existing paths
harden_paths() {
    owner=$1
    mode=$2
    shift 2

    for path do
        if [ -f "$path" ] || [ -d "$path" ] || [ -L "$path" ]; then
            if ! chown "$owner" "$path"; then
                echo "[ERROR] Failed chown: $path"
            fi

            if ! chmod "$mode" "$path"; then
                echo "[ERROR] Failed chmod: $path"
            fi
        fi
    done
}

echo "Starting CCDC permission hardening..."

# ==========================================
# 1. COMMON FILE PERMISSIONS
# ==========================================

# 1. ACCOUNT AND AUTHENTICATION FILES

harden_paths root:root 644 \
    /etc/passwd \
    /etc/group \
    /etc/group- \
    /etc/shells

harden_paths root:shadow 640 \
    /etc/shadow \
    /etc/gshadow

harden_paths root:root 600 \
    /etc/passwd- \
    /etc/security/opasswd

harden_paths root:shadow 600 \
    /etc/shadow- \
    /etc/gshadow-

# 2. SSH CONFIGURATION

harden_paths root:root 755 \
    /etc/ssh \
    /etc/ssh/sshd_config.d

harden_paths root:root 600 \
    /etc/ssh/sshd_config \
    /etc/ssh/ssh_host_*_key \
    /etc/ssh/sshd_config.d/*

harden_paths root:root 644 \
    /etc/ssh/ssh_config \
    /etc/ssh/ssh_host_*_key.pub

# 3. SUDO AND PAM

harden_paths root:root 440 /etc/sudoers

harden_paths root:root 750 /etc/sudoers.d

harden_paths root:root 440 /etc/sudoers.d/*

harden_paths root:root 644 \
    /etc/sudo.conf

harden_paths root:root 755 /etc/pam.d

harden_paths root:root 644 /etc/pam.d/*

# 4. CRON AND AT

harden_paths root:root 600 \
    /etc/crontab \
    /etc/cron.allow \
    /etc/cron.deny \
    /etc/at.allow \
    /etc/at.deny

harden_paths root:root 755 \
    /etc/cron.d \
    /etc/cron.hourly \
    /etc/cron.daily \
    /etc/cron.weekly \
    /etc/cron.monthly

harden_paths root:root 644 /etc/cron.d/*

# 5. SYSTEM CONFIGURATION

harden_paths root:root 644 \
    /etc/fstab \
    /etc/hosts \
    /etc/hostname \
    /etc/issue \
    /etc/issue.net \
    /etc/motd \
    /etc/profile \
    /etc/bash.bashrc \
    /etc/environment \
    /etc/login.defs \
    /etc/security/limits.conf \
    /etc/sysctl.conf

# 6. SYSTEM BINARIES AND ADMINISTRATIVE DIRECTORIES

harden_paths root:root 755 \
    /bin \
    /sbin \
    /usr/bin \
    /usr/sbin \
    /usr/local/bin \
    /usr/local/sbin \
    /usr/local/etc

# 7. TEMPORARY DIRECTORIES

harden_paths root:root 1777 \
    /tmp \
    /var/tmp \
    /dev/shm

# 8. LOG FILES (DEBIAN/UBUNTU EXAMPLES)

harden_paths root:root 755 /var/log

harden_paths root:adm 640 /var/log/auth.log

harden_paths syslog:adm 640 \
    /var/log/syslog \
    /var/log/kern.log

harden_paths root:utmp 664 \
    /var/log/wtmp \
    /var/log/lastlog

harden_paths root:utmp 640 /var/log/btmp

harden_paths root:root 750 /var/log/audit

harden_paths root:root 600 /var/log/audit/audit.log

# 9. ROOT AND USER HOME DIRECTORIES

harden_paths root:root 700 /root

for user in /home/*
do
    [ -d "$user" ] || continue

    chmod 700 "$user" || echo "[ERROR] Failed chmod: $user"

    if [ -d "$user/.ssh" ]; then
        chmod 700 "$user/.ssh"

        for file in authorized_keys id_rsa id_ed25519
        do
            if [ -f "$user/.ssh/$file" ]; then
                chmod 600 "$user/.ssh/$file"
            fi
        done

        for file in id_rsa.pub id_ed25519.pub
        do
            if [ -f "$user/.ssh/$file" ]; then
                chmod 644 "$user/.ssh/$file"
            fi
        done
    fi

    for file in .bashrc .profile
    do
        if [ -f "$user/$file" ]; then
            chmod 644 "$user/$file"
        fi
    done
done

echo
echo "CCDC permission baseline commands completed."

# ==========================================
# AUDIT DIRECTORY LIST
# ==========================================

# POSIX shell: use a regular word list instead of arrays.

DIRECTORIES="
/etc
/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin
/boot
/root
/home
/opt
/var/spool
/var/www
/tmp
/var/tmp
/dev/shm
"

# ==========================================
# 2. SUID AUDIT
# ==========================================

echo
echo "========== SUID AUDIT =========="

for DIR in $DIRECTORIES
do
    [ -d "$DIR" ] || continue

    find "$DIR" -xdev -type f -perm -4000 \
        -exec sh -c '
            for FILE do
                case "$FILE" in
                    /usr/bin/passwd|\
                    /usr/bin/su|\
                    /usr/bin/sudo|\
                    /usr/bin/mount|\
                    /usr/bin/umount|\
                    /usr/bin/chsh|\
                    /usr/bin/chfn|\
                    /usr/bin/newgrp|\
                    /usr/bin/gpasswd|\
                    /usr/bin/pkexec|\
                    /usr/bin/fusermount|\
                    /usr/bin/fusermount3|\
                    /usr/lib/openssh/ssh-keysign)
                        ;;
                    *)
                        echo "[WARNING] Unexpected SUID: $FILE"
                        stat -c "Owner: %U:%G | Permissions: %a" "$FILE"
                        ;;
                esac
            done
        ' sh {} + 
done

# ==========================================
# 3. WORLD-WRITABLE FILE AUDIT
# ==========================================

echo
echo "========== WORLD-WRITABLE FILE AUDIT =========="

for DIR in $DIRECTORIES
do
    [ -d "$DIR" ] || continue

    find "$DIR" -xdev -type f -perm -0002 \
        -exec sh -c '
            for FILE do
                stat -c "[WARNING] %A %U:%G %n" "$FILE"
            done
        ' sh {} +
done

# ==========================================
# SCRIPT COMPLETE
# ==========================================

echo
echo "=========================================="
echo "CCDC PERMISSION HARDENING AND AUDITS DONE"
echo "=========================================="

