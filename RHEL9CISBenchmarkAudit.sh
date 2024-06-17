#!/bin/bash

# CIS Red Hat Enterprise Linux 9 Benchmark v1.0.0 - 11-28-2022

# 1 Initial Setup
echo "1 Initial Setup"

# 1.1 Filesystem Configuration
echo "1.1 Filesystem Configuration"

# 1.1.1 Disable unused filesystems
disabled_filesystems=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "vfat")
for fs in "${disabled_filesystems[@]}"
do
    if modprobe -n -v $fs 2>&1 | grep -q "install /bin/true"; then
        echo "$fs is disabled - PASS"
    else
        echo "$fs is not disabled - FAIL"
    fi
done

# 1.1.1.1 Ensure mounting of squashfs filesystems is disabled (Automated)
if grep -q "squashfs" /etc/modprobe.d/* /etc/modprobe.d/*; then
    echo "squashfs is disabled - PASS"
else
    echo "squashfs is not disabled - FAIL"
fi

# 1.1.1.2 Ensure mounting of udf filesystems is disabled (Automated)
if grep -q "udf" /etc/modprobe.d/* /etc/modprobe.d/*; then
    echo "udf is disabled - PASS"
else
    echo "udf is not disabled - FAIL"
fi

# 1.1.2 Configure /tmp

# 1.1.2.1 Ensure /tmp is a separate partition (Automated)
if mount | grep " /tmp " | grep -q "/tmp"; then
    echo "/tmp is a separate partition - PASS"
else
    echo "/tmp is not a separate partition - FAIL"
fi

# 1.1.2.2 Ensure nodev option set on /tmp partition (Automated)
if mount | grep " /tmp " | grep -q "nodev"; then
    echo "nodev option set on /tmp partition - PASS"
else
    echo "nodev option not set on /tmp partition - FAIL"
fi

# 1.1.2.3 Ensure noexec option set on /tmp partition (Automated)
if mount | grep " /tmp " | grep -q "noexec"; then
    echo "noexec option set on /tmp partition - PASS"
else
    echo "noexec option not set on /tmp partition - FAIL"
fi

# 1.1.2.4 Ensure nosuid option set on /tmp partition (Automated)
if mount | grep " /tmp " | grep -q "nosuid"; then
    echo "nosuid option set on /tmp partition - PASS"
else
    echo "nosuid option not set on /tmp partition - FAIL"
fi

# 1.1.3 Configure /var

# 1.1.3.1 Ensure separate partition exists for /var (Automated)
if mount | grep " /var " | grep -q "/var"; then
    echo "/var is a separate partition - PASS"
else
    echo "/var is not a separate partition - FAIL"
fi

# 1.1.3.2 Ensure nodev option set on /var partition (Automated)
if mount | grep " /var " | grep -q "nodev"; then
    echo "nodev option set on /var partition - PASS"
else
    echo "nodev option not set on /var partition - FAIL"
fi

# 1.1.3.3 Ensure nosuid option set on /var partition (Automated)
if mount | grep " /var " | grep -q "nosuid"; then
    echo "nosuid option set on /var partition - PASS"
else
    echo "nosuid option not set on /var partition - FAIL"
fi

# 1.1.4 Configure /var/tmp
# 1.1.4.1 Ensure separate partition exists for /var/tmp (Automated)
if mount | grep " /var/tmp " | grep -q "/var/tmp"; then
    echo "/var/tmp is a separate partition - PASS"
else
    echo "/var/tmp is not a separate partition - FAIL"
fi

# 1.1.4.2 Ensure noexec option set on /var/tmp partition (Automated)
if mount | grep " /var/tmp " | grep -q "noexec"; then
    echo "noexec option set on /var/tmp partition - PASS"
else
    echo "noexec option not set on /var/tmp partition - FAIL"
fi

# 1.1.4.3 Ensure nosuid option set on /var/tmp partition (Automated)
if mount | grep " /var/tmp " | grep -q "nosuid"; then
    echo "nosuid option set on /var/tmp partition - PASS"
else
    echo "nosuid option not set on /var/tmp partition - FAIL"
fi

# 1.1.4.4 Ensure nodev option set on /var/tmp partition (Automated)
if mount | grep " /var/tmp " | grep -q "nodev"; then
    echo "nodev option set on /var/tmp partition - PASS"
else
    echo "nodev option not set on /var/tmp partition - FAIL"
fi

# 1.1.5 Configure /var/log
# 1.1.5.1 Ensure separate partition exists for /var/log (Automated)
if mount | grep " /var/log " | grep -q "/var/log"; then
    echo "/var/log is a separate partition - PASS"
else
    echo "/var/log is not a separate partition - FAIL"
fi

# 1.1.5.2 Ensure nodev option set on /var/log partition (Automated)
if mount | grep " /var/log " | grep -q "nodev"; then
    echo "nodev option set on /var/log partition - PASS"
else
    echo "nodev option not set on /var/log partition - FAIL"
fi

# 1.1.5.3 Ensure noexec option set on /var/log partition (Automated)
if mount | grep " /var/log " | grep -q "noexec"; then
    echo "noexec option set on /var/log partition - PASS"
else
    echo "noexec option not set on /var/log partition - FAIL"
fi

# 1.1.5.4 Ensure nosuid option set on /var/log partition (Automated)
if mount | grep " /var/log " | grep -q "nosuid"; then
    echo "nosuid option set on /var/log partition - PASS"
else
    echo "nosuid option not set on /var/log partition - FAIL"
fi

# 1.1.6 Configure /var/log/audit
# 1.1.6.1 Ensure separate partition exists for /var/log/audit (Automated)
if mount | grep " /var/log/audit " | grep -q "/var/log/audit"; then
    echo "/var/log/audit is a separate partition - PASS"
else
    echo "/var/log/audit is not a separate partition - FAIL"
fi

# 1.1.6.2 Ensure noexec option set on /var/log/audit partition (Automated)
if mount | grep " /var/log/audit " | grep -q "noexec"; then
    echo "noexec option set on /var/log/audit partition - PASS"
else
    echo "noexec option not set on /var/log/audit partition - FAIL"
fi

# 1.1.6.3 Ensure nodev option set on /var/log/audit partition (Automated)
if mount | grep " /var/log/audit " | grep -q "nodev"; then
    echo "nodev option set on /var/log/audit partition - PASS"
else
    echo "nodev option not set on /var/log/audit partition - FAIL"
fi

# 1.1.6.4 Ensure nosuid option set on /var/log/audit partition (Automated)
if mount | grep " /var/log/audit " | grep -q "nosuid"; then
    echo "nosuid option set on /var/log/audit partition - PASS"
else
    echo "nosuid option not set on /var/log/audit partition - FAIL"
fi

# 1.1.7 Configure /home
# 1.1.7.1 Ensure separate partition exists for /home (Automated)
if mount | grep " /home " | grep -q "/home"; then
    echo "/home is a separate partition - PASS"
else
    echo "/home is not a separate partition - FAIL"
fi

# 1.1.7.2 Ensure nodev option set on /home partition (Automated)
if mount | grep " /home " | grep -q "nodev"; then
    echo "nodev option set on /home partition - PASS"
else
    echo "nodev option not set on /home partition - FAIL"
fi

# 1.1.7.3 Ensure nosuid option set on /home partition (Automated)
if mount | grep " /home " | grep -q "nosuid"; then
    echo "nosuid option set on /home partition - PASS"
else
    echo "nosuid option not set on /home partition - FAIL"
fi

# 1.1.8 Configure /dev/shm
# 1.1.8.1 Ensure /dev/shm is a separate partition (Automated)
if mount | grep " /dev/shm " | grep -q "/dev/shm"; then
    echo "/dev/shm is a separate partition - PASS"
else
    echo "/dev/shm is not a separate partition - FAIL"
fi

# 1.1.8.2 Ensure nodev option set on /dev/shm partition (Automated)
if mount | grep " /dev/shm " | grep -q "nodev"; then
    echo "nodev option set on /dev/shm partition - PASS"
else
    echo "nodev option not set on /dev/shm partition - FAIL"
fi

# 1.1.8.3 Ensure noexec option set on /dev/shm partition (Automated)
if mount | grep " /dev/shm " | grep -q "noexec"; then
    echo "noexec option set on /dev/shm partition - PASS"
else
    echo "noexec option not set on /dev/shm partition - FAIL"
fi

# 1.1.8.4 Ensure nosuid option set on /dev/shm partition (Automated)
if mount | grep " /dev/shm " | grep -q "nosuid"; then
    echo "nosuid option set on /dev/shm partition - PASS"
else
    echo "nosuid option not set on /dev/shm partition - FAIL"
fi

# 1.1.9 Disable USB Storage (Automated)
if modprobe -n -v usb-storage 2>&1 | grep -q "install /bin/true"; then
    echo "USB Storage is disabled - PASS"
else
    echo "USB Storage is not disabled - FAIL"
fi

# 1.2 Configure Software Updates
# 1.2.1 Ensure GPG keys are configured (Manual)
if rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n' | grep -q "is not installed"; then
    echo "GPG keys are not configured - FAIL"
else
    echo "GPG keys are configured - PASS"
fi

# 1.2.2 Ensure gpgcheck is globally activated (Automated)
if grep -q "gpgcheck=1" /etc/yum.conf /etc/yum.repos.d/*; then
    echo "gpgcheck is globally activated - PASS"
else
    echo "gpgcheck is not globally activated - FAIL"
fi

# 1.2.3 Ensure package manager repositories are configured (Manual)
if [ -f /etc/yum.repos.d/redhat.repo ]; then
    echo "Package manager repositories are configured - PASS"
else
    echo "Package manager repositories are not configured - FAIL"
fi

# 1.2.4 Ensure repo_gpgcheck is globally activated (Manual)
if grep -q "repo_gpgcheck=1" /etc/yum.conf /etc/yum.repos.d/*; then
    echo "repo_gpgcheck is globally activated - PASS"
else
    echo "repo_gpgcheck is not globally activated - FAIL"
fi

# 1.3 Filesystem Integrity Checking
# 1.3.1 Ensure AIDE is installed (Automated)
if rpm -q aide 2>&1 | grep -q "not installed"; then
    echo "AIDE is not installed - FAIL"
else
    echo "AIDE is installed - PASS"
fi

# 1.3.2 Ensure filesystem integrity is regularly checked (Automated)
if [ -e /etc/cron.daily/aide ]; then
    echo "Filesystem integrity is regularly checked - PASS"
else
    echo "Filesystem integrity is not regularly checked - FAIL"
fi

# 1.3.3 Ensure cryptographic mechanisms are used to protect the integrity of audit tools (Automated)
if sha512sum /sbin/aide | grep -q "aide"; then
    echo "Cryptographic mechanisms are used to protect the integrity of audit tools - PASS"
else
    echo "Cryptographic mechanisms are not used to protect the integrity of audit tools - FAIL"
fi

# 1.4 Secure Boot Settings
# 1.4.1 Ensure bootloader password is set (Automated)
if grep -q "password --md5" /boot/grub2/grub.cfg /etc/grub2.cfg /boot/grub/grub.cfg /etc/grub.cfg; then
    echo "Bootloader password is set - PASS"
else
    echo "Bootloader password is not set - FAIL"
fi

# 1.4.2 Ensure permissions on bootloader config are configured (Automated)
if stat -L -c "%a %u %g" /boot/grub2/grub.cfg | grep -q "600 0 0"; then
    echo "Permissions on bootloader config are configured correctly - PASS"
else
    echo "Permissions on bootloader config are not configured correctly - FAIL"
fi

# 1.5 Additional Process Hardening
# 1.5.1 Ensure core dump storage is disabled (Automated)
if [ "$(sysctl fs.suid_dumpable)" -eq 0 ]; then
    echo "Core dump storage is disabled - PASS"
else
    echo "Core dump storage is not disabled - FAIL"
fi

# 1.5.2 Ensure core dump backtraces are disabled (Automated)
if [ "$(sysctl kernel.randomize_va_space)" -eq 2 ]; then
    echo "Core dump backtraces are disabled - PASS"
else
    echo "Core dump backtraces are not disabled - FAIL"
fi

# 1.5.3 Ensure address space layout randomization (ASLR) is enabled (Automated)
if [ "$(sysctl kernel.randomize_va_space)" -eq 2 ]; then
    echo "ASLR is enabled - PASS"
else
    echo "ASLR is not enabled - FAIL"
fi

# 1.6 Mandatory Access Control
# 1.6.1 Configure SELinux
# 1.6.1.1 Ensure SELinux is installed (Automated)
if rpm -q libselinux-utils 2>&1 | grep -q "not installed"; then
    echo "SELinux is not installed - FAIL"
else
    echo "SELinux is installed - PASS"
fi

# 1.6.1.2 Ensure SELinux is not disabled in bootloader configuration (Automated)
if grep "^\s*kernel" /boot/grub2/grub.cfg /etc/default/grub /boot/grub/grub.cfg | grep -q "selinux=0"; then
    echo "SELinux is not disabled in bootloader configuration - PASS"
else
    echo "SELinux is disabled in bootloader configuration - FAIL"
fi

# 1.6.1.3 Ensure SELinux policy is configured (Automated)
if [ "$(sestatus | grep "Current mode" | awk '{print $3}')" == "enforcing" ]; then
    echo "SELinux policy is configured - PASS"
else
    echo "SELinux policy is not configured - FAIL"
fi

# 1.6.1.4 Ensure the SELinux mode is not disabled (Automated)
if [ "$(sestatus | grep "Mode from config file" | awk '{print $4}')" == "enforcing" ]; then
    echo "SELinux mode is not disabled - PASS"
else
    echo "SELinux mode is disabled - FAIL"
fi

# 1.6.1.5 Ensure the SELinux mode is enforcing (Automated)
if [ "$(sestatus | grep "SELinux status" | awk '{print $3}')" == "enabled" ]; then
    echo "SELinux mode is enforcing - PASS"
else
    echo "SELinux mode is not enforcing - FAIL"
fi

# 1.6.1.6 Ensure no unconfined services exist (Automated)
if [ "$(ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' | grep -v "^unconfined_t$")" == "" ]; then
    echo "No unconfined services exist - PASS"
else
    echo "Unconfined services exist - FAIL"
fi

# 1.6.1.7 Ensure SETroubleshoot is not installed (Automated)
if rpm -q setroubleshoot 2>&1 | grep -q "not installed"; then
    echo "SETroubleshoot is not installed - PASS"
else
    echo "SETroubleshoot is installed - FAIL"
fi

# 1.6.1.8 Ensure the MCS Translation Service (mcstrans) is not installed (Automated)
if rpm -q mcstrans 2>&1 | grep -q "not installed"; then
    echo "The MCS Translation Service (mcstrans) is not installed - PASS"
else
    echo "The MCS Translation Service (mcstrans) is installed - FAIL"
fi

# 1.7 Command Line Warning Banners
# 1.7.1 Ensure message of the day is configured properly (Automated)
motd="/etc/motd"
if [ -f "$motd" ] && [ "$(stat -c %a $motd)" -eq 644 ]; then
    echo "Message of the day is configured properly - PASS"
else
    echo "Message of the day is not configured properly - FAIL"
fi

# 1.7.2 Ensure local login warning banner is configured properly (Automated)
issue="/etc/issue"
if [ -f "$issue" ] && [ "$(stat -c %a $issue)" -eq 644 ]; then
    echo "Local login warning banner is configured properly - PASS"
else
    echo "Local login warning banner is not configured properly - FAIL"
fi

# 1.7.3 Ensure remote login warning banner is configured properly (Automated)
issue_net="/etc/issue.net"
if [ -f "$issue_net" ] && [ "$(stat -c %a $issue_net)" -eq 644 ]; then
    echo "Remote login warning banner is configured properly - PASS"
else
    echo "Remote login warning banner is not configured properly - FAIL"
fi

# 1.7.4 Ensure permissions on /etc/motd are configured (Automated)
if [ "$(stat -c %a /etc/motd)" -eq 644 ]; then
    echo "Permissions on /etc/motd are configured - PASS"
else
    echo "Permissions on /etc/motd are not configured - FAIL"
fi

# 1.7.5 Ensure permissions on /etc/issue are configured (Automated)
if [ "$(stat -c %a /etc/issue)" -eq 644 ]; then
    echo "Permissions on /etc/issue are configured - PASS"
else
    echo "Permissions on /etc/issue are not configured - FAIL"
fi

# 1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)
if [ "$(stat -c %a /etc/issue.net)" -eq 644 ]; then
    echo "Permissions on /etc/issue.net are configured - PASS"
else
    echo "Permissions on /etc/issue.net are not configured - FAIL"
fi

# 1.8 GNOME Display Manager
# 1.8.1 Ensure GNOME Display Manager is removed (Automated)
if ! rpm -q gdm &>/dev/null; then
    echo "GNOME Display Manager is removed - PASS"
else
    echo "GNOME Display Manager is not removed - FAIL"
fi

# 1.8.2 Ensure GDM login banner is configured (Automated)
if [ -f /etc/dconf/profile/gdm ]; then
    if [ "$(grep -E '^\[org/gnome/login-screen\]$' /etc/dconf/profile/gdm)" != "" ]; then
        if [ "$(grep -E '^\[org/gnome/login-screen\]$' /etc/dconf/db/gdm.d/00-banner-message)" != "" ]; then
            echo "GDM login banner is configured - PASS"
        else
            echo "GDM login banner is not configured - FAIL"
        fi
    else
        echo "GDM login banner is not configured - FAIL"
    fi
else
    echo "GDM login banner is not configured - FAIL"
fi

# 1.8.3 Ensure GDM disable-user-list option is enabled (Automated)
if [ "$(grep -E '^\[org/gnome/login-screen\]$' /etc/dconf/db/gdm.d/00-banner-message | grep disable-user-list | awk -F= '{print $2}' | tr -d ' ')" == "true" ]; then
    echo "GDM disable-user-list option is enabled - PASS"
else
    echo "GDM disable-user-list option is not enabled - FAIL"
fi

# 1.8.4 Ensure GDM screen locks when the user is idle (Automated)
if [ "$(grep -E '^\[org/gnome/desktop/session\]$' /etc/dconf/db/gdm.d/00-banner-message | grep idle-delay | awk -F= '{print $2}' | tr -d ' ')" -gt 0 ]; then
    echo "GDM screen locks when the user is idle - PASS"
else
    echo "GDM screen locks when the user is not idle - FAIL"
fi

# 1.8.5 Ensure GDM screen locks cannot be overridden (Automated)
if [ "$(grep -E '^\[org/gnome/desktop/screensaver\]$' /etc/dconf/db/gdm.d/00-banner-message | grep 'user-admin' | awk -F= '{print $2}' | tr -d ' ')" == "false" ]; then
    echo "GDM screen locks cannot be overridden - PASS"
else
    echo "GDM screen locks can be overridden - FAIL"
fi

# 1.8.6 Ensure GDM automatic mounting of removable media is disabled (Automated)
if [ "$(grep -E '^\[org/gnome/desktop/media-handling\]$' /etc/dconf/db/gdm.d/00-banner-message | grep 'automount' | awk -F= '{print $2}' | tr -d ' ')" == "false" ]; then
    echo "GDM automatic mounting of removable media is disabled - PASS"
else
    echo "GDM automatic mounting of removable media is not disabled - FAIL"
fi

# 1.8.7 Ensure GDM disabling automatic mounting of removable media is not overridden (Automated)
if [ "$(grep -E '^\[org/gnome/desktop/media-handling\]$' /etc/dconf/db/gdm.d/00-banner-message | grep 'automount-open' | awk -F= '{print $2}' | tr -d ' ')" == "false" ]; then
    echo "GDM disabling automatic mounting of removable media is not overridden - PASS"
else
    echo "GDM disabling automatic mounting of removable media is overridden - FAIL"
fi

# 1.8.8 Ensure GDM autorun-never is enabled (Automated)
if [ "$(grep -E '^\[org/gnome/desktop/media-handling\]$' /etc/dconf/db/gdm.d/00-banner-message | grep 'autorun-never' | awk -F= '{print $2}' | tr -d ' ')" == "true" ]; then
    echo "GDM autorun-never is enabled - PASS"
else
    echo "GDM autorun-never is not enabled - FAIL"
fi

# 1.8.9 Ensure GDM autorun-never is not overridden (Automated)
if [ "$(grep -E '^\[org/gnome/desktop/media-handling\]$' /etc/dconf/db/gdm.d/00-banner-message | grep 'autorun-never' | awk -F= '{print $2}' | tr -d ' ')" == "true" ]; then
    echo "GDM autorun-never is not overridden - PASS"
else
    echo "GDM autorun-never is overridden - FAIL"
fi

# 1.8.10 Ensure XDCMP is not enabled (Automated)
if [ "$(grep -E '^\[xdmcp\]$' /etc/gdm/custom.conf | grep Enable | awk -F= '{print $2}' | tr -d ' ')" == "false" ]; then
    echo "XDCMP is not enabled - PASS"
else
    echo "XDCMP is enabled - FAIL"
fi

# 1.10 Ensure system-wide crypto policy is not legacy (Automated)
crypto_policy=$(update-crypto-policies --show)
if [[ "$crypto_policy" == *"LEGACY"* ]]; then
    echo "System-wide crypto policy is legacy - FAIL"
else
    echo "System-wide crypto policy is not legacy - PASS"
fi

# 2 Services
# 2.1 Time Synchronization
# 2.1.1 Ensure time synchronization is in use (Automated)
if systemctl is-enabled chronyd &>/dev/null; then
    echo "Time synchronization is in use - PASS"
else
    echo "Time synchronization is not in use - FAIL"
fi

# 2.1.2 Ensure chrony is configured (Automated)
if grep -q "^server" /etc/chrony.conf; then
    echo "chrony is configured - PASS"
else
    echo "chrony is not configured - FAIL"
fi

# 2.2 Special Purpose Services
# 2.2.1 Ensure xorg-x11-server-common is not installed (Automated)
if ! rpm -q xorg-x11-server-common &>/dev/null; then
    echo "xorg-x11-server-common is not installed - PASS"
else
    echo "xorg-x11-server-common is installed - FAIL"
fi

# 2.2.2 Ensure Avahi Server is not installed (Automated)
if ! rpm -q avahi &>/dev/null; then
    echo "Avahi Server is not installed - PASS"
else
    echo "Avahi Server is installed - FAIL"
fi

# 2.2.3 Ensure CUPS is not installed (Automated)
if ! rpm -q cups &>/dev/null; then
    echo "CUPS is not installed - PASS"
else
    echo "CUPS is installed - FAIL"
fi

# 2.2.4 Ensure DHCP Server is not installed (Automated)
if ! rpm -q dhcp-server &>/dev/null; then
    echo "DHCP Server is not installed - PASS"
else
    echo "DHCP Server is installed - FAIL"
fi

# 2.2.5 Ensure DNS Server is not installed (Automated)
if ! rpm -q bind &>/dev/null; then
    echo "DNS Server is not installed - PASS"
else
    echo "DNS Server is installed - FAIL"
fi

# 2.2.6 Ensure VSFTP Server is not installed (Automated)
if ! rpm -q vsftpd &>/dev/null; then
    echo "VSFTP Server is not installed - PASS"
else
    echo "VSFTP Server is installed - FAIL"
fi

# 2.2.7 Ensure TFTP Server is not installed (Automated)
if ! rpm -q tftp &>/dev/null; then
    echo "TFTP Server is not installed - PASS"
else
    echo "TFTP Server is installed - FAIL"
fi

# 2.2.8 Ensure a web server is not installed (Automated)
if ! rpm -q httpd &>/dev/null; then
    echo "Web Server is not installed - PASS"
else
    echo "Web Server is installed - FAIL"
fi

# 2.2.9 Ensure IMAP and POP3 server is not installed (Automated)
if ! rpm -q dovecot &>/dev/null; then
    echo "IMAP and POP3 Server is not installed - PASS"
else
    echo "IMAP and POP3 Server is installed - FAIL"
fi

# 2.2.10 Ensure Samba is not installed (Automated)
if ! rpm -q samba &>/dev/null; then
    echo "Samba is not installed - PASS"
else
    echo "Samba is installed - FAIL"
fi

# 2.2.11 Ensure HTTP Proxy Server is not installed (Automated)
if ! rpm -q squid &>/dev/null; then
    echo "HTTP Proxy Server is not installed - PASS"
else
    echo "HTTP Proxy Server is installed - FAIL"
fi

# 2.2.12 Ensure net-snmp is not installed (Automated)
if ! rpm -q net-snmp &>/dev/null; then
    echo "net-snmp is not installed - PASS"
else
    echo "net-snmp is installed - FAIL"
fi

# 2.2.13 Ensure telnet-server is not installed (Automated)
if ! rpm -q telnet-server &>/dev/null; then
    echo "telnet-server is not installed - PASS"
else
    echo "telnet-server is installed - FAIL"
fi

# 2.2.14 Ensure dnsmasq is not installed (Automated)
if ! rpm -q dnsmasq &>/dev/null; then
    echo "dnsmasq is not installed - PASS"
else
    echo "dnsmasq is installed - FAIL"
fi

# 2.2.15 Ensure mail transfer agent is configured for local-only mode (Automated)
if grep -q "^inet_interfaces = localhost" /etc/postfix/main.cf; then
    echo "Mail transfer agent is configured for local-only mode - PASS"
else
    echo "Mail transfer agent is not configured for local-only mode - FAIL"
fi

# 2.2.16 Ensure nfs-utils is not installed or the nfs-server service is masked (Automated)
if ! rpm -q nfs-utils &>/dev/null || systemctl is-enabled nfs-server &>/dev/null; then
    echo "nfs-utils is not installed or the nfs-server service is masked - PASS"
else
    echo "nfs-utils is installed or the nfs-server service is not masked - FAIL"
fi

# 2.2.17 Ensure rpcbind is not installed or the rpcbind services are masked (Automated)
if ! rpm -q rpcbind &>/dev/null || systemctl is-enabled rpcbind &>/dev/null; then
    echo "rpcbind is not installed or the rpcbind services are masked - PASS"
else
    echo "rpcbind is installed or the rpcbind services are not masked - FAIL"
fi

# 2.2.18 Ensure rsync-daemon is not installed or the rsyncd service is masked (Automated)
if ! rpm -q rsync-daemon &>/dev/null || systemctl is-enabled rsyncd &>/dev/null; then
    echo "rsync-daemon is not installed or the rsyncd service is masked - PASS"
else
    echo "rsync-daemon is installed or the rsyncd service is not masked - FAIL"
fi

# 2.3 Service Clients
# 2.3.1 Ensure telnet client is not installed (Automated)
if ! rpm -q telnet &>/dev/null; then
    echo "telnet client is not installed - PASS"
else
    echo "telnet client is installed - FAIL"
fi

# 2.3.2 Ensure LDAP client is not installed (Automated)
if ! rpm -q openldap-clients &>/dev/null; then
    echo "LDAP client is not installed - PASS"
else
    echo "LDAP client is installed - FAIL"
fi

# 2.3.3 Ensure TFTP client is not installed (Automated)
if ! rpm -q tftp &>/dev/null; then
    echo "TFTP client is not installed - PASS"
else
    echo "TFTP client is installed - FAIL"
fi

# 2.3.4 Ensure FTP client is not installed (Automated)
if ! rpm -q ftp &>/dev/null; then
    echo "FTP client is not installed - PASS"
else
    echo "FTP client is installed - FAIL"
fi

# 3 Network Configuration
# 3.1 Disable unused network protocols and devices
# 3.1.1 Ensure IPv6 status is identified (Manual)
if grep -q "^NETWORKING_IPV6=" /etc/sysconfig/network; then
    echo "IPv6 is disabled - PASS"
else
    echo "IPv6 is not disabled - FAIL"
fi

# 3.1.2 Ensure wireless interfaces are disabled (Automated)
if rfkill list wifi | grep -q "Soft blocked: yes"; then
    echo "Wireless interfaces are disabled - PASS"
else
    echo "Wireless interfaces are not disabled - FAIL"
fi

# 3.1.3 Ensure TIPC is disabled (Automated)
if ! modprobe -n -v tipc | grep -q "install /bin/true"; then
    echo "TIPC is disabled - PASS"
else
    echo "TIPC is not disabled - FAIL"
fi

# 3.2 Network Parameters (Host Only)
# 3.2.1 Ensure IP forwarding is disabled (Automated)
if ! sysctl net.ipv4.ip_forward | grep -q "net.ipv4.ip_forward = 0"; then
    echo "IP forwarding is disabled - PASS"
else
    echo "IP forwarding is not disabled - FAIL"
fi

# 3.2.2 Ensure packet redirect sending is disabled (Automated)
if ! sysctl net.ipv4.conf.all.send_redirects | grep -q "net.ipv4.conf.all.send_redirects = 0"; then
    echo "Packet redirect sending is disabled - PASS"
else
    echo "Packet redirect sending is not disabled - FAIL"
fi

# 3.3 Network Parameters (Host and Router)
# 3.3.1 Ensure source routed packets are not accepted (Automated)
if ! sysctl net.ipv4.conf.all.accept_source_route | grep -q "net.ipv4.conf.all.accept_source_route = 0"; then
    echo "Source routed packets are not accepted - PASS"
else
    echo "Source routed packets are accepted - FAIL"
fi

# 3.3.2 Ensure ICMP redirects are not accepted (Automated)
if ! sysctl net.ipv4.conf.all.accept_redirects | grep -q "net.ipv4.conf.all.accept_redirects = 0"; then
    echo "ICMP redirects are not accepted - FAIL"
else
    echo "ICMP redirects are not accepted - PASS"
fi

# 3.3.3 Ensure secure ICMP redirects are not accepted (Automated)
if ! sysctl net.ipv4.conf.all.secure_redirects | grep -q "net.ipv4.conf.all.secure_redirects = 0"; then
    echo "Secure ICMP redirects are not accepted - FAIL"
else
    echo "Secure ICMP redirects are not accepted - PASS"
fi

# 3.3.4 Ensure suspicious packets are logged (Automated)
if ! sysctl net.ipv4.conf.all.log_martians | grep -q "net.ipv4.conf.all.log_martians = 1"; then
    echo "Suspicious packets are not logged - FAIL"
else
    echo "Suspicious packets are logged - PASS"
fi

# 3.3.5 Ensure broadcast ICMP requests are ignored (Automated)
if ! sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -q "net.ipv4.icmp_echo_ignore_broadcasts = 1"; then
    echo "Broadcast ICMP requests are not ignored - FAIL"
else
    echo "Broadcast ICMP requests are ignored - PASS"
fi

# 3.3.6 Ensure bogus ICMP responses are ignored (Automated)
if ! sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep -q "net.ipv4.icmp_ignore_bogus_error_responses = 1"; then
    echo "Bogus ICMP responses are not ignored - FAIL"
else
    echo "Bogus ICMP responses are ignored - PASS"
fi

# 3.3.7 Ensure Reverse Path Filtering is enabled (Automated)
if ! sysctl net.ipv4.conf.all.rp_filter | grep -q "net.ipv4.conf.all.rp_filter = 1"; then
    echo "Reverse Path Filtering is not enabled - FAIL"
else
    echo "Reverse Path Filtering is enabled - PASS"
fi

# 3.3.8 Ensure TCP SYN Cookies is enabled (Automated)
if ! sysctl net.ipv4.tcp_syncookies | grep -q "net.ipv4.tcp_syncookies = 1"; then
    echo "TCP SYN Cookies is not enabled - FAIL"
else
    echo "TCP SYN Cookies is enabled - PASS"
fi

# 3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)
if ! sysctl net.ipv6.conf.all.accept_ra | grep -q "net.ipv6.conf.all.accept_ra = 0"; then
    echo "IPv6 router advertisements are not accepted - FAIL"
else
    echo "IPv6 router advertisements are not accepted - PASS"
fi

# 3.4 Configure Host Based Firewall
# 3.4.1 Configure a firewall utility
# 3.4.1.1 Ensure nftables is installed (Automated)
if ! rpm -q nftables; then
    echo "nftables is not installed - FAIL"
else
    echo "nftables is installed - PASS"
fi

# 3.4.1.2 Ensure a single firewall configuration utility is in use (Automated)
if ! alternatives --display iptables | grep -q "/usr/sbin/nft"; then
    echo "nftables is not the active firewall configuration utility - FAIL"
else
    echo "nftables is the active firewall configuration utility - PASS"
fi

# 3.4.2 Configure firewall rules
# 3.4.2.1 Ensure firewalld default zone is set (Automated)
if ! firewall-cmd --get-default-zone | grep -q "public"; then
    echo "Default zone is not set to public - FAIL"
else
    echo "Default zone is set to public - PASS"
fi

# 3.4.2.2 Ensure at least one nftables table exists (Automated)
if ! nft list tables | grep -q "table ip"; then
    echo "No nftables tables found - FAIL"
else
    echo "At least one nftables table exists - PASS"
fi

# 3.4.2.3 Ensure nftables base chains exist (Automated)
if ! nft list ruleset | grep -q "chain"; then
    echo "No nftables base chains found - FAIL"
else
    echo "nftables base chains exist - PASS"
fi

# 3.4.2.4 Ensure host based firewall loopback traffic is configured (Automated)
if ! iptables -L INPUT -v -n | grep -q "127.0.0.0/8"; then
    echo "Loopback traffic is not configured - FAIL"
else
    echo "Loopback traffic is configured - PASS"
fi

# 3.4.2.5 Ensure firewalld drops unnecessary services and ports (Manual)
if firewall-cmd --list-all | grep -q "services: "; then
    echo "Unnecessary services and ports are not dropped - FAIL"
else
    echo "Unnecessary services and ports are dropped - PASS"
fi

# 3.4.2.6 Ensure nftables established connections are configured (Manual)
if ! nft list ruleset | grep -q "ct state established,related accept"; then
    echo "nftables established connections are not configured - FAIL"
else
    echo "nftables established connections are configured - PASS"
fi

# 3.4.2.7 Ensure nftables default deny firewall policy (Automated)
if ! nft list ruleset | grep -q "hook input priority 0; policy drop"; then
    echo "nftables default deny firewall policy is not set - FAIL"
else
    echo "nftables default deny firewall policy is set - PASS"
fi

# 4 Logging and Auditing
# 4.1 Configure System Accounting (auditd)
# 4.1.1 Ensure auditing is enabled
# 4.1.1.1 Ensure auditd is installed (Automated)
if ! rpm -q audit; then
    echo "auditd is not installed - FAIL"
else
    echo "auditd is installed - PASS"
fi

# 4.1.1.2 Ensure auditing for processes that start prior to auditd is enabled (Automated)
if ! grep -q "^kernel.*audit=1" /boot/grub2/grub.cfg /etc/default/grub; then
    echo "Auditing for processes that start prior to auditd is not enabled - FAIL"
else
    echo "Auditing for processes that start prior to auditd is enabled - PASS"
fi

# 4.1.1.3 Ensure audit_backlog_limit is sufficient (Automated)
if ! grep -q "^[[:space:]]*audit_backlog_limit" /etc/audit/auditd.conf; then
    echo "audit_backlog_limit is not configured - FAIL"
else
    echo "audit_backlog_limit is configured - PASS"
fi

# 4.1.1.4 Ensure auditd service is enabled (Automated)
if ! systemctl is-enabled auditd | grep -q "enabled"; then
    echo "auditd service is not enabled - FAIL"
else
    echo "auditd service is enabled - PASS"
fi

# 4.1.2 Configure Data Retention
# 4.1.2.1 Ensure audit log storage size is configured (Automated)
if ! grep -q "max_log_file = [0-9]*" /etc/audit/auditd.conf; then
    echo "Audit log storage size is not configured - FAIL"
else
    echo "Audit log storage size is configured - PASS"
fi

# 4.1.2.2 Ensure audit logs are not automatically deleted (Automated)
if ! grep -q "max_log_file_action = ignore" /etc/audit/auditd.conf; then
    echo "Audit logs are automatically deleted - FAIL"
else
    echo "Audit logs are not automatically deleted - PASS"
fi

# 4.1.2.3 Ensure system is disabled when audit logs are full (Automated)
if ! grep -q "space_left_action = email" /etc/audit/auditd.conf; then
    echo "System is not disabled when audit logs are full - FAIL"
else
    echo "System is disabled when audit logs are full - PASS"
fi

# 4.1.3 Configure auditd rules
# 4.1.3.1 Ensure changes to system administration scope (sudoers) is collected (Automated)
if ! grep -q "sudoers" /etc/audit/rules.d/*.rules; then
    echo "Changes to system administration scope (sudoers) is not collected - FAIL"
else
    echo "Changes to system administration scope (sudoers) is collected - PASS"
fi

# 4.1.3.2 Ensure actions as another user are always logged (Automated)
if ! grep -q "fm=[0-9]*" /etc/audit/rules.d/*.rules; then
    echo "Actions as another user are not always logged - FAIL"
else
    echo "Actions as another user are always logged - PASS"
fi

# 4.1.3.3 Ensure events that modify the sudo log file are collected (Automated)
if ! grep -q "sudo.log" /etc/audit/rules.d/*.rules; then
    echo "Events that modify the sudo log file are not collected - FAIL"
else
    echo "Events that modify the sudo log file are collected - PASS"
fi

# 4.1.3.4 Ensure events that modify date and time information are collected (Automated)
if ! grep -q "time-change" /etc/audit/rules.d/*.rules; then
    echo "Events that modify date and time information are not collected - FAIL"
else
    echo "Events that modify date and time information are collected - PASS"
fi

# 4.1.3.5 Ensure events that modify the system's network environment are collected (Automated)
if ! grep -q "system-locale" /etc/audit/rules.d/*.rules; then
    echo "Events that modify the system's network environment are not collected - FAIL"
else
    echo "Events that modify the system's network environment are collected - PASS"
fi

# 4.1.3.6 Ensure use of privileged commands are collected (Automated)
if ! grep -q "privileged" /etc/audit/rules.d/*.rules; then
    echo "Use of privileged commands are not collected - FAIL"
else
    echo "Use of privileged commands are collected - PASS"
fi

# 4.1.3.7 Ensure unsuccessful file access attempts are collected (Automated)
if ! grep -q "access" /etc/audit/rules.d/*.rules; then
    echo "Unsuccessful file access attempts are not collected - FAIL"
else
    echo "Unsuccessful file access attempts are collected - PASS"
fi

# 4.1.3.8 Ensure events that modify user/group information are collected (Automated)
if ! grep -q "identity" /etc/audit/rules.d/*.rules; then
    echo "Events that modify user/group information are not collected - FAIL"
else
    echo "Events that modify user/group information are collected - PASS"
fi

# 4.1.3.9 Ensure discretionary access control permission modification events are collected (Automated)
if ! grep -q "dac" /etc/audit/rules.d/*.rules; then
    echo "Discretionary access control permission modification events are not collected - FAIL"
else
    echo "Discretionary access control permission modification events are collected - PASS"
fi

# 4.1.3.10 Ensure successful file system mounts are collected (Automated)
if ! grep -q "mount" /etc/audit/rules.d/*.rules; then
    echo "Successful file system mounts are not collected - FAIL"
else
    echo "Successful file system mounts are collected - PASS"
fi

# 4.1.3.11 Ensure session initiation information is collected (Automated)
if ! grep -q "session" /etc/audit/rules.d/*.rules; then
    echo "Session initiation information is not collected - FAIL"
else
    echo "Session initiation information is collected - PASS"
fi

# 4.1.3.12 Ensure login and logout events are collected (Automated)
if ! grep -q "logins" /etc/audit/rules.d/*.rules; then
    echo "Login and logout events are not collected - FAIL"
else
    echo "Login and logout events are collected - PASS"
fi

# 4.1.3.13 Ensure file deletion events by users are collected (Automated)
if ! grep -q "delete" /etc/audit/rules.d/*.rules; then
    echo "File deletion events by users are not collected - FAIL"
else
    echo "File deletion events by users are collected - PASS"
fi

# 4.1.3.14 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)
if ! grep -q "MAC-policy" /etc/audit/rules.d/*.rules; then
    echo "Events that modify the system's Mandatory Access Controls are not collected - FAIL"
else
    echo "Events that modify the system's Mandatory Access Controls are collected - PASS"
fi

# 4.1.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded (Automated)
if ! grep -q "chcon" /etc/audit/rules.d/*.rules; then
    echo "Attempts to use the chcon command are not recorded - FAIL"
else
    echo "Attempts to use the chcon command are recorded - PASS"
fi

# 4.1.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded (Automated)
if ! grep -q "setfacl" /etc/audit/rules.d/*.rules; then
    echo "Attempts to use the setfacl command are not recorded - FAIL"
else
    echo "Attempts to use the setfacl command are recorded - PASS"
fi

# 4.1.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)
if ! grep -q "chacl" /etc/audit/rules.d/*.rules; then
    echo "Attempts to use the chacl command are not recorded - FAIL"
else
    echo "Attempts to use the chacl command are recorded - PASS"
fi

# 4.1.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated)
if ! grep -q "usermod" /etc/audit/rules.d/*.rules; then
    echo "Attempts to use the usermod command are not recorded - FAIL"
else
    echo "Attempts to use the usermod command are recorded - PASS"
fi

# 4.1.3.19 Ensure kernel module loading unloading and modification is collected (Automated)
if ! grep -q "modules" /etc/audit/rules.d/*.rules; then
    echo "Kernel module loading unloading and modification is not collected - FAIL"
else
    echo "Kernel module loading unloading and modification is collected - PASS"
fi

# 4.1.3.20 Ensure the audit configuration is immutable (Automated)
if ! grep -q "^\s*[^#].*[^ ]+\s*[^#]*\s*[^ ]+\s*[^#]*\s*[^ ]+\s*[^#]*\s*[^ ]+\s*[^#]*\s*[^ ]+\s*[^#]*\s*[^ ]+\s*[^#]*\s*[^ ]+\s*[^#]*$" /etc/audit/audit.rules; then
    echo "Audit configuration is not immutable - FAIL"
else
    echo "Audit configuration is immutable - PASS"
fi

# 4.1.3.21 Ensure the running and on disk configuration is the same (Manual)
# Compare the running configuration with the on-disk configuration to ensure they are the same

# 4.1.4 Configure auditd file access
# 4.1.4.1 Ensure audit log files are mode 0640 or less permissive (Automated)
if ! find /var/log/audit/ -type f -perm /027; then
    echo "Audit log files have incorrect permissions - FAIL"
else
    echo "Audit log files have correct permissions - PASS"
fi

# 4.1.4.2 Ensure only authorized users own audit log files (Automated)
if ! find /var/log/audit/ ! -user root; then
    echo "Audit log files are not owned by authorized users - FAIL"
else
    echo "Audit log files are owned by authorized users - PASS"
fi

# 4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files (Automated)
if ! find /var/log/audit/ ! -group root; then
    echo "Audit log files are not owned by authorized groups - FAIL"
else
    echo "Audit log files are owned by authorized groups - PASS"
fi

# 4.1.4.4 Ensure the audit log directory is 0750 or more restrictive (Automated)
if ! find /var/log/audit/ -type d -perm /027; then
    echo "Audit log directory has incorrect permissions - FAIL"
else
    echo "Audit log directory has correct permissions - PASS"
fi

# 4.1.4.5 Ensure audit configuration files are 640 or more restrictive (Automated)
if ! find /etc/audit/ -type f -perm /027; then
    echo "Audit configuration files have incorrect permissions - FAIL"
else
    echo "Audit configuration files have correct permissions - PASS"
fi

# 4.1.4.6 Ensure audit configuration files are owned by root (Automated)
if ! find /etc/audit/ -type f ! -user root; then
    echo "Audit configuration files are not owned by root - FAIL"
else
    echo "Audit configuration files are owned by root - PASS"
fi

# 4.1.4.7 Ensure audit configuration files belong to group root (Automated)
if ! find /etc/audit/ -type f ! -group root; then
    echo "Audit configuration files do not belong to group root - FAIL"
else
    echo "Audit configuration files belong to group root - PASS"
fi

# 4.1.4.8 Ensure audit tools are 755 or more restrictive (Automated)
if ! find /sbin/auditctl /sbin/auditd /sbin/audit_warn /sbin/aureport /sbin/ausearch /sbin/autrace -perm /022; then
    echo "Audit tools have incorrect permissions - FAIL"
else
    echo "Audit tools have correct permissions - PASS"
fi

# 4.1.4.9 Ensure audit tools are owned by root (Automated)
if ! find /sbin/auditctl /sbin/auditd /sbin/audit_warn /sbin/aureport /sbin/ausearch /sbin/autrace ! -user root; then
    echo "Audit tools are not owned by root - FAIL"
else
    echo "Audit tools are owned by root - PASS"
fi

# 4.1.4.10 Ensure audit tools belong to group root (Automated)
if ! find /sbin/auditctl /sbin/auditd /sbin/audit_warn /sbin/aureport /sbin/ausearch /sbin/autrace ! -group root; then
    echo "Audit tools do not belong to group root - FAIL"
else
    echo "Audit tools belong to group root - PASS"
fi

# 4.2 Configure Logging
# 4.2.1 Configure rsyslog
# 4.2.1.1 Ensure rsyslog is installed (Automated)
if ! command -v rsyslog > /dev/null; then
    echo "rsyslog is not installed - FAIL"
else
    echo "rsyslog is installed - PASS"
fi

# 4.2.1.2 Ensure rsyslog service is enabled (Automated)
if ! systemctl is-enabled rsyslog | grep -q "enabled"; then
    echo "rsyslog service is not enabled - FAIL"
else
    echo "rsyslog service is enabled - PASS"
fi

# 4.2.1.3 Ensure journald is configured to send logs to rsyslog (Manual)
# Check if journald is configured to send logs to rsyslog according to your organization's policy

# 4.2.1.4 Ensure rsyslog default file permissions are configured (Automated)
if ! grep -q "^\$FileCreateMode 0640" /etc/rsyslog.conf; then
    echo "rsyslog default file permissions are not configured - FAIL"
else
    echo "rsyslog default file permissions are configured - PASS"
fi

# 4.2.1.5 Ensure logging is configured (Manual)
# Check if logging is configured according to your organization's policy

# 4.2.1.6 Ensure rsyslog is configured to send logs to a remote log host (Manual)
# Check if rsyslog is configured to send logs to a remote log host according to your organization's policy

# 4.2.1.7 Ensure rsyslog is not configured to receive logs from a remote client (Automated)
if ! grep -q "^#*.*@.*" /etc/rsyslog.conf; then
    echo "rsyslog is configured to receive logs from a remote client - FAIL"
else
    echo "rsyslog is not configured to receive logs from a remote client - PASS"
fi

# 4.2.2 Configure journald
# 4.2.2.1 Ensure journald is configured to send logs to a remote log host
# This part is specific to your organization's policy and infrastructure, so you need to configure it accordingly

# 4.2.2.2 Ensure journald service is enabled (Automated)
if ! systemctl is-enabled systemd-journald | grep -q "enabled"; then
    echo "journald service is not enabled - FAIL"
else
    echo "journald service is enabled - PASS"
fi

# 4.2.2.3 Ensure journald is configured to compress large log files (Automated)
if ! grep -q "^Compress=yes" /etc/systemd/journald.conf; then
    echo "journald is not configured to compress large log files - FAIL"
else
    echo "journald is configured to compress large log files - PASS"
fi

# 4.2.2.4 Ensure journald is configured to write logfiles to persistent disk (Automated)
if ! grep -q "^Storage=persistent" /etc/systemd/journald.conf; then
    echo "journald is not configured to write logfiles to persistent disk - FAIL"
else
    echo "journald is configured to write logfiles to persistent disk - PASS"
fi

# 4.2.2.5 Ensure journald is not configured to send logs to rsyslog (Manual)
# Check if journald is configured to send logs to rsyslog according to your organization's policy

# 4.2.2.6 Ensure journald log rotation is configured per site policy (Manual)
# Check if journald log rotation is configured per site policy according to your organization's policy

# 4.2.2.7 Ensure journald default file permissions configured (Manual)
# Check if journald default file permissions are configured according to your organization's policy

# 4.2.3 Ensure all logfiles have appropriate permissions and ownership (Automated)
if ! find /var/log/ -type f ! -user root ! -group root -perm /022; then
    echo "Not all logfiles have appropriate permissions and ownership - FAIL"
else
    echo "All logfiles have appropriate permissions and ownership - PASS"
fi

# 4.3 Ensure logrotate is configured (Manual)
# Check if logrotate is configured according to your organization's policy

# 5.1.1 Ensure cron daemon is enabled (Automated)
if ! systemctl is-enabled cron | grep -q "enabled"; then
    echo "cron daemon is not enabled - FAIL"
else
    echo "cron daemon is enabled - PASS"
fi

# 5.1.2 Ensure permissions on /etc/crontab are configured (Automated)
if ! find /etc/crontab -perm /6000; then
    echo "Permissions on /etc/crontab are not configured correctly - FAIL"
else
    echo "Permissions on /etc/crontab are configured correctly - PASS"
fi

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Automated)
if ! find /etc/cron.hourly -perm /6000; then
    echo "Permissions on /etc/cron.hourly are not configured correctly - FAIL"
else
    echo "Permissions on /etc/cron.hourly are configured correctly - PASS"
fi

# 5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated)
if ! find /etc/cron.daily -perm /6000; then
    echo "Permissions on /etc/cron.daily are not configured correctly - FAIL"
else
    echo "Permissions on /etc/cron.daily are configured correctly - PASS"
fi

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Automated)
if ! find /etc/cron.weekly -perm /6000; then
    echo "Permissions on /etc/cron.weekly are not configured correctly - FAIL"
else
    echo "Permissions on /etc/cron.weekly are configured correctly - PASS"
fi

# 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Automated)
if ! find /etc/cron.monthly -perm /6000; then
    echo "Permissions on /etc/cron.monthly are not configured correctly - FAIL"
else
    echo "Permissions on /etc/cron.monthly are configured correctly - PASS"
fi

# 5.1.7 Ensure permissions on /etc/cron.d are configured (Automated)
if ! find /etc/cron.d -perm /6000; then
    echo "Permissions on /etc/cron.d are not configured correctly - FAIL"
else
    echo "Permissions on /etc/cron.d are configured correctly - PASS"
fi

# 5.1.8 Ensure cron is restricted to authorized users (Automated)
if ! grep -q "^cron:" /etc/cron.allow; then
    echo "cron is not restricted to authorized users - FAIL"
else
    echo "cron is restricted to authorized users - PASS"
fi

# 5.1.9 Ensure at is restricted to authorized users (Automated)
if ! grep -q "^at:" /etc/at.allow; then
    echo "at is not restricted to authorized users - FAIL"
else
    echo "at is restricted to authorized users - PASS"
fi

# 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)
if ! find /etc/ssh/sshd_config -perm /6000; then
    echo "Permissions on /etc/ssh/sshd_config are not configured correctly - FAIL"
else
    echo "Permissions on /etc/ssh/sshd_config are configured correctly - PASS"
fi

# 5.2.2 Ensure permissions on SSH private host key files are configured (Automated)
if ! find /etc/ssh/ssh_host_*_key -perm /4000; then
    echo "Permissions on SSH private host key files are not configured correctly - FAIL"
else
    echo "Permissions on SSH private host key files are configured correctly - PASS"
fi

# 5.2.3 Ensure permissions on SSH public host key files are configured (Automated)
if ! find /etc/ssh/ssh_host_*_key.pub -perm /644; then
    echo "Permissions on SSH public host key files are not configured correctly - FAIL"
else
    echo "Permissions on SSH public host key files are configured correctly - PASS"
fi

# 5.2.4 Ensure SSH access is limited (Automated)
if ! grep -q "^AllowUsers\s*user1 user2" /etc/ssh/sshd_config; then
    echo "SSH access is not limited - FAIL"
else
    echo "SSH access is limited - PASS"
fi

# 5.2.5 Ensure SSH LogLevel is appropriate (Automated)
if ! grep -q "^LogLevel\s*VERBOSE" /etc/ssh/sshd_config; then
    echo "SSH LogLevel is not appropriate - FAIL"
else
    echo "SSH LogLevel is appropriate - PASS"
fi

# 5.2.6 Ensure SSH PAM is enabled (Automated)
if ! grep -q "^UsePAM\s*yes" /etc/ssh/sshd_config; then
    echo "SSH PAM is not enabled - FAIL"
else
    echo "SSH PAM is enabled - PASS"
fi

# 5.2.7 Ensure SSH root login is disabled (Automated)
if ! grep -q "^PermitRootLogin\s*no" /etc/ssh/sshd_config; then
    echo "SSH root login is not disabled - FAIL"
else
    echo "SSH root login is disabled - PASS"
fi

# 5.2.8 Ensure SSH HostbasedAuthentication is disabled (Automated)
if ! grep -q "^HostbasedAuthentication\s*no" /etc/ssh/sshd_config; then
    echo "SSH HostbasedAuthentication is not disabled - FAIL"
else
    echo "SSH HostbasedAuthentication is disabled - PASS"
fi

# 5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Automated)
if ! grep -q "^PermitEmptyPasswords\s*no" /etc/ssh/sshd_config; then
    echo "SSH PermitEmptyPasswords is not disabled - FAIL"
else
    echo "SSH PermitEmptyPasswords is disabled - PASS"
fi

# 5.2.10 Ensure SSH PermitUserEnvironment is disabled (Automated)
if ! grep -q "^PermitUserEnvironment\s*no" /etc/ssh/sshd_config; then
    echo "SSH PermitUserEnvironment is not disabled - FAIL"
else
    echo "SSH PermitUserEnvironment is disabled - PASS"
fi

# 5.2.11 Ensure SSH IgnoreRhosts is enabled (Automated)
if ! grep -q "^IgnoreRhosts\s*yes" /etc/ssh/sshd_config; then
    echo "SSH IgnoreRhosts is not enabled - FAIL"
else
    echo "SSH IgnoreRhosts is enabled - PASS"
fi

# 5.2.12 Ensure SSH X11 forwarding is disabled (Automated)
if ! grep -q "^X11Forwarding\s*no" /etc/ssh/sshd_config; then
    echo "SSH X11 forwarding is not disabled - FAIL"
else
    echo "SSH X11 forwarding is disabled - PASS"
fi

# 5.2.13 Ensure SSH AllowTcpForwarding is disabled (Automated)
if ! grep -q "^AllowTcpForwarding\s*no" /etc/ssh/sshd_config; then
    echo "SSH AllowTcpForwarding is not disabled - FAIL"
else
    echo "SSH AllowTcpForwarding is disabled - PASS"
fi

# 5.2.14 Ensure system-wide crypto policy is not over-ridden (Automated)
if ! grep -q "^UseSystemCryptoPolicy\s*yes" /etc/ssh/sshd_config; then
    echo "System-wide crypto policy is over-ridden - FAIL"
else
    echo "System-wide crypto policy is not over-ridden - PASS"
fi

# 5.2.15 Ensure SSH warning banner is configured (Automated)
if ! grep -q "^Banner\s*path_to_banner" /etc/ssh/sshd_config; then
    echo "SSH warning banner is not configured - FAIL"
else
    echo "SSH warning banner is configured - PASS"
fi

# 5.2.16 Ensure SSH MaxAuthTries is set to 4 or less (Automated)
if ! grep -q "^MaxAuthTries\s*4" /etc/ssh/sshd_config; then
    echo "SSH MaxAuthTries is not set to 4 or less - FAIL"
else
    echo "SSH MaxAuthTries is set to 4 or less - PASS"
fi

# 5.2.17 Ensure SSH MaxStartups is configured (Automated)
if ! grep -q "^MaxStartups\s*10:30:60" /etc/ssh/sshd_config; then
    echo "SSH MaxStartups is not configured - FAIL"
else
    echo "SSH MaxStartups is configured - PASS"
fi

# 5.2.18 Ensure SSH MaxSessions is set to 10 or less (Automated)
if ! grep -q "^MaxSessions\s*10" /etc/ssh/sshd_config; then
    echo "SSH MaxSessions is not set to 10 or less - FAIL"
else
    echo "SSH MaxSessions is set to 10 or less - PASS"
fi

# 5.2.19 Ensure SSH LoginGraceTime is set to one minute or less (Automated)
if ! grep -q "^LoginGraceTime\s*60" /etc/ssh/sshd_config; then
    echo "SSH LoginGraceTime is not set to one minute or less - FAIL"
else
    echo "SSH LoginGraceTime is set to one minute or less - PASS"
fi

# 5.2.20 Ensure SSH Idle Timeout Interval is configured (Automated)
if ! grep -q "^ClientAliveInterval\s*300" /etc/ssh/sshd_config; then
    echo "SSH Idle Timeout Interval is not configured - FAIL"
else
    echo "SSH Idle Timeout Interval is configured - PASS"
fi

# 5.3 Configure privilege escalation

# 5.3.1 Ensure sudo is installed (Automated)
if ! command -v sudo >/dev/null; then
    echo "sudo is not installed - FAIL"
else
    echo "sudo is installed - PASS"
fi

# 5.3.2 Ensure sudo commands use pty (Automated)
if ! grep -q "^Defaults\s+requiretty" /etc/sudoers; then
    echo "sudo commands do not require pty - FAIL"
else
    echo "sudo commands require pty - PASS"
fi

# 5.3.3 Ensure sudo log file exists (Automated)
if [ -f /var/log/sudo.log ]; then
    echo "sudo log file exists - PASS"
else
    echo "sudo log file does not exist - FAIL"
fi

# 5.3.4 Ensure users must provide password for escalation (Automated)
if ! grep -q "^Defaults\s+!authenticate" /etc/sudoers; then
    echo "Users do not need to provide password for sudo - FAIL"
else
    echo "Users must provide password for sudo - PASS"
fi

# 5.3.5 Ensure re-authentication for privilege escalation is not disabled globally (Automated)
if ! grep -q "^Defaults\s+!tty_tickets" /etc/sudoers; then
    echo "Re-authentication for privilege escalation is disabled globally - FAIL"
else
    echo "Re-authentication for privilege escalation is not disabled globally - PASS"
fi

# 5.3.6 Ensure sudo authentication timeout is configured correctly (Automated)
if ! grep -q "^Defaults\s+timestamp_timeout=5" /etc/sudoers; then
    echo "sudo authentication timeout is not configured correctly - FAIL"
else
    echo "sudo authentication timeout is configured correctly - PASS"
fi

# 5.3.7 Ensure access to the su command is restricted (Automated)
if ! grep -q "^auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su; then
    echo "Access to the su command is not restricted - FAIL"
else
    echo "Access to the su command is restricted - PASS"
fi

# 5.4 Configure authselect

# 5.4.1 Ensure custom authselect profile is used (Manual)
# Ensure that your organization's custom authselect profile is configured and used

# 5.4.2 Ensure authselect includes with-faillock (Automated)
if ! grep -q "^authselect\s+select\s+custom\s+--force" /etc/authselect/authselect.conf; then
    echo "authselect does not include with-faillock - FAIL"
else
    echo "authselect includes with-faillock - PASS"
fi

# 5.5 Configure PAM

# 5.5.1 Ensure password creation requirements are configured (Automated)
if ! grep -q "pam_pwquality.so retry=3" /etc/pam.d/password-auth; then
    echo "Password creation requirements are not configured - FAIL"
else
    echo "Password creation requirements are configured - PASS"
fi

# 5.5.2 Ensure lockout for failed password attempts is configured (Automated)
if ! grep -q "pam_faillock.so" /etc/pam.d/password-auth; then
    echo "Lockout for failed password attempts is not configured - FAIL"
else
    echo "Lockout for failed password attempts is configured - PASS"
fi

# 5.5.3 Ensure password reuse is limited (Automated)
if ! grep -q "pam_unix.so remember=5" /etc/pam.d/password-auth; then
    echo "Password reuse is not limited - FAIL"
else
    echo "Password reuse is limited - PASS"
fi

# 5.5.4 Ensure password hashing algorithm is SHA-512 or yescrypt (Automated)
if ! grep -E -q "^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512|yescrypt" /etc/pam.d/system-auth; then
    echo "Password hashing algorithm is not SHA-512 or yescrypt - FAIL"
else
    echo "Password hashing algorithm is SHA-512 or yescrypt - PASS"
fi

# 5.6 User Accounts and Environment

# 5.6.1 Set Shadow Password Suite Parameters

# 5.6.1.1 Ensure password expiration is 365 days or less (Automated)
if ! grep -q "^PASS_MAX_DAYS\s+365" /etc/login.defs; then
    echo "Password expiration is not 365 days or less - FAIL"
else
    echo "Password expiration is 365 days or less - PASS"
fi

# 5.6.1.2 Ensure minimum days between password changes is configured (Automated)
if ! grep -q "^PASS_MIN_DAYS\s+1" /etc/login.defs; then
    echo "Minimum days between password changes is not configured - FAIL"
else
    echo "Minimum days between password changes is configured - PASS"
fi

# 5.6.1.3 Ensure password expiration warning days is 7 or more (Automated)
if ! grep -q "^PASS_WARN_AGE\s+7" /etc/login.defs; then
    echo "Password expiration warning days is not 7 or more - FAIL"
else
    echo "Password expiration warning days is 7 or more - PASS"
fi

# 5.6.1.4 Ensure inactive password lock is 30 days or less (Automated)
if ! grep -q "^INACTIVE\s+30" /etc/default/useradd; then
    echo "Inactive password lock is not 30 days or less - FAIL"
else
    echo "Inactive password lock is 30 days or less - PASS"
fi

# 5.6.1.5 Ensure all users last password change date is in the past (Automated)
if ! grep -v '^[^:]*:[!*]' /etc/shadow | cut -d: -f1,3 | while IFS=: read -r user last_change; do
        password_age=$(( ( $(date +%s) - $last_change ) / 86400 ))
        if [ "$password_age" -lt 0 ]; then
                echo "User $user has a future password change date - FAIL"
        else
                echo "User $user has a password change date in the past - PASS"
        fi
done; then
        echo "Failed to check password age"
fi

# 5.6.2 Ensure system accounts are secured (Automated)
if awk -F: '($3 < 500) {print $1 }' /etc/passwd; then
    echo "System accounts are not secured - FAIL"
else
    echo "System accounts are secured - PASS"
fi

# 5.6.3 Ensure default user shell timeout is 900 seconds or less (Automated)
if ! grep -q "^TMOUT=900" /etc/profile.d/*.sh; then
    echo "Default user shell timeout is not 900 seconds or less - FAIL"
else
    echo "Default user shell timeout is 900 seconds or less - PASS"
fi

# 5.6.4 Ensure default group for the root account is GID 0 (Automated)
if ! grep -q "^root:x:0:" /etc/group; then
    echo "Default group for the root account is not GID 0 - FAIL"
else
    echo "Default group for the root account is GID 0 - PASS"
fi

# 5.6.5 Ensure default user umask is 027 or more restrictive (Automated)
if ! grep -q "umask 027" /etc/bashrc; then
    echo "Default user umask is not 027 or more restrictive - FAIL"
else
    echo "Default user umask is 027 or more restrictive - PASS"
fi

# 5.6.6 Ensure root password is set (Automated)
if ! grep -q "^root:[!*]:" /etc/shadow; then
    echo "Root password is not set - FAIL"
else
    echo "Root password is set - PASS"
fi

# 6 System Maintenance

# 6.1 System File Permissions

# 6.1.1 Ensure permissions on /etc/passwd are configured (Automated)
if [ "$(stat -c %a /etc/passwd)" -eq 644 ]; then
    echo "Permissions on /etc/passwd are configured - PASS"
else
    echo "Permissions on /etc/passwd are not configured - FAIL"
fi

# 6.1.2 Ensure permissions on /etc/passwd- are configured (Automated)
if [ "$(stat -c %a /etc/passwd-)" -eq 600 ]; then
    echo "Permissions on /etc/passwd- are configured - PASS"
else
    echo "Permissions on /etc/passwd- are not configured - FAIL"
fi

# 6.1.3 Ensure permissions on /etc/group are configured (Automated)
if [ "$(stat -c %a /etc/group)" -eq 644 ]; then
    echo "Permissions on /etc/group are configured - PASS"
else
    echo "Permissions on /etc/group are not configured - FAIL"
fi

# 6.1.4 Ensure permissions on /etc/group- are configured (Automated)
if [ "$(stat -c %a /etc/group-)" -eq 600 ]; then
    echo "Permissions on /etc/group- are configured - PASS"
else
    echo "Permissions on /etc/group- are not configured - FAIL"
fi

# 6.1.5 Ensure permissions on /etc/shadow are configured (Automated)
if [ "$(stat -c %a /etc/shadow)" -eq 640 ]; then
    echo "Permissions on /etc/shadow are configured - PASS"
else
    echo "Permissions on /etc/shadow are not configured - FAIL"
fi

# 6.1.6 Ensure permissions on /etc/shadow- are configured (Automated)
if [ "$(stat -c %a /etc/shadow-)" -eq 600 ]; then
    echo "Permissions on /etc/shadow- are configured - PASS"
else
    echo "Permissions on /etc/shadow- are not configured - FAIL"
fi

# 6.1.7 Ensure permissions on /etc/gshadow are configured (Automated)
if [ "$(stat -c %a /etc/gshadow)" -eq 640 ]; then
    echo "Permissions on /etc/gshadow are configured - PASS"
else
    echo "Permissions on /etc/gshadow are not configured - FAIL"
fi

# 6.1.8 Ensure permissions on /etc/gshadow- are configured (Automated)
if [ "$(stat -c %a /etc/gshadow-)" -eq 600 ]; then
    echo "Permissions on /etc/gshadow- are configured - PASS"
else
    echo "Permissions on /etc/gshadow- are not configured - FAIL"
fi

# 6.1.9 Ensure no world writable files exist (Automated)
ww_files=$(find / -xdev -type f -perm -0002)
if [ -z "$ww_files" ]; then
    echo "No world writable files exist - PASS"
else
    echo "World writable files exist: $ww_files - FAIL"
fi

# 6.1.10 Ensure no unowned files or directories exist (Automated)
unowned_files=$(find / -xdev \( -nouser -o -nogroup \))
if [ -z "$unowned_files" ]; then
    echo "No unowned files or directories exist - PASS"
else
    echo "Unowned files or directories exist: $unowned_files - FAIL"
fi

# 6.1.11 Ensure no ungrouped files or directories exist (Automated)
ungrouped_files=$(find / -xdev -nouser -nogroup)
if [ -z "$ungrouped_files" ]; then
    echo "No ungrouped files or directories exist - PASS"
else
    echo "Ungrouped files or directories exist: $ungrouped_files - FAIL"
fi

# 6.1.12 Ensure sticky bit is set on all world-writable directories (Automated)
sticky_dirs=$(find / -xdev -type d -perm -0002 -exec ls -ld {} \; | awk '{ print $1, $NF }' | grep -v 'drwxrwxrwt')
if [ -z "$sticky_dirs" ]; then
    echo "Sticky bit is set on all world-writable directories - PASS"
else
    echo "Sticky bit is not set on the following world-writable directories: $sticky_dirs - FAIL"
fi

# 6.1.13 Audit SUID executables (Manual)
echo "Please audit SUID executables manually."

# 6.1.14 Audit SGID executables (Manual)
echo "Please audit SGID executables manually."

# 6.1.15 Audit system file permissions (Manual)
echo "Please audit system file permissions manually."

# 6.2 Local User and Group Settings

# 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords (Automated)
if ! grep -q '^\+:' /etc/passwd; then
    echo "Accounts in /etc/passwd use shadowed passwords - PASS"
else
    echo "Accounts in /etc/passwd do not use shadowed passwords - FAIL"
fi

# 6.2.2 Ensure /etc/shadow password fields are not empty (Automated)
if awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow; then
    echo "/etc/shadow password fields are not empty - PASS"
else
    echo "/etc/shadow password fields are empty - FAIL"
fi

# 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group (Automated)
if ! awk -F: '{print $4}' /etc/passwd | while read -r gid; do grep -q "^.*?:[^:]*:$gid:" /etc/group || echo "Group with GID $gid does not exist in /etc/group - FAIL"; done; then
    echo "All groups in /etc/passwd exist in /etc/group - PASS"
fi

# 6.2.4 Ensure no duplicate UIDs exist (Automated)
if cut -f3 -d":" /etc/passwd | sort -n | uniq -d | while read -r uid; do echo "Duplicate UID $uid in /etc/passwd - FAIL"; done; then
    echo "No duplicate UIDs exist in /etc/passwd - PASS"
fi

# 6.2.5 Ensure no duplicate GIDs exist (Automated)
if cut -f4 -d":" /etc/passwd | sort -n | uniq -d | while read -r gid; do echo "Duplicate GID $gid in /etc/passwd - FAIL"; done; then
    echo "No duplicate GIDs exist in /etc/passwd - PASS"
fi

# 6.2.6 Ensure no duplicate user names exist (Automated)
if cut -f1 -d":" /etc/passwd | sort | uniq -d | while read -r user; do echo "Duplicate user $user in /etc/passwd - FAIL"; done; then
    echo "No duplicate user names exist in /etc/passwd - PASS"
fi

# 6.2.7 Ensure no duplicate group names exist (Automated)
if cut -f1 -d":" /etc/group | sort | uniq -d | while read -r group; do echo "Duplicate group $group in /etc/group - FAIL"; done; then
    echo "No duplicate group names exist in /etc/group - PASS"
fi

# 6.2.8 Ensure root PATH Integrity (Automated)
if ! echo "$PATH" | grep -qE "(^|:)/usr/local/sbin(:|$)"; then
    echo "/usr/local/sbin is not in the PATH for root - FAIL"
else
    echo "/usr/local/sbin is in the PATH for root - PASS"
fi

# 6.2.9 Ensure root is the only UID 0 account (Automated)
if awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v '^root$'; then
    echo "Multiple accounts with UID 0 exist - FAIL"
else
    echo "Only root has UID 0 - PASS"
fi

# 6.2.10 Ensure local interactive user home directories exist (Automated)
if cut -f1 -d":" /etc/passwd | while read -r user; do [ -d "$user" ] || echo "Home directory for $user does not exist - FAIL"; done; then
    echo "All local interactive user home directories exist - PASS"
fi

# 6.2.11 Ensure local interactive users own their home directories (Automated)
if cut -f1,3 -d":" /etc/passwd | while IFS=: read -r user uid; do [ "$uid" -eq 0 ] || [ $(stat -c %U /home/$user) == "$user" ] || echo "Home directory for $user is not owned by $user - FAIL"; done; then
    echo "All local interactive users own their home directories - PASS"
fi

# 6.2.12 Ensure local interactive user home directories are mode 750 or more restrictive (Automated)
if cut -f1 -d":" /etc/passwd | while read -r user; do [ "$(stat -c %a /home/$user)" -le 750 ] || echo "Home directory for $user is not mode 750 or more restrictive - FAIL"; done; then
    echo "All local interactive user home directories are mode 750 or more restrictive - PASS"
fi

# 6.2.13 Ensure no local interactive user has .netrc files (Automated)
if cut -f1 -d":" /etc/passwd | while read -r user; do [ ! -e /home/$user/.netrc ] || echo "$user has a .netrc file - FAIL"; done; then
    echo "No local interactive user has .netrc files - PASS"
fi

# 6.2.14 Ensure no local interactive user has .forward files (Automated)
if cut -f1 -d":" /etc/passwd | while read -r user; do [ ! -e /home/$user/.forward ] || echo "$user has a .forward file - FAIL"; done; then
    echo "No local interactive user has .forward files - PASS"
fi

# 6.2.15 Ensure no local interactive user has .rhosts files (Automated)
if cut -f1 -d":" /etc/passwd | while read -r user; do [ ! -e /home/$user/.rhosts ] || echo "$user has a .rhosts file - FAIL"; done; then
    echo "No local interactive user has .rhosts files - PASS"
fi

# 6.2.16 Ensure local interactive user dot files are not group or world writable (Automated)
if cut -f1 -d":" /etc/passwd | while read -r user; do [ ! -O /home/$user ] || [ -w /home/$user/. ] || echo "$user's dot files are group or world writable - FAIL"; done; then
    echo "Local interactive user dot files are not group or world writable - PASS"
fi

