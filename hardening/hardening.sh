#!/bin/bash

# This script is designed to harden an Arch Linux system.

#Check if the user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Update the system
echo "updatin system..."
pacman -Syyu

# Create a backup of the original resolv.conf file
echo "hardening resolv.conf..."
cp /etc/resolv.conf /etc/resolv.conf.bak

# Create a new resolv.conf file with the following settings:
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
echo "options timeout:1 attempts:1 rotate" >> /etc/resolv.conf
echo "options edns0" >> /etc/resolv.conf
echo "options ndots:0" >> /etc/resolv.conf

# Make the new resolv.conf file immutable to prevent changes:
chattr +i /etc/resolv.conf

# Install the necessary packages
pacman -S sudo fail2ban ufw gufw clamav rkhunter chkrootkit

echo "sshd : ALL : ALLOW" > /etc/hosts.allow
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

# Cron
echo "Hardening cron files..."

rm /etc/cron.deny 2> /dev/null
rm /etc/at.deny 2> /dev/null

echo 'root' > /etc/cron.allow
echo 'root' > /etc/at.allow

chown root:root /etc/cron*
chmod og-rwx /etc/cron*

chown root:root /etc/at*
chmod og-rwx /etc/at*

systemctl mask atd.service
systemctl stop atd.service
systemctl daemon-reload

sed -i 's/^#cron./cron./' /etc/rsyslog.d/50-default.conf

if [[ $VERBOSE == "Y" ]]; then
  systemctl status atd.service --no-pager
  echo
fi

# Install AIDE
echo "Installing and configurin AIDE..."
pacman -S aide

# Create AIDE configuration file
cat > /etc/aide.conf << EOF
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes
verbose=5
report_url=file:/var/log/aide/aide.log
report_url=stdout
report_url=syslog:LOG_AUTH
database_attrs=sha256+sha512+rmd160+sha1+tiger+haval+gost+crc32+whirlpool
EOF

# Create AIDE database
aide --init --config /etc/aide.conf 
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 

# Create AIDE log directory and set permissions 
mkdir /var/log/aide 
chmod 700 /var/log/aide 
chown root:root /var/log/aide 

# Set up cron job to run AIDE daily 
echo "0 0 * * * root aide --check" >> /etc/crontab 
systemctl restart cron 
echo "AIDE is now hardened on Arch Linux!"

# Configure sudo
echo "Hardening sudo..."
# Create a backup of the sudoers file.
cp /etc/sudoers /etc/sudoers.bak

# Set the secure path for sudo.
echo "Defaults secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /etc/sudoers

# Set the timeout for sudo.
echo "Defaults timestamp_timeout=0" >> /etc/sudoers

# Disable the ability to run commands as root with sudo.
echo "Defaults rootpw" >> /etc/sudoers

# Set the default umask for sudo.
echo "Defaults umask=077" >> /etc/sudoers

# Set the default editor for sudo.
echo "Defaults editor=/usr/bin/vim" >> /etc/sudoers

# Set the default environment variables for sudo.
echo "Defaults env_reset,env_keep=\"COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS\"" >> /etc/sudoers

# Set the default password prompt timeout for sudo.
echo "Defaults passwd_timeout=0" >> /etc/sudoers
echo "Defaults env_reset,timestamp_timeout=30" >> /etc/sudoers
echo "Defaults !visiblepw" >> /etc/sudoers
echo "Defaults always_set_home" >> /etc/sudoers
echo "Defaults match_group_by_gid" >> /etc/sudoers
echo "Defaults always_query_group_plugin" >> /etc/sudoers
echo "Defaults passwd_timeout=60" >> /etc/sudoers
echo "Defaults passwd_tries=3" >> /etc/sudoers
echo "Defaults loglinelen=0" >> /etc/sudoers
echo "Defaults insults" >> /etc/sudoers
echo "Defaults lecture=always" >> /etc/sudoers
echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers
echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Configure fail2ban
echo "Installing and configuring Fail2Ban..."
# Install fail2ban
pacman -S fail2ban

# Create a copy of the default configuration file
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit the configuration file
vim /etc/fail2ban/jail.local

# Set the bantime to 1 hour 
bantime = 3600

# Set the maxretry to 3 attempts 
maxretry = 3

# Set the backend to auto 
backend = auto

# Enable the ssh jail 
[sshd] 
enabled = true 
port = ssh 
filter = sshd 
logpath = %(sshd_log)s 
maxretry = 3 
bantime = 3600 

 # Enable the apache jail 
[apache] 
enabled = true 
port = http,httpsHTTP 
filter = apache-auth 
logpath = %(apache_error_log)s 
maxretry = 3 
bantime = 3600 

 # Enable the postfix jail 
[postfix] 
enabled = true 
port = smtp,ssmtp,submission,imap2,imap3,imaps,pop3,pop3s 
filter = postfix 
logpath = %(postfix_log)s 
maxretry = 3 
bantime = 3600

 # Enable the recidive jail for persistent offenders  
[recidive]		   
enabled = true  											   
logpath = /var/log/fail2ban.log   
action = iptables-allports[name=recidive]   
bantime = -1   
findtime = 86400   
maxretry = 5   

# Restart fail2ban service to apply changes   
systemctl restart fail2ban

cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local  # Copy the default configuration to the local configuration file. 
sed -i 's|ignoreip = 127.0.0.1/8|ignoreip = 127.0.0.1\/8 10.0.0.0\/8 172.16.0.0\/12 192.168.0.0\/16|g' /etc/fail2ban/jail.local  # Add private IP ranges to ignore list. 
sed -i 's|bantime  = 600|bantime  = 86400|g' /etc/fail2ban/jail.local  # Increase ban time to 24 hours (86400 seconds). 
sed -i 's|findtime  = 600|findtime  = 3600|g' /etc/fail2ban/jail.local  # Increase find time to 1 hour (3600 seconds). 
systemctl enable fail2ban  # Enable fail2ban service on bootup. 

# Configure ClamAV antivirus scanner
# Update ClamAV
echo -e "${BBlue}Installing and configuring Clamav...${NC}"
pacman -Syu clamav

# Set ClamAV to run as a daemon
systemctl enable clamav-daemon.service

# Configure ClamAV to scan all files
sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf
echo "ScanArchive true" >> /etc/clamav/clamd.conf
echo "ArchiveBlockEncrypted false" >> /etc/clamav/clamd.conf

# Configure ClamAV to scan all incoming emails
sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf
echo "NotifyClamd /etc/clamav/clamd.conf" >> /etc/clamav/freshclam.conf

# Configure ClamAV to update its virus definitions daily
sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf
echo "DatabaseMirror database.clamav.net" >> /etc/clamav/freshclam.conf
echo "Checks 24" >> /etc/clamav/freshclam.conf
echo "DatabaseOwner clamav" >> /etc/clamav/freshclam.conf 
echo "UpdateLogFile /var/log/clamav/freshclam.log" >> /etc/clamav/freshclam.conf 
echo "LogVerbose false" >> /etc/clamav/freshclam.conf 
echo "LogSyslog false" >> /etc/clamav/freshclam.conf 
echo "LogFacility LOG_LOCAL6" >> /etc/clamav/freshclam.conf 
echo "LogRotate true" >> /etc/clamav/freshclam.conf 
echo "MaxAttempts 5" >> /etc/clamav/freshclam.conf 
echo "DatabaseDirectory /var/lib/clamav" >> /etc/clamav/freshclam.conf 
echo "PidFile /var/run/clamd.pid" >> /etc/clamav/freshclam.conf 
echo "LocalSocket /var/run/clamd" >> /etc/clamav/freshlam.conf 
echo "LocalSocketGroup clamav" >> /etc/clamav/freshlam/conf 

 # Create a log file for ClamAV updates 
touch /var/log/clamav/freschlam/log 

 # Set permissions for the log file 
chown clamav:root /var/log/clamav/freschlam/log 

 # Set permissions for the Clamd socket 
chown clamav:root /var/run/clama/d 

 # Restart the Clamd service 
systemctl restart clamav-daemon 

 # Configure Rootkit Hunter (rkhunter) scanner  
rkhunter --update   # Update rkhunter database and ruleset  

 # Configure chkrootkit scanner  
chkrootkit -q   # Run chkrootkit in quiet mode


#Sysctl hardening
echo -e "${BBlue}Hardeining sysctl...${NC}"
# Disable IP forwarding
sysctl -w net.ipv4.ip_forward=0

# Enable IP spoofing protection
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# Enable source packet routing
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0

# Enable ICMP redirects (send and accept)
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

# Enable secure ICMP redirects (send and accept) 
sysctl -w net.ipv4.conf.all.secure_redirects=1 
sysctl -w net.ipv4.conf.default.secure_redirects=1 
 
# Log suspicious packets 
sysctl -w net.ipv4.conf.all.log_martians=1 
sysctl -w net.ipv4.conf.default.log_martians=1 

# Disable ICMP broadcast echo protection 
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 

# Enable bad error message protection 
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 

# Enable TCP/IP SYN cookies 
sysctl -w net

# Install the necessary packages
pacman -S --noconfirm linux-hardened linux-hardened-headers


# Enable the kernel parameters in /etc/sysctl.d/99-sysctl.conf
echo "dev.tty.ldisc_autoload=0" >> /etc/sysctl.d/99-sysctl.conf  # Prevent unprivileged attackers from loading vulnerable line disciplines with the TIOCSETD ioctl

# These prevent creating files in potentially attacker-controlled environments, such as world-writable directories, to make data spoofing attacks more difficult.
echo "fs.protected_fifos = 2" >> /etc/sysctl.d/99-sysctl.conf
echo "fs.protected_regular = 2" >> /etc/sysctl.d/99-sysctl.conf

echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-sysctl.conf # Restrict core dumps
echo "fs.protected_hardlinks = 1" >> /etc/sysctl.d/99-sysctl.conf # Protect hard links
echo "fs.protected_symlinks = 1" >> /etc/sysctl.d/99-sysctl.conf # Protect symbolic links
echo "kernel.sysrq = 0" >> /etc/sysctl.d/99-sysctl.conf # Controls the System Request debugging functionality of the kernel
echo "kernel.core_uses_pid = 1" >> /etc/sysctl.d/99-sysctl.conf # Controls whether core dumps will append the PID to the core filename.Useful for debugging multi-threaded applications.
echo "kernel.pid_max = 65535" >> /etc/sysctl.d/99-sysctl.conf # Allow for more PIDs

# The contents of /proc/<pid>/maps and smaps files are only visible to

echo "kernel.maps_protect = 1" >> /etc/sysctl.d/99-sysctl.conf # readers that are allowed to ptrace() the process
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-sysctl.conf
echo "kernel.msgmnb = 65535" >> /etc/sysctl.d/99-sysctl.conf # Controls the maximum size of a message, in bytes
echo "kernel.msgmax = 65535" >> /etc/sysctl.d/99-sysctl.conf # Controls the default maximum size of a message queue
echo "kernel.kptr_restrict = 2" >> /etc/sysctl.d/99-sysctl.conf # Hide exposed kernel pointers

# Those options prevents those information leaks. This must be used in combination with "net.core.bpf_jit_harden=2"
echo "kernel.printk=3 3 3 3" >> /etc/sysctl.d/99-sysctl.conf
echo "kernel.unprivileged_bpf_disabled=1" >> /etc/sysctl.d/99-sysctl.conf

echo "kernel.panic = 10" >> /etc/sysctl.d/99-sysctl.conf # Wait given seconds before rebooting after a kernel panic. 0 means no reboot.
echo "kernel.panic_on_oops = 1" >> /etc/sysctl.d/99-sysctl.conf # Specifies that a system must panic if a kernel oops occurs.

echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-sysctl.conf
echo "kernel.exec-shield = 1" >> /etc/sysctl.d/99-sysctl.conf #  Provide protection against buffer overflow attacks.
echo "kernel.kptr_restrict = 2" >> /etc/sysctl.d/99-sysctl.conf # This setting aims to mitigate kernel pointer leaks.
echo "kernel.yama.ptrace_scope = 2" >> /etc/sysctl.d/99-sysctl.conf #  This restricts usage of ptrace to only processes with the CAP_SYS_PTRACE capability. Alternatively, set the sysctl to 3 to disable ptrace entirely.
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.d/99-sysctl.conf #  Restricts the kernel log to the CAP_SYSLOG capability.
echo "kernel.perf_event_paranoid = 3" >> /etc/sysctl.d/99-sysctl.conf # Disallow all usage of performance events to the CAP_PERFMON 
echo "kernel.core_uses_pid = 1" >> /etc/sysctl.d/99-sysctl.conf

# ASLR is a common exploit mitigation which randomises the position of critical parts of a process in memory.
# The above settings increase the bits of entropy used for mmap ASLR, improving its effectiveness. Values are compatible with x86, but other architectures may differ.
echo "vm.mmap_rnd_bits=32" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.mmap_rnd_compat_bits=16" >> /etc/sysctl.d/99-sysctl.conf

echo "vm.mmap_min_addr = 65536" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.swappiness = 10" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.dirty_ratio = 10" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.dirty_background_ratio = 5" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.overcommit_memory = 2" >> /etc/sysctl.d/99-sysctl.conf 
echo "vm.overcommit_ratio = 50" >> /etc/sysctl.d/99-sysctl.conf 
echo "vm.overcommit_background_ratio = 50" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.unprivileged_userfaultfd=0" >> /etc/sysctl.d/99-sysctl.conf # Restrict this syscall to the CAP_SYS_PTRACE capability to prevent use-after-free flaws.
echo "kernel.unprivileged_userns_clone=0" >> /etc/sysctl.d/99-sysctl.conf

# Controls IP packet forwarding
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf

# Often martian and the unroutable packets may be used for a dangerous purpose. Logging these packets for further inspection.
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/99-sysctl.conf

# By enabling reverse path filtering, the kernel will do source validation of the packets received from all the interfaces on the machine.
# This can protect from attackers that are using IP spoofing methods to do harm.
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.rp_filter= 1" >> /etc/sysctl.d/99-sysctl.conf

# Protect against TCP time-wait assassination hazards, drop RST packets for sockets in the time-wait state.
echo "net.ipv4.tcp_rfc1337 = 1" >> /etc/sysctl.d/99-sysctl.conf

# Disable ICMP redirect sending when on a non router
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf

# Ignore all ICMP requests to avoid Smurf attacks, make the device more difficult to enumerate on the network and prevent clock fingerprinting through ICMP timestamps.
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.d/99-sysctl.conf

# Enable ignoring broadcasts request
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/99-sysctl.conf

# Enable bad error message Protection
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/99-sysctl.conf

# Disable ICMP redirects
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf


# Protect against SYN flood attacks.
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.d/99-sysctl.conf

# Some IPV6 security improvments and tunnings here.

# Malicious IPv6 router advertisements can result in a man-in-the-middle attack, so they should be disabled.
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/99-sysctl.conf

# Disable ICMP redirects
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf

# Source routing is a mechanism that allows users to redirect network traffic. As this can be used to perform man-in-the-middle attacks we disable it.
echo "net.ipv6.conf.all.accept_source_route=0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.accept_source_route=0" >> /etc/sysctl.d/99-sysctl.conf

echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.all.use_tempaddr = 2 " >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.autoconf = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.dad_transmits = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.max_addresses = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.router_solicitations = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.use_tempaddr = 2" >> /etc/sysctl.d/99-sysctl.conf

# Enable TCP Fast Open
# Helps reduce network latency by enabling data to be exchanged during the sender’s initial TCP SYN
echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.d/99-sysctl.conf

# Increasing the size of the receive queue.
echo "net.core.netdev_max_backlog = 16384" >> /etc/sysctl.d/99-sysctl.conf

# Increase the maximum connections
echo "net.core.somaxconn = 8192" >> /etc/sysctl.d/99-sysctl.conf

# Increase the memory dedicated to the network interfaces (increase more in case of large amount of memory)
echo "net.core.rmem_default = 1048576" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.rmem_max = 16777216" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.wmem_default = 1048576" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.wmem_max = 16777216" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.optmem_max = 65536" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_rmem = 4096 1048576 2097152" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_wmem = 4096 65536 16777216" >> /etc/sysctl.d/99-sysctl.conf

# Increase the default 4096 UDP limits:
echo "net.ipv4.udp_rmem_min = 8192" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.udp_wmem_min = 8192" >> /etc/sysctl.d/99-sysctl.conf

# CVE-2016-5696
echo "net.ipv4.tcp_challenge_ack_limit=2147483647" >> /etc/sysctl.d/99-sysctl.conf

# In the event of a synflood DOS attack, this queue can fill up pretty quickly,
# at which point TCP SYN cookies will kick in allowing your system to continue to respond to legitimate traffic, and allowing you to gain access to block malicious IPs.
# If the server suffers from overloads at peak times, you may want to increase this value
echo "net.ipv4.tcp_max_syn_backlog = 20480" >> /etc/sysctl.d/99-sysctl.conf

# tcp_max_tw_buckets is the maximum number of sockets in the TIME_WAIT state.
# After reaching this number the system will start destroying the sockets that are in this state.
# Increase this to prevent simple DOS attacks
echo "net.ipv4.tcp_max_tw_buckets = 2000000" >> /etc/sysctl.d/99-sysctl.conf

# This helps avoid running out of available network sockets:
echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.d/99-sysctl.conf

# Specify how many seconds to wait for a final FIN packet before the socket is forcibly closed.
# This is strictly a violation of the TCP specification but required to prevent denial-of-service attacks.
# Default value is 180
echo "net.ipv4.tcp_fin_timeout = 20" >> /etc/sysctl.d/99-sysctl.conf

# This setting kills persistent single connection performance and could be turned off:
echo "net.ipv4.tcp_slow_start_after_idle = 0" >> /etc/sysctl.d/99-sysctl.conf

# TCP will send the keepalive probe that contains null data to the network peer several times after a period of idle time.
# If the peer does not respond, the socket will be closed automatically.
# By default, the TCP keepalive process waits for two hours (7200 secs) for socket activity before sending the first keepalive probe,
# and then resend it every 75 seconds. As long as there are TCP/IP socket communications going on and active, no keepalive packets are needed.
# With the following settings, your application will detect dead TCP connections after 120 seconds (60s + 10s + 10s + 10s + 10s + 10s + 10s).
echo "net.ipv4.tcp_keepalive_time = 60" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_keepalive_intvl = 10" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_keepalive_probes = 6" >> /etc/sysctl.d/99-sysctl.conf

# Enable MTU probing
echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.d/99-sysctl.conf

# The BBR congestion control algorithm can help achieve higher bandwidths and lower latencies for internet traffic.
echo "net.core.default_qdisc = cake" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.d/99-sysctl.conf

# This disables TCP SACK. SACK is commonly exploited and unnecessary in many circumstances.
echo "net.ipv4.tcp_sack=0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_dsack=0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_fack=0" >> /etc/sysctl.d/99-sysctl.conf


# Install packages needed for hardening files
pacman -S attr acl 

# Create a directory to store the files that will be hardened
mkdir /hardened_files

# Set the default ACL on the directory to deny all access to everyone except root 
setfacl -m d:o::- /hardened_files 

# Set the default ACL on all files in the directory to deny all access to everyone except root 
setfacl -R -m d:o::- /hardened_files/* 

# Set the default ACL on all subdirectories in the directory to deny all access to everyone except root 
setfacl -R -d -m d:o::- /hardened_files/* 

# Set the immutable flag on all files in the directory 
chattr +i /hardened_files/* 

# Set the immutable flag on all subdirectories in the directory 
find /hardened_files -type d -exec chattr +i {} \;

# Set umask to 027
echo -e "${BBlue}Setting umask to 027${NC}"
umask 027

# Set permissions for /etc/shadow
echo -e "${BBlue}Setting permissions for /etc/shadow${NC}"
chmod 600 /etc/shadow

# Set permissions for /etc/passwd
echo -e "${BBlue}Setting permissions for /etc/passwd${NC}"
chmod 644 /etc/passwd

# Set permissions for /etc/group
echo -e "${BBlue}Setting permissions for /etc/group${NC}"
chmod 644 /etc/group

# Set permissions for /etc/gshadow
echo -e "${BBlue}Setting permissions for /etc/gshadow${NC}"
chmod 600 /etc/gshadow

# Set permissions for /etc/sudoers
echo -e "${BBlue}Setting permissions for /etc/sudoers${NC}"
chmod 440 /etc/sudoers 
chown root:root /etc/sudoer

# Set permissions for SSH config files 
echo -e "${BBlue}Setting permissions for SSH config files${NC}"
chmod 600 ~/.ssh/authorized_keys 
chmod 600 ~/.ssh/config 
chmod 600 ~/.ssh/known_hosts 
chmod 600 ~/.ssh/id_rsa 
chmod 600 ~/.ssh/id_rsa.pub 
chown -R $USER:$USER ~/.ssh 

 # Set default ACLs on home directory 
echo -e "${BBlue}Setting default ACLs on home directory${NC}"
setfacl -d -m u::rwx,g::---,o::--- ~

# Set permissions on files and directories
echo -e "${BBlue}setting permissions on other files and directories...${NC}"
find / -type f -exec chmod 600 {} \;  # set file permissions to 600 (read and write for owner only) 
find / -type d -exec chmod 700 {} \;  # set directory permissions to 700 (read, write, and execute for owner only) 
chown root:root /etc/passwd # set ownership of passwd file to root:root 
chown root:shadow /etc/shadow # set ownership of shadow file to root:shadow 
chmod o-rwx /etc/shadow # set permissions of shadow file to no access for other users 
chmod g-rwx /etc/shadow # set permissions of shadow file to no access for group users 
chmod o-rwx /etc/passwd # set permissions of passwd file to no access for other users 
chmod g-rwx /etc/passwd # set permissions of passwd file to no access for group users 
chown root:root /boot/grub/grub.cfg # set ownership of grub.cfg to root:root 
chmod o-rwx /boot/grub/grub.cfg # set permissions of grub.cfg to no access for other users 
chmod g-rwx /boot/grub/grub.cfg # set permissions of grub.cfg to no access for group users 


# Set SUID and SGID bits on binaries that require it 
find / -perm -4000 -exec chmod u-s {} \; # remove SUID bit from all binaries 
find / -perm -2000 -exec chmod g-s {} \; # remove SGID bit from all binaries 
chmod u+s /usr/bin/sudo # add SUID bit to sudo binary 


 # Reboot the system for changes to take effect  
reboot