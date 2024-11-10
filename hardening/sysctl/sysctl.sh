#!/bin/bash 
                               
#Description    : Script to harden sysctl.conf settings 
#Author         : @brulliant                                                
#Linkedin       : https://www.linkedin.com/in/schmidbruno/


# Set up the color variables
BBlue='\033[1;34m'
NC='\033[0m'

# Check if user is root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi

echo -e "${BBlue}Hardening sysctl...${NC}"

# Enable the kernel parameters in /etc/sysctl.d/99-sysctl.conf
echo "dev.tty.ldisc_autoload=0" > /etc/sysctl.d/99-sysctl.conf  # Prevent unprivileged attackers from loading vulnerable line disciplines with the TIOCSETD ioctl

# These prevent creating files in potentially attacker-controlled environments, such as world-writable directories, to make data spoofing attacks more difficult.
echo "fs.protected_fifos = 2" >> /etc/sysctl.d/99-sysctl.conf
echo "fs.protected_regular = 2" >> /etc/sysctl.d/99-sysctl.conf

echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-sysctl.conf # Restrict core dumps
echo "fs.protected_hardlinks = 1" >> /etc/sysctl.d/99-sysctl.conf # Protect hard links
echo "fs.protected_symlinks = 1" >> /etc/sysctl.d/99-sysctl.conf # Protect symbolic links

# ASLR is a common exploit mitigation which randomises the position of critical parts of a process in memory.
# The above settings increase the bits of entropy used for mmap ASLR, improving its effectiveness. Values are compatible with x86, but other architectures may differ.
echo "vm.mmap_rnd_bits=32" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.mmap_rnd_compat_bits=16" >> /etc/sysctl.d/99-sysctl.conf

echo "vm.vfs_cache_pressure = 50" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.mmap_min_addr = 65536" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.swappiness = 10" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.dirty_ratio = 10" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.dirty_background_ratio = 5" >> /etc/sysctl.d/99-sysctl.conf
echo "vm.overcommit_memory = 2" >> /etc/sysctl.d/99-sysctl.conf 
echo "vm.overcommit_ratio = 50" >> /etc/sysctl.d/99-sysctl.conf 
echo "vm.unprivileged_userfaultfd=0" >> /etc/sysctl.d/99-sysctl.conf # Restrict this syscall to the CAP_SYS_PTRACE capability to prevent use-after-free flaws.
echo "kernel.unprivileged_userns_clone=0" >> /etc/sysctl.d/99-sysctl.conf

echo "kernel.sysrq = 0" >> /etc/sysctl.d/99-sysctl.conf # Controls the System Request debugging functionality of the kernel
echo "kernel.core_uses_pid = 1" >> /etc/sysctl.d/99-sysctl.conf # Controls whether core dumps will append the PID to the core filename.Useful for debugging multi-threaded applications.
echo "kernel.pid_max = 65535" >> /etc/sysctl.d/99-sysctl.conf # Allow for more PIDs

# The contents of /proc/<pid>/maps and smaps files are only visible to

echo "kernel.msgmnb = 65535" >> /etc/sysctl.d/99-sysctl.conf # Controls the maximum size of a message, in bytes
echo "kernel.msgmax = 65535" >> /etc/sysctl.d/99-sysctl.conf # Controls the default maximum size of a message queue

# Those options prevents those information leaks. This must be used in combination with "net.core.bpf_jit_harden=2"
echo "kernel.printk=3 3 3 3" >> /etc/sysctl.d/99-sysctl.conf
echo "kernel.unprivileged_bpf_disabled=1" >> /etc/sysctl.d/99-sysctl.conf

echo "kernel.panic = 10" >> /etc/sysctl.d/99-sysctl.conf # Wait given seconds before rebooting after a kernel panic. 0 means no reboot.
echo "kernel.panic_on_oops = 1" >> /etc/sysctl.d/99-sysctl.conf # Specifies that a system must panic if a kernel oops occurs.

echo "kernel.modules_disabled = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-sysctl.conf
# echo "kernel.exec-shield = 1" >> /etc/sysctl.d/99-sysctl.conf #  Provide protection against buffer overflow attacks.
echo "kernel.kptr_restrict = 2" >> /etc/sysctl.d/99-sysctl.conf # This setting aims to mitigate kernel pointer leaks.
echo "kernel.yama.ptrace_scope = 2" >> /etc/sysctl.d/99-sysctl.conf #  This restricts usage of ptrace to only processes with the CAP_SYS_PTRACE capability. Alternatively, set the sysctl to 3 to disable ptrace entirely.
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.d/99-sysctl.conf #  Restricts the kernel log to the CAP_SYSLOG capability.
echo "kernel.perf_event_paranoid = 3" >> /etc/sysctl.d/99-sysctl.conf # Disallow all usage of performance events to the CAP_PERFMON 
echo "kernel.shmall = 268435456"  >> /etc/sysctl.d/99-sysctl.conf
echo "kernel.shmmax = 1073741824"  >> /etc/sysctl.d/99-sysctl.conf


# Network-related settings
echo "net.core.bpf_jit_harden = 2" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.dev_weight = 64" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.all.proxy_arp = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.neigh.default.gc_thresh1 = 32" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.neigh.default.gc_thresh2 = 1024" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.neigh.default.gc_thresh3 = 2048" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.all.proxy_arp = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.all.proxy_arp = 0" >> /etc/sysctl.d/99-sysctl.conf

# Controls IP packet forwarding
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf

# Often, martian and unroutable packets may be used for a dangerous purpose. Logging these packets for further inspection.
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/99-sysctl.conf

# By enabling reverse path filtering, the kernel will do source validation of the packets received from all the interfaces on the machine.
# This can protect from attackers that are using IP spoofing methods to do harm.
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/99-sysctl.conf

# Protect against TCP time-wait assassination hazards, drop RST packets for sockets in the time-wait state.
echo "net.ipv4.tcp_rfc1337 = 1" >> /etc/sysctl.d/99-sysctl.conf

# Disable ICMP redirect sending when on a non router
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf

# Ignore all ICMP requests to avoid Smurf attacks, make the device more difficult to enumerate on the network, and prevent clock fingerprinting through ICMP timestamps.
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

# Some IPV6 security improvements and tunings are here.
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf
# Malicious IPv6 router advertisements can result in a man-in-the-middle attack, so they should be disabled.
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/99-sysctl.conf

# Disable ICMP redirects
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf

# Source routing is a mechanism that allows users to redirect network traffic. 
# As this can be used to perform man-in-the-middle attacks, we disable it.
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
echo "net.core.rmem_max = 25165824" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.rmem_default = 262144" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.wmem_default = 262144" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.wmem_max = 25165824" >> /etc/sysctl.d/99-sysctl.conf
echo "net.core.optmem_max = 25165824" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_rmem = 4096 25165824 25165824" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_wmem = 4096 65536 25165824" >> /etc/sysctl.d/99-sysctl.conf

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
# The socket will be closed automatically if the peer does not respond.
# By default, the TCP keepalive process waits for two hours (7200 secs) for socket activity before sending the first keepalive probe,
# and then resending it every 75 seconds. As long as active TCP/IP socket communications exist, no keepalive packets are needed.
# With the following settings, your application will detect dead TCP connections after 120 seconds (60s + 10s + 10s + 10s + 10s + 10s + 10s).
echo "net.ipv4.tcp_keepalive_time = 60" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_keepalive_intvl = 10" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_keepalive_probes = 6" >> /etc/sysctl.d/99-sysctl.conf

# Enable MTU probing
echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.d/99-sysctl.conf

# The BBR congestion control algorithm can help achieve higher bandwidths and lower latencies for internet traffic.
echo "net.core.default_qdisc = cake" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.d/99-sysctl.conf

# Enable TCP SACK. Modern kernels have patched vulnerabilities related to SACK.
echo "net.ipv4.tcp_sack=1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_dsack=1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.tcp_fack=1" >> /etc/sysctl.d/99-sysctl.conf


sysctl --load=/etc/sysctl.d/99-sysctl.conf

echo -e "${BBlue}Sysctl is now hardened.${NC}"
