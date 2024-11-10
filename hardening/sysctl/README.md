# Sysctl Hardening

Below is a comprehensive list of all the security hardening and performance configurations applied in the sysctl hardening script. 

## Security Hardening Configurations

1. dev.tty.ldisc_autoload=0
	- Prevents unprivileged attackers from loading vulnerable line disciplines using the TIOCSETD ioctl.
2. fs.protected_fifos = 2
	- Restricts creation of FIFOs (named pipes) in world-writable sticky directories to prevent data spoofing attacks.
3. fs.protected_regular = 2
	- Similar to fs.protected_fifos, but applies to regular files to prevent unauthorized file creation.
4. fs.suid_dumpable = 0
	- Disables core dumps from setuid programs to prevent leakage of sensitive information.
5. fs.protected_hardlinks = 1
	- It prevents hard link creation to files you don't own, mitigating privilege escalation attacks.
6. fs.protected_symlinks = 1
	- Restricts symlink following in world-writable directories to prevent symlink attacks.
7. vm.mmap_rnd_bits=32
	- Increases address space layout randomization (ASLR) entropy for 64-bit systems, making memory attacks harder.
8. vm.mmap_rnd_compat_bits=16
	- Increases ASLR entropy for 32-bit compatibility processes.
9. vm.mmap_min_addr = 65536
	- Sets the minimum virtual address that a process can mmap, protecting against NULL pointer dereference attacks.
10. vm.unprivileged_userfaultfd=0
	- Restricts the userfaultfd syscall to privileged users to prevent use-after-free vulnerabilities.
11. kernel.unprivileged_userns_clone=0
	- Disables unprivileged user namespaces to prevent potential privilege escalation.
12. kernel.sysrq = 0
	- Disables the magic SysRq key to prevent unauthorized system control.
13. kernel.core_uses_pid = 1
	- Appends the PID to core dump filenames for better debugging and to prevent overwriting.
14. kernel.pid_max = 65535
	- Increases the maximum number of process identifiers (PIDs) to prevent PID reuse attacks.
15. kernel.msgmnb = 65535
	- Sets the maximum message queue size to prevent denial-of-service (DoS) via message queues.
16. kernel.msgmax = 65535
	- Defines the maximum size of a single message in bytes for message queues.
17. kernel.printk=3 3 3 3
	- Restricts kernel message logging levels to prevent sensitive information leakage.
18. kernel.unprivileged_bpf_disabled=1
	- Disables unprivileged use of the Berkeley Packet Filter (BPF) to prevent exploitation.
19. kernel.panic = 10
	- Configures the system to reboot 10 seconds after a kernel panic, enhancing availability.
20. kernel.panic_on_oops = 1
	- It forces a kernel to panic when a kernel oops occurs, preventing potential exploitation of kernel bugs.
21. kernel.modules_disabled = 1
	- Disables the loading of kernel modules, preventing attackers from inserting malicious modules.
22. kernel.randomize_va_space = 2
	- Enables full randomization of process address space for ASLR.
23. kernel.kptr_restrict = 2
	- Restricts the visibility of kernel pointers in /proc and other interfaces to prevent info leaks.
24. kernel.yama.ptrace_scope = 2
	- Limits the use of ptrace to processes with the CAP_SYS_PTRACE capability, reducing the attack surface.
25. kernel.dmesg_restrict = 1
	- Restricts access to kernel message logs (dmesg) to privileged users.
26. kernel.perf_event_paranoid = 3
	- Disallows unprivileged use of performance events to prevent side-channel attacks.
27. kernel.shmall = 268435456
	- Sets the total amount of shared memory pages that can be used system-wide.
28. kernel.shmmax = 1073741824
	- Defines a single shared memory segment's maximum size (in bytes).
29. kernel.kexec_load_disabled = 1
	- Disables the ability to load a new kernel via kexec, preventing unauthorized code execution.
30. net.ipv4.conf.all.arp_ignore = 1
	- Ignores ARP requests that do not match the target IP address, mitigating ARP spoofing.
31. net.ipv4.conf.all.arp_announce = 2
	- Restricts ARP announcements to prevent ARP cache poisoning.
32. net.core.bpf_jit_harden = 2
	- Enables hardening of the BPF Just-In-Time compiler to prevent JIT spraying attacks.
33. net.ipv4.conf.all.proxy_arp = 0
	- Disables proxy ARP to prevent unauthorized forwarding of ARP requests.
34. net.ipv4.ip_forward = 0
	- Disables IP forwarding to prevent the system from routing packets.
35. net.ipv4.conf.all.accept_source_route = 0
	- Disables source routing to prevent attackers from specifying a packet's route.
36. net.ipv4.conf.default.accept_source_route = 0
	- Ensures source routing is disabled by default on new interfaces.
37. net.ipv4.conf.all.log_martians = 1
	- Logs packets with impossible addresses for security auditing.
38. net.ipv4.conf.default.log_martians = 1
	- Enables martian packet logging by default on new interfaces.
39. net.ipv4.conf.all.rp_filter = 1
	- Enables reverse path filtering to prevent IP spoofing.
40. net.ipv4.conf.default.rp_filter = 1
	- Applies reverse path filtering by default on new interfaces.
41. net.ipv4.tcp_rfc1337 = 1
	- Protects against TCP time-wait assassination hazards.
42. net.ipv4.conf.all.send_redirects = 0
	- Disables sending of ICMP redirects to prevent malicious network redirection.
43. net.ipv4.conf.default.send_redirects = 0
	- Disables ICMP redirects by default on new interfaces.
44. net.ipv4.icmp_echo_ignore_all = 1
	- Ignores all ICMP echo requests (ping), making the system less discoverable.
45. net.ipv4.icmp_echo_ignore_broadcasts = 1
	- Ignores ICMP echo requests to broadcast addresses to prevent Smurf attacks.
46. net.ipv4.icmp_ignore_bogus_error_responses = 1
	- Suppresses logging of bogus ICMP error responses to reduce log noise.
47. net.ipv4.conf.all.accept_redirects = 0
	- Disables acceptance of ICMP redirects to prevent malicious route updates.
48. net.ipv4.conf.default.accept_redirects = 0
	- Disables ICMP redirects by default on new interfaces.
49. net.ipv4.conf.all.secure_redirects = 0
	- Disables acceptance of secure ICMP redirects.
50. net.ipv4.conf.default.secure_redirects = 0
	- Disables secure redirects by default on new interfaces.
51. net.ipv4.tcp_syncookies = 1
	- Enables SYN cookies to protect against SYN flood attacks.
52. net.ipv6.conf.all.disable_ipv6 = 1
	- Disables IPv6 to reduce attack surface (ensure IPv6 is unnecessary).
53. net.ipv6.conf.default.disable_ipv6 = 1
	- Disables IPv6 by default on new interfaces.
54. net.ipv6.conf.all.accept_ra = 0
	- Disables acceptance of IPv6 router advertisements to prevent rogue RA attacks.
55. net.ipv6.conf.default.accept_ra = 0
	- Disables router advertisements by default on new interfaces.
56. net.ipv6.conf.all.accept_redirects = 0
	- Disables acceptance of IPv6 ICMP redirects.
57. net.ipv6.conf.default.accept_redirects = 0
	- Disables IPv6 redirects by default on new interfaces.
58. net.ipv6.conf.all.accept_source_route = 0
	- Disables IPv6 source routing to prevent routing attacks.
59. net.ipv6.conf.default.accept_source_route = 0
	- Disables source routing by default on new IPv6 interfaces.
60. net.ipv6.conf.all.forwarding = 0
	- Disables IPv6 forwarding to prevent the system from acting as a router.
61. net.ipv6.conf.all.use_tempaddr = 2
	- Enables temporary IPv6 addresses for outbound connections to enhance privacy.
62. net.ipv6.conf.default.use_tempaddr = 2
	- Uses temporary addresses by default on new IPv6 interfaces.
63. net.ipv6.conf.default.accept_ra_defrtr = 0
	- Disables acceptance of default routers via router advertisements.
64. net.ipv6.conf.default.accept_ra_pinfo = 0
	- Disables acceptance of prefix information via router advertisements.
65. net.ipv6.conf.default.autoconf = 0
	- Disables automatic configuration of IPv6 addresses.
66. net.ipv6.conf.default.dad_transmits = 0
	- Disables Duplicate Address Detection transmissions.
67. net.ipv6.conf.default.max_addresses = 1
	- Limits the number of IPv6 addresses assigned to an interface.
68. net.ipv6.conf.default.router_solicitations = 0
	- Disables sending of router solicitations.
69. net.ipv4.tcp_challenge_ack_limit = 2147483647
	- Mitigates a vulnerability (CVE-2016-5696) by increasing the challenge ACK limit.
70. net.ipv4.tcp_max_syn_backlog = 20480
	- Increases the SYN backlog queue to handle SYN flood attacks better.
71. net.ipv4.tcp_max_tw_buckets = 2000000
	- Increases the maximum number of time-wait sockets to prevent DoS attacks.
72. net.ipv4.tcp_tw_reuse = 1
	- Enables reuse of time-wait sockets for new connections to improve resource utilization.
73. net.ipv4.tcp_fin_timeout = 20
	- Reduces the time sockets remain in the FIN-WAIT-2 state to prevent resource exhaustion.
74. net.ipv4.tcp_mtu_probing = 1
	- Enables TCP MTU probing to avoid issues with path MTU discovery black holes.


## Performance Optimizations

1. vm.vfs_cache_pressure = 50
	- Reduces the tendency to reclaim memory used for inode and dentry caches, improving filesystem performance.
2. vm.swappiness = 10
	- Lowers the preference of the kernel to swap out memory, keeping applications in RAM for faster access.
3. vm.dirty_ratio = 10
	- Sets the maximum percentage of system memory that can be filled with dirty pages before writing to disk.
4. vm.dirty_background_ratio = 5
	- Defines the percentage of memory at which the background kernel flusher threads start writing dirty data to disk.
5. vm.overcommit_memory = 2
	- Disables memory overcommitment unless sufficient swap space is available, improving system stability.
6. vm.overcommit_ratio = 50
	- Sets the ratio of physical RAM considered for overcommit when vm.overcommit_memory is set to 2.
7. kernel.pid_max = 65535
	- Increases the maximum number of PIDs, allowing the system to handle more concurrent processes.
8. kernel.shmall = 268435456
	- Increases the total shared memory pages, enhancing performance for applications using shared memory.
9. kernel.shmmax = 1073741824
	- Raises the maximum size of a single shared memory segment to improve performance for memory-intensive applications.
10. net.core.dev_weight = 64
	- Adjusts the maximum number of packets processed per network interrupt to balance CPU usage and network performance.
11. net.core.netdev_max_backlog = 16384
	- Increases the queue size for incoming packets, preventing packet loss under high load.
12. net.core.somaxconn = 8192
	- Raises the maximum number of queued socket connections, improving server capacity.
13. net.core.rmem_max = 25165824
	- Increases network sockets' maximum receive buffer size, enhancing throughput for high-latency networks.
14. net.core.wmem_max = 25165824
	- Increases the maximum send buffer size for network sockets.
15. net.core.rmem_default = 262144
	- Sets the default receive buffer size for network sockets.
16. net.core.wmem_default = 262144
	- Sets the default send buffer size for network sockets.
17. net.core.optmem_max = 25165824
	- Sets the maximum ancillary buffer size allowed per socket.
18. net.ipv4.tcp_rmem = 4096 25165824 25165824
	- Configures the minimum, default, and maximum TCP receive buffer sizes.
19. net.ipv4.tcp_wmem = 4096 65536 25165824
	- Configures the minimum, default, and maximum TCP send buffer sizes.
20. net.ipv4.udp_rmem_min = 8192
	- Sets the minimum receive buffer size for UDP sockets.
21. net.ipv4.udp_wmem_min = 8192
	- Sets the minimum send buffer size for UDP sockets.
22. net.ipv4.tcp_slow_start_after_idle = 0
	- Disables slow start after idle, maintaining higher throughput for intermittent connections.
23. net.ipv4.tcp_keepalive_time = 60
	- Reduces the idle time before TCP sends keepalive probes, detecting dead connections faster.
24. net.ipv4.tcp_keepalive_intvl = 10
	- Sets the interval between TCP keepalive probes.
25. net.ipv4.tcp_keepalive_probes = 6
	- Defines the number of TCP keepalive probes sent before dropping the connection.
26. net.ipv4.tcp_fastopen = 3
	- Enables TCP Fast Open on both client and server, reducing latency for new connections.
27. net.ipv4.tcp_congestion_control = bbr
	- Sets the TCP congestion control algorithm to BBR for improved bandwidth and reduced latency.
28. net.core.default_qdisc = cake
	- Sets the default queuing discipline to CAKE, enhancing queue management and fairness.
29. net.ipv4.tcp_sack = 1
	- Enables TCP Selective Acknowledgments for better handling of packet loss.
30. net.ipv4.tcp_dsack = 1
	- Enables TCP Duplicate Selective Acknowledgments to improve loss recovery.
31. net.ipv4.tcp_fack = 1
	- Enables Forward Acknowledgment to enhance congestion control during packet loss.
