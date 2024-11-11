# SSH Hardening Script


This script enhances the security of your system's SSH server (sshd) and client configurations. It generates new host keys, hardens the SSH daemon configuration (sshd_config), and applies strict security measures to the SSH client configuration (ssh_config). It also sets up a legal banner and implements rate-limiting  iptables to prevent brute-force attacks.

Author: [Bruno Schmid](https://www.linkedin.com/in/schmidbruno/) X: @brulliant


### Table of Contents

- Prerequisites
- Usage
- Configurations Applied
	- 1. Host Key Generation
	- 2. SSH Daemon Configuration (/etc/ssh/sshd_config)
	- 3. SSH Client Configuration (/etc/ssh/ssh_config)
	- 4. Permissions and Ownership
	- 5. Legal Banner
	- 6. Rate Limiting with iptables
- Important Notes
- Testing
---

## Prerequisites

- Root Privileges: This script must be run as the root user.
- Operating System: Designed for Linux systems using OpenSSH.
---

## Usage

1. Clone or Download the Script: Save the script to your local machine.
2. Make the Script Executable:
3. Run the Script as Root:
---

## Configurations Applied


1. Host Key Generation

- Old Keys Cleanup:
	- Securely deletes existing SSH host keys to prevent unauthorized access using old keys.
- Generate New Host Keys:
	- ed25519 Key: Creates a new ED25519 host key for secure and efficient authentication.
	- RSA Key: Generates a 4096-bit RSA host key for compatibility with clients that may not support ED25519.

2. SSH Daemon Configuration (/etc/ssh/sshd_config)

The script hardens the SSH daemon by modifying /etc/ssh/sshd_config with the following settings:
1. StrictModes:
	- Ensures SSH daemon checks file permissions and ownership of user files and directories.
2. Port Configuration:
	- Sets the SSH listening port. Default is 22.
3. Authentication Methods:
	- Requires both password and public key authentication for increased security.
4. Public Key Authentication:
	- Enables public key authentication and specifies the location of authorized keys and host keys.
5. Algorithms and Key Exchange:
	- Specifies secure host key algorithms, key exchange algorithms, ciphers, and MACs.
	- Points to a file containing revoked keys (/etc/ssh/revokedKeys).
6. Access Control:
	- Disables root login.
	- Restricts SSH access to specified users.
	- Limits authentication attempts and sessions per user.
7. Authentication Settings:
	- Enables password authentication (used in combination with public key).
	- Disables empty passwords, host-based authentication, and other less secure authentication methods.
	- Disables X11 forwarding and user environment modification.
8. Logging and DNS:
	- Sets verbose logging for detailed authentication logs.
	- Specifies syslog facility.
	- Disables DNS reverse lookup to speed up SSH connections.
	- Disables compression to prevent attacks exploiting compression algorithms.
9. Forwarding and Tunneling:
	- Disables various forwarding and tunneling features to prevent port forwarding and tunneling through SSH.
10. Banner and Messages:
	- Displays a legal banner before authentication.
	- Shows the last login message upon successful authentication.
	- Sets rekeying limits to enhance security over long connections.
11. Client Keepalive and Timeouts:
	- Sets keepalive intervals and timeouts to disconnect idle sessions.
	- Limits the number of concurrent unauthenticated connections.
12. Environment and Subsystems:
	- Allows clients to pass locale environment variables.
	- Enables the SFTP subsystem with logging.
	- Uses Pluggable Authentication Modules (PAM) for authentication.

3. SSH Client Configuration (/etc/ssh/ssh_config)

The script hardens the SSH client configuration with the following settings:
1. Known Hosts Hashing:
	- Hashes host names and addresses in the known hosts file for privacy.
2. Host Configuration:
	- Applies settings to all hosts.
	- Sets connection timeout.
	- Specifies preferred algorithms, ciphers, and MACs.
	- Enables persistent connections and control sockets.
	- Asks before adding new host keys to known hosts (enhances security against MITM attacks).

4. Permissions and Ownership

- Set Ownership and Permissions for sshd_config:
	- Ensures the root owns the SSH daemon configuration file and that it is readable.

5. Legal Banner

- Create a Legal Banner in /etc/issue.net:
	- Displays a legal warning to unauthorized users before logging in.

6. Rate Limiting with iptables

- Implement Rate Limiting to Prevent Brute-Force Attacks:
	- Limits new SSH connection attempts to prevent brute-force attacks.
	- Blocks an IP address if it makes more than four new connection attempts within 60 seconds.
---

## Important Notes

- Backup Existing Configurations: Before running the script, consider backing up your existing SSH configurations:
- Test Access: Ensure you have a console or out-of-band access to the server in case the new configuration prevents SSH access.
Legal Disclaimer: Please modify the banner content in /etc/issue.net to comply with your organization's policies and legal requirements.
- Persistence of iptables Rules: The rate-limiting rules may not persist after a reboot. To make them persistent:
---

## Testing

After running the script:
1. Verify SSH Service Status:
2. Attempt SSH Connection:
	- Attempt SSH into the server from a remote machine using the allowed user.
3. Check Authentication Methods:
	- Password and public key authentication are required if that's the intended configuration.
4. Monitor Logs:
	- Check /var/log/auth.log for any authentication errors or issues.

## TODO:

- Add OTP
- Add client configuration
- Use public key for authentication 
