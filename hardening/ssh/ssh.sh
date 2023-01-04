#!/bin/bash

#Script Name    : ssh.sh                                   
#Description    : A very secure sshd_config and ssh_config                                                 
#Author         : @brulliant                                                
#Linkedin       : https://www.linkedin.com/in/schmidbruno/    

BBlue='\033[1;34m'
NC='\033[0m'
SSH_PORT='<custom_port>'
ALLOWED_USERS='<users separated by space>'
REVOKED_KEYS_FILE='/etc/ssh/revokedKeys'

# Check if user is root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi

echo -e "${BBlue}Cleaning old keys...${NC}"
cd /etc/ssh
rm ssh_host_*key*

echo -e "${BBlue}Creating ed25519, ras, ecdsa and dsa keys...${NC}"
ssh-keygen -t ed25519 -b 4096 -f ssh_host_ed25519_key -N "" < /dev/null
ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N "" < /dev/null
# ssh-keygen -t ecdsa -b 4096 -f ssh_host_ecdsa_key -N "" < /dev/null

echo -e "${BBlue}Hardening \"/etc/ssh/sshd_config\"...${NC}"

touch $REVOKED_KEYS_FILE

echo "Protocol 2" > /etc/ssh/sshd_config  #Protocol 1 is fundamentally broken
echo "StrictModes yes" >> /etc/ssh/sshd_config   #Protects from misconfiguration

#echo "ListenAddress <IPs allowed here coma separated>" >> /etc/ssh/sshd_config  # If you need to limit the access to few IPs from a local network this will be ideal.
echo "Port $SSH_PORT" >> /etc/ssh/sshd_config  #Listening port. default is port 22

echo "AuthenticationMethods password,publickey" >> /etc/ssh/sshd_config #Only public key authentication should be allowed.
#echo "RequiredAuthentications2 publickey,password" >> /etc/ssh/sshd_config # Requires both a passphrase and a public key

# to create a key: ssh-keygen -t ed25519 -C "$USER"
echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config #Allow public key authentication
echo "AuthorizedKeysFile .ssh/authorized_keys" >> /etc/ssh/sshd_config #Allow authorized keys in .ssh/authorized_keys
echo "HostKey /etc/ssh/ssh_host_ed25519_key" >> /etc/ssh/sshd_config #Allow ed25519 pubic key authentication
echo "HostKey /etc/ssh/ssh_host_rsa_key" >> /etc/ssh/sshd_config #Allow RSA pubic key authentication

echo "HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" >> /etc/ssh/sshd_config  #Host keys the client should accepts
echo "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config #Specifies the available KEX (Key Exchange) algorithms
echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr" >> /etc/ssh/sshd_config   #Specifies the ciphers allowed
echo "Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config     #Specifies the available MAC alg.
echo "RevokedKeys $REVOKED_KEYS_FILE" >> /etc/ssh/sshd_config  #Specifies revoked public keys file

#Only allow incoming ECDSA and ed25519 sessions:
echo "CASignatureAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519" >> /etc/ssh/sshd_config
echo "HostbasedAcceptedKeyTypes ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519" >> /etc/ssh/sshd_config
echo "PubkeyAcceptedKeyTypes sk-ecdsa-sha2-nistp256@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,ssh-ed25519" >> /etc/ssh/sshd_config

echo "PermitRootLogin no" >> /etc/ssh/sshd_config        #Disable root login
echo "AllowUsers $ALLOWED_USERS" >> /etc/ssh/sshd_config     #Authorized SSH users are inside the admin group
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config            #Maximum allowed authentication attempts
echo "MaxSessions 2" >> /etc/ssh/sshd_config             #Maximum allowed sessions by the user

echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config   #No username password authentication
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config   #No empty password authentcation allowed
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config          #Dont read users rhost files
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config   #Disable host-based authentication
echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config   #Unused authentication scheme172.16.136.141
echo "KerberosAuthentication no" >> /etc/ssh/sshd_config   # Disable kerberos authentication
echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config   # Disable GSSAP authentication 
echo "X11Forwarding no" >> /etc/ssh/sshd_config          #Disable X11 forwarding

echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config          #Fingerprint details of failed login attempts
echo "SyslogFacility AUTH" >> /etc/ssh/sshd_config       #Logging authentication and authorization related commands
echo "UseDNS no" >> /etc/ssh/sshd_config                 #Client from a location without proper DNS generate a warning in the logs
echo "Compression no" >> /etc/ssh/sshd_config

echo "PermitTunnel no" >> /etc/ssh/sshd_config           #Only SSH connection and nothing else
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config     #Disablow tunneling out via SSH
echo "AllowStreamLocalForwarding no" >> /etc/ssh/sshd_config  #Disablow tunneling out via SSH
echo "GatewayPorts no" >> /etc/ssh/sshd_config           #Disablow tunneling out via SSH
echo "DisableForwarding no" >> /etc/ssh/sshd_config      #Disables all forwarding features
echo "AllowAgentForwarding no" >> /etc/ssh/sshd_config   #Do not allow agent forwardng

echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config     #Show legal login banner
echo "PrintLastLog yes" >> /etc/ssh/sshd_config          #Show last login
echo "RekeyLimit 512M 1h" >> /etc/ssh/sshd_config

echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config   #Client timeout (15 minutes)
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config     #This way enforces timeouts on the server side
echo "LoginGraceTime 30" >> /etc/ssh/sshd_config         #Authenticatin must happen within 30 seconds
echo "MaxStartups 2" >> /etc/ssh/sshd_config             #Max concurrent SSH sessions
echo "TCPKeepAlive no" >> /etc/ssh/sshd_config           #Do not use TCP keep alive

echo "AcceptEnv LANG LC_*" >> /etc/ssh/sshd_config       #Allow client to pass locale environment variables
echo "Subsystem sftp /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO" >> /etc/ssh/sshd_config   #Enable sFTP subsystem over SSH
echo "UsePAM yes" >> /etc/ssh/ssh_config     #Enable PAM authentication

echo -e "${BBlue}Hardening \"/etc/ssh/ssh_config\"...${NC}"
echo "HashKnownHosts yes" > /etc/ssh/ssh_config #Hash the information in the knownHosts files
echo "Host *" >> /etc/ssh/ssh_config
echo "  ConnectTimeout 30" >> /etc/ssh/ssh_config
echo "  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256" >> /etc/ssh/ssh_config
echo "  KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/ssh_config
echo "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> /etc/ssh/ssh_config
echo "  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/ssh_config
echo "  ServerAliveInterval 10" >> /etc/ssh/ssh_config
echo "  ControlMaster auto" >> /etc/ssh/ssh_config
echo "  ControlPersist yes" >> /etc/ssh/ssh_config
echo "  ControlPath ~/.ssh/socket-%r@%h:%p" >> /etc/ssh/ssh_config

echo -e "${BBlue}Hardening permissions...${NC}"
chown root:root /etc/ssh/sshd_config
chmod 0600 /etc/ssh/sshd_config

echo -e "${BBlue}Creating Banner (/etc/issue.net).${NC}"

cat > /etc/issue.net << EOF
                     .ed"""" """\$\$\$\$be.
                   -"           ^""**\$\$\$e.
                 ."                   '\$\$\$c
                /                      "4\$\$b
               d  3                     \$\$\$\$
               \$  *                   .\$\$\$\$\$\$
              .\$  ^c           \$\$\$\$\$e\$\$\$\$\$\$\$\$.
              d\$L  4.         4\$\$\$\$\$\$\$\$\$\$\$\$\$\$b
              \$\$\$\$b ^ceeeee.  4\$\$ECL.F*\$\$\$\$\$\$\$
  e\$""=.      \$\$\$\$P d\$\$\$\$F \$ \$\$\$\$\$\$\$\$\$- \$\$\$\$\$\$
 z\$\$b. ^c     3\$\$\$F "\$\$\$\$b   \$"\$\$\$\$\$\$\$  \$\$\$\$*"      .=""\$c
4\$\$\$\$L   \     \$\$P"  "\$\$b   .\$ \$\$\$\$\$...e\$\$        .=  e\$\$\$.
^*\$\$\$\$\$c  %..   *c    ..    \$\$ 3\$\$\$\$\$\$\$\$\$\$eF     zP  d\$\$\$\$\$
  "**\$\$\$ec   "\   %ce""    \$\$\$  \$\$\$\$\$\$\$\$\$\$*    .r" =\$\$\$\$P""
        "*\$b.  "c  *\$e.    *** d\$\$\$\$\$"L\$\$    .d"  e\$\$***"
          ^*\$\$c ^\$c \$\$\$      4J\$\$\$\$\$% \$\$\$ .e*".eeP"
             "\$\$\$\$\$\$"'\$=e....\$*\$\$**\$cz\$\$" "..d\$*"
               "*\$\$\$  *=%4.\$ L L\$ P3\$\$\$F \$\$\$P"
                  "\$   "%*ebJLzb\$e\$\$\$\$\$b \$P"
                    %..      4\$\$\$\$\$\$\$\$\$\$ "
                     \$\$\$e   z\$\$\$\$\$\$\$\$\$\$%
                      "*\$c  "\$\$\$\$\$\$\$P"
                       ."""*\$\$\$\$\$\$\$\$bc
                    .-"    .\$***\$\$\$"""*e.
                 .-"    .e\$"     "*\$c  ^*b.
          .=*""""    .e\$*"          "*bc  "*\$e..
        .\$"        .z*"               ^*\$e.   "*****e.
        \$\$ee\$c   .d"                     "*\$.        3.
        ^*\$E")\$..\$"                         *   .ee==d%
           \$.d\$\$\$*                           *  J\$\$\$e*
            """""                             "\$\$\$"

********************************************************************
*                                                                  *
* This system is for the use of authorized users only. Usage of    *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************
EOF

chown root:root /etc/issue.net
chmod 644 /etc/issue.net

if [ $? -eq 0 ]; then
    echo -e "${BBlue}Restarting and enabling SSHD...${NC}"
    systemctl restart sshd.service
    systemctl status sshd.service
fi

echo -e "${BBlue}SSH is running on port $SSH_PORT.${NC}"
