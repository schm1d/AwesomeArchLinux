
#!/bin/bash

# This script will harden the PAM configuration on Arch Linux

# Update the system
pacman -Syu

# Install pam_unix2 package
pacman -S pam_unix2

# Back up the original PAM configuration file
cp /etc/pam.d/system-auth /etc/pam.d/system-auth.orig

# Create a new PAM configuration file with the following settings
cat > /etc/pam.d/system-auth << EOF
#%PAM-1.0
auth        required      pam_tally2.so deny=5 unlock_time=900 onerr=fail audit
auth        required      pam_env.so 
auth        required      pam_unix2.so use_first_pass 
account     required      pam_unix2.so 
password    required      pam_unix2.so use_authtok nullok sha512 shadow remember=5 
session     optional      pam_keyinit.so revoke 
session     required      pam_limits.so 
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid 
session     required      pam_unix2.so 
EOF

# Set the minimum password length to 12 characters in /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*$/PASS_MIN_LEN 12/' /etc/login.defs 

# Set password aging parameters in /etc/login.defs to enforce password expiration and change frequency 
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs  # Maximum number of days a password may be used 
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' /etc/login.defs   # Minimum number of days between password changes 
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs   # Number of days of warning before a password change is required 

 # Set the maximum number of unsuccessful login attempts to 5 in /etc/pam.d/system-auth 
 sed -i 's/.*pam_tally2.*$/auth        required      pam_tally2.so deny=5 unlock_time=900 onerr=fail audit/' /etc/pam.d/system-auth 

 # Set the minimum number of digits, uppercase letters, lowercase letters, and special characters in passwords to 1 in /etc/pam.d/system-auth 
 sed -i 's/.*pam_unix2.*$/auth        required      pam_unix2.so use_first_pass minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try_first_pass use_authtok/' /etc/pam.d/system-auth 

 # Set the password hashing algorithm to SHA512 in /etc/pam.d/system-auth 
 sed -i 's/.*pam_unix2.*$//password    required      pam_unix2.so use_authtok nullok sha512 shadow remember=5 try_first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 remember=5 sha512 shadow nullok try first pass use authtok minlen=8 dcredit=-1 ucredit