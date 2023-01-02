
#!/bin/bash

# This script will harden vsftp on Arch Linux

# Make sure only root can run our script
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Install vsftp if not already installed
if ! pacman -Qi vsftpd &> /dev/null; then
   pacman -S --noconfirm vsftpd
fi

# Create a backup of the original config file
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

# Edit the config file to harden vsftp
echo "listen=YES" >> /etc/vsftpd.conf
echo "anonymous_enable=NO" >> /etc/vsftpd.conf
echo "local_enable=YES" >> /etc/vsftpd.conf
echo "write_enable=YES" >> /etc/vsftpd.conf
echo "local_umask=022" >> /etc/vsftpd.conf
echo "dirmessage_enable=YES" >> /etc/vsftpd.conf
echo "xferlog_enable=YES" >> /etc/vsftpd.conf
echo "connect_from_port_20=YES" >> /etc/vsftpd.conf
echo "xferlog_std_format=YES" >> /etc/vsftpd.conf
echo "chroot_local_user=YES" >> /etc/vsftpd.conf
echo "allow_writeable_chroot=YES" >> /etc/vsftpd.conf
echo "secure_chroot_dir=/var/run/vsftpd" >> /etc/vsftpd.conf 
echo "pam_service_name=vsftpd" >> /etc/vsftpd.conf 
echo "rsa_cert_file=/etc/ssl/private/vsftpd.pem" >> /etc/vsftpd.conf 
echo "rsa_private_key_file=/etc/ssl/private/vsftpd.pem" >> /etc/vsftpd.conf 
echo "ssl_enable=YES" >> /etc/vsftpd.conf 
echo "allow_anon_ssl=NO" >> /etc/vsftpd.conf 
echo "force_local_data_ssl=YES" >> /etc/vsftpd.conf 
echo "force_local_logins_ssl=YES" >> /etc/vsftpd.conf 
echo "ssl_tlsv1=YES" >> /etc/vsftpd.conf 
echo "ssl_sslv2=NO" >> /etc/vsftpd.conf 
echo "ssl_sslv3=NO" >> /etc/vsftpd.conf 

 # Create a directory for the SSL certificate and private key files and set the correct permissions 
mkdir -p /etc/ssl/private && chmod 700 /etc/ssl/private 

 # Generate a self-signed SSL certificate and private key file for vsFTPd 
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem

 # Restart vsFTPd service to apply changes 
systemctl restart vsftpd