# 🛡️ Enhancing Network Security: Firehol Arch Linux setup

This sultry little FireHOL setup script brings you cutting-edge protection with minimal effort.  Paired with the sizzling blocklists from [FireHOL/blocklist-ipsets](https://github.com/firehol/blocklist-ipsets), it’s your ticket to locking down malicious traffic in style. Let’s dive in and get that firewall purring!

## 🔥 Ignite Your Setup

 **Snag the Script:**  
   Download the script to get started:
   ```bash
   wget https://raw.githubusercontent.com/schm1d/AwesomeArchLinux/main/hardening/firehol/firehol.sh
```

Make the script executable and run it:

```bash
    chmod +x ./firehol.sh
   ./firehol.sh]
   ```

Now that FireHOL is running successfully, you can add blocklists from the FireHOL blocklist-ipsets repository.  
Here's a step-by-step guide to implement these blocklists:

## 1. **Download the blocklist IP sets**
   ```bash
   sudo update-ipsets -g
   ```
   This will download all available blocklists to your system.

## 2. **View available blocklists**
   ```bash
   sudo update-ipsets
   ```
   This shows all blocklists you can use.

## 3. **Enable specific blocklists**
   You can enable individual blocklists according to your needs:
   ```bash
   # Basic protection (recommended to start with)
   sudo update-ipsets enable firehol_level1
   
   # For specific threats, add more specialized lists
   sudo update-ipsets enable spamhaus_drop
   sudo update-ipsets enable dshield
   sudo update-ipsets enable alienvault_reputation
   ```

## 4. **Edit your FireHOL configuration**
   ```bash
   sudo nano /etc/firehol/firehol.conf
   ```
   
   Modify your configuration to include the blocklists. Add these lines within the `interface any world` section:
   ```
   # Block traffic using FireHOL IP sets
   blacklist fullbogons ipset:firehol_level1
   blacklist fullbogons ipset:spamhaus_drop
   blacklist fullbogons ipset:dshield
   ```

   The blocklist format is:
   - `blacklist fullbogons`: Blocks both incoming and outgoing traffic
   - `blacklist inbound`: Blocks only incoming traffic
   - `blacklist outbound`: Blocks only outgoing traffic

## 5. **Test your configuration**
   ```bash
   sudo firehol try
   ```
   This will load the new configuration temporarily and prompt you to confirm it works.

## 6. **Additional blocklist options**

   There are different levels of protection:
   - `firehol_level1`: Safe for most users
   - `firehol_level2`: More aggressive blocking
   - `firehol_level3`: Very aggressive (may cause false positives)
   - `firehol_level4`: Extremely aggressive (high chance of false positives)

   Category-specific blocklists:
   - `firehol_webserver`: Protection for web servers
   - `firehol_anonymous`: Blocks anonymous networks (Tor, proxies)
   - `cybercrime`: Blocks known cybercrime sources
   - `coinbl_hosts`: Cryptocurrency mining/cryptojacking protection
   - `malware`: Known malware sources

## 7. **Verify your active blocklists**
   ```bash
   sudo ipset list
   ```
   This will show all active IP sets.

## 8. **Monitor logs for blocked traffic**
   ```bash
   sudo journalctl -f | grep DROP
   ```

The cron job you've already set up will automatically update these IP sets daily, ensuring you have the latest protection.  

 Dive Deeper
 [FireHOL Docs](https://firehol.org/documentation/)  

> [!IMPORTANT]
> Start with fewer blocklists and gradually add more as needed to avoid accidentally blocking legitimate traffic.


