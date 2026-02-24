# WordPress Production Hardening

Hardens an existing WordPress installation on Arch Linux. This script does **not** install WordPress -- it secures the server environment around an existing WordPress site with wp-config.php hardening, strict file permissions, a hardened nginx server block, fail2ban jails, PHP runtime restrictions, and a systemd-based cron replacement.

## Quick Start

```bash
# Harden a WordPress installation
sudo ./wordpress.sh -d example.com

# Custom path and database settings
sudo ./wordpress.sh -d blog.example.com -w /srv/http/wordpress --db-name wpblog --db-user bloguser
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d DOMAIN` | Domain name for the WordPress site | *required* |
| `-w WP_PATH` | WordPress installation path | `/var/www/wordpress` |
| `--db-name DB` | Database name | `wordpress` |
| `--db-user USER` | Database user | `wpuser` |
| `--db-host HOST` | Database host | `localhost` |
| `-h` | Show help | |

### Prerequisites

- Arch Linux with pacman
- Root privileges
- An existing WordPress installation at WP_PATH
- nginx-mainline installed (see `../nginx/nginx.sh`)
- PHP-FPM installed and running

## What It Does

### 1. WordPress Verification

Checks that `wp-config.php` or `wp-includes/` exists at the specified path before making any changes. If neither is found, the script exits with an error.

### 2. wp-config.php Hardening

| Constant | Value | Purpose |
|----------|-------|---------|
| `DISALLOW_FILE_EDIT` | `true` | Disable the theme/plugin editor in wp-admin |
| `DISALLOW_FILE_MODS` | `false` | Allow updates from admin (set `true` for locked-down servers) |
| `FORCE_SSL_ADMIN` | `true` | Force HTTPS for wp-admin and wp-login.php |
| `WP_AUTO_UPDATE_CORE` | `'minor'` | Auto-update minor/security releases only |
| `WP_DEBUG` | `false` | Disable debug output in production |
| `WP_DEBUG_DISPLAY` | `false` | Never display errors to visitors |
| `WP_DEBUG_LOG` | `false` | Disable debug log file |
| `CONCATENATE_SCRIPTS` | `false` | Prevent script concatenation attacks |
| `WP_MEMORY_LIMIT` | `'256M'` | PHP memory limit for frontend |
| `WP_MAX_MEMORY_LIMIT` | `'512M'` | PHP memory limit for wp-admin |
| `DISABLE_WP_CRON` | `true` | Replaced with systemd timer |

Additionally:
- **Security keys/salts** are regenerated from `https://api.wordpress.org/secret-key/1.1/salt/`
- **Table prefix** is randomized (4-char string) if still set to `wp_`
- A comment block for **custom `WP_CONTENT_DIR`** is added

### 3. File Permissions

| Target | Owner | Permissions | Notes |
|--------|-------|-------------|-------|
| `wp-config.php` | `root:http` | `640` | Only root can write, web server can read |
| All PHP files | `root:http` | `640` | Read-only for web server |
| All directories | `root:http` | `750` | Traverse-only for web server |
| `wp-content/uploads` | `http:http` | `770/660` | Web server needs write access |
| `wp-content/cache` | `http:http` | `770/660` | Cache plugins need write access |
| `wp-content/themes` | `root:http` | `750/640` | Read-only for web server |
| `wp-content/plugins` | `root:http` | `750/640` | Read-only for web server |

Files removed:
- `wp-config-sample.php`, `readme.html`, `license.txt` (information disclosure)
- `wp-admin/install.php` (if WordPress is already installed)

### 4. nginx Server Block

A complete, hardened nginx configuration for WordPress:

- **PHP-FPM** via Unix socket with `try_files $uri =404` to prevent arbitrary PHP execution
- **WordPress permalinks**: `try_files $uri $uri/ /index.php?$args`
- **xmlrpc.php blocked**: `deny all; return 403`
- **wp-config.php blocked**: direct access returns 403
- **PHP blocked in uploads**: prevents execution of uploaded PHP files
- **PHP blocked in wp-includes**: prevents direct access to include files
- **PHP blocked in wp-content**: except index.php files
- **.htaccess/.htpasswd blocked**: hidden file protection
- **Rate limiting**: wp-login.php (1r/s, burst 3), admin-ajax.php (10r/s, burst 20)
- **Static asset caching**: 1 year, immutable for images, CSS, JS, fonts
- **FastCGI cache**: included as commented template
- **Security headers**: CSP (WordPress-tuned), X-Frame-Options, X-Content-Type-Options, COOP
- **X-Powered-By hidden**: via `fastcgi_hide_header`
- **X-Robots-Tag**: `noindex, nofollow` for wp-admin

### 5. fail2ban Jails

| Jail | Filter | Max Retry | Ban Time | What It Catches |
|------|--------|-----------|----------|-----------------|
| `wordpress-auth` | `wordpress-auth.conf` | 5 | 1 hour | Failed wp-login.php POST attempts |
| `wordpress-xmlrpc` | `wordpress-xmlrpc.conf` | 2 | 24 hours | Any xmlrpc.php requests |

### 6. PHP .user.ini Hardening

| Setting | Value | Reason |
|---------|-------|--------|
| `upload_max_filesize` | `10M` | Limit upload size |
| `post_max_size` | `10M` | Match upload limit |
| `max_execution_time` | `30` | Prevent long-running scripts |
| `max_input_vars` | `3000` | WordPress admin needs more than default 1000 |
| `open_basedir` | `WP_PATH:/tmp` | Restrict PHP file access to WordPress dir |
| `session.cookie_httponly` | `1` | Prevent JavaScript access to session cookies |
| `session.cookie_secure` | `1` | Cookies only over HTTPS |
| `display_errors` | `Off` | Never show errors to visitors |

### 7. WP-Cron Replacement

WordPress's built-in wp-cron runs on every page load, which is inefficient and unreliable. This script:

1. Sets `DISABLE_WP_CRON` to `true` in wp-config.php
2. Creates a systemd timer that runs every 15 minutes
3. Uses `wp-cli cron event run --due-now` if wp-cli is installed, otherwise falls back to `curl`

## WordPress Security Best Practices

### Admin Account Security

- **Never use "admin" as a username** -- it is the first username attackers try
- Create a separate editor account for daily tasks; use the admin account only for administration
- Use strong, unique passwords (20+ characters, generated by a password manager)
- **Enable two-factor authentication (2FA)** for all administrator and editor accounts
- Regularly audit user accounts and remove unused ones
- Follow the principle of least privilege -- assign the minimum role needed

### Limiting Login Attempts

The fail2ban jails in this script handle server-level login throttling. For application-level protection:

- Install a login-limiting plugin (Wordfence, Limit Login Attempts Reloaded)
- Consider changing the wp-login.php URL with a plugin like WPS Hide Login
- Add CAPTCHA to the login form for additional bot protection
- Monitor `/var/log/fail2ban.log` for banned IPs

### Disabling the File Editor

This script sets `DISALLOW_FILE_EDIT` to `true`, which removes the theme/plugin editor from wp-admin. This prevents attackers who compromise an admin account from injecting PHP code via the editor.

For maximum lockdown, set `DISALLOW_FILE_MODS` to `true` to also disable plugin/theme installation and updates from the admin panel. Updates must then be done via wp-cli or manually on the server.

## Customizing the Content-Security-Policy

### Default CSP

The default CSP is tuned for WordPress with the admin dashboard in mind:

```
default-src 'self';
script-src 'self' 'unsafe-inline' 'unsafe-eval';
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
img-src 'self' data: https:;
font-src 'self' https://fonts.gstatic.com data:;
connect-src 'self' https:;
frame-ancestors 'self';
form-action 'self';
base-uri 'self';
upgrade-insecure-requests;
```

### Why WordPress Needs unsafe-inline

WordPress core and many plugins/themes use inline scripts and styles extensively. The admin dashboard relies on `unsafe-inline` for scripts and styles, and `unsafe-eval` for features like the Customizer and certain editor blocks. Removing these will break WordPress admin functionality.

### Per-Theme Adjustments

Different themes and plugins may load resources from external domains. Common adjustments:

```nginx
# Google Fonts (many themes use this)
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com;

# YouTube embeds
frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com;

# Google Analytics
script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.googletagmanager.com https://www.google-analytics.com;
connect-src 'self' https: https://www.google-analytics.com;
img-src 'self' data: https: https://www.google-analytics.com;

# Gravatar (WordPress default avatars)
img-src 'self' data: https: https://secure.gravatar.com;

# WooCommerce with Stripe
script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com;
frame-src 'self' https://js.stripe.com https://hooks.stripe.com;
connect-src 'self' https: https://api.stripe.com;
```

### Testing CSP Changes

Use report-only mode first to identify what the CSP would block without breaking the site:

```nginx
add_header Content-Security-Policy-Report-Only "default-src 'self'; ..." always;
```

Check the browser console (F12 > Console) for CSP violation reports.

## nginx Configuration Details

### Generated Files

| Path | Description |
|------|-------------|
| `/etc/nginx/sites-enabled/<domain>.conf` | Main WordPress server block |
| `/etc/fail2ban/filter.d/wordpress-auth.conf` | Login failure filter |
| `/etc/fail2ban/filter.d/wordpress-xmlrpc.conf` | xmlrpc.php filter |
| `/etc/fail2ban/jail.d/wordpress.conf` | WordPress fail2ban jails |
| `<WP_PATH>/.user.ini` | PHP runtime restrictions |
| `/etc/systemd/system/wordpress-cron.service` | WP-Cron systemd service |
| `/etc/systemd/system/wordpress-cron.timer` | WP-Cron systemd timer |

### FastCGI Cache

The nginx config includes a commented-out FastCGI cache configuration. To enable it:

1. Uncomment the `fastcgi_cache_path` directive at the top of the server block
2. Uncomment the `fastcgi_cache` directives inside the PHP location block
3. Add cache bypass rules for logged-in users and POST requests:

```nginx
# Add before the server block
set $skip_cache 0;

# Skip cache for logged-in users
if ($http_cookie ~* "comment_author_|wordpress_[a-f0-9]+|wp-postpass_|wordpress_logged_in_") {
    set $skip_cache 1;
}

# Skip cache for POST requests
if ($request_method = POST) {
    set $skip_cache 1;
}

# Skip cache for query strings (search, pagination)
if ($query_string != "") {
    set $skip_cache 1;
}
```

### Rate Limiting Tuning

The default rate limits are:

| Endpoint | Rate | Burst | Purpose |
|----------|------|-------|---------|
| `wp-login.php` | 1 req/sec | 3 | Prevent brute-force login attacks |
| `admin-ajax.php` | 10 req/sec | 20 | Allow AJAX-heavy admin operations |

Adjust the `limit_req_zone` rate and `burst` values in the nginx config if legitimate users are being rate-limited. The `nodelay` flag processes burst requests immediately rather than queuing them.

## Plugin Security

### Vetting Plugins Before Installation

- Check the plugin's last update date -- avoid plugins not updated in 12+ months
- Review the number of active installations and user ratings
- Check the plugin's support forum for unresolved security issues
- Search for the plugin name + "vulnerability" on CVE databases
- Prefer plugins from known developers with a track record
- Never install nulled (pirated) plugins -- they almost always contain malware

### Keeping Plugins Updated

- Enable auto-updates for trusted plugins in wp-admin > Plugins
- Subscribe to the WordPress security mailing list
- Monitor [WPScan Vulnerability Database](https://wpscan.com/wordpresses) for known issues
- Remove unused plugins entirely -- deactivated plugins can still be exploited

### Plugin File Permissions

With the permissions set by this script, plugins and themes are owned by `root:http` and are read-only to the web server. This means:

- Plugin/theme installation and updates from wp-admin will fail (by design)
- Use wp-cli to install/update: `sudo -u http wp plugin update --all --path=/var/www/wordpress`
- Or temporarily set `DISALLOW_FILE_MODS` to `false` and adjust permissions

## Backup Strategy

### Database Backups

```bash
# Manual backup with mysqldump
mysqldump -u wpuser -p wordpress > wordpress-$(date +%Y%m%d).sql

# Automated daily backup via systemd timer
# Create /etc/systemd/system/wp-backup.service and wp-backup.timer

# wp-cli database export
sudo -u http wp db export /backups/wordpress-$(date +%Y%m%d).sql --path=/var/www/wordpress
```

### File Backups

```bash
# Full file backup
tar -czf wordpress-files-$(date +%Y%m%d).tar.gz /var/www/wordpress

# Incremental backup (only changed files since last backup)
rsync -avz --delete /var/www/wordpress/ /backups/wordpress/
```

### Backup Best Practices

- Back up both database **and** files -- one without the other is incomplete
- Store backups off-server (S3, external drive, different server)
- Test restores regularly -- a backup you cannot restore is useless
- Encrypt backups at rest: `gpg -c wordpress-backup.tar.gz`
- Retain at least 30 days of daily backups
- Document the restore procedure and test it quarterly

## WordPress REST API Security

The WordPress REST API (`/wp-json/`) is enabled by default and exposes user enumeration endpoints. To restrict it:

### Disable REST API for unauthenticated users (plugin or functions.php)

```php
// Only allow authenticated REST API access
add_filter('rest_authentication_errors', function($result) {
    if (!is_user_logged_in()) {
        return new WP_Error('rest_forbidden', 'REST API restricted.', ['status' => 401]);
    }
    return $result;
});
```

### Block user enumeration via nginx

Add to the server block:

```nginx
# Block user enumeration via REST API
location ~* /wp-json/wp/v2/users {
    deny all;
    return 403;
}

# Block author enumeration via query string
if ($args ~* "author=\d+") {
    return 403;
}
```

### REST API best practices

- Disable endpoints you do not use (especially `/wp/v2/users`)
- Use application passwords (WordPress 5.6+) instead of cookie auth for API access
- Rate limit API endpoints if exposed to the public
- Monitor API access in nginx logs

## Monitoring

### Login Attempt Monitoring

```bash
# Check fail2ban status for WordPress jails
fail2ban-client status wordpress-auth
fail2ban-client status wordpress-xmlrpc

# View banned IPs
fail2ban-client status wordpress-auth | grep "Banned IP"

# Monitor fail2ban in real time
journalctl -u fail2ban -f

# Search nginx logs for login attempts
grep "wp-login.php" /var/log/nginx/access.log | tail -20

# Count login attempts per IP
grep "POST /wp-login.php" /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
```

### File Change Monitoring

Detect unauthorized modifications to WordPress core files:

```bash
# Use wp-cli to verify core file integrity
sudo -u http wp core verify-checksums --path=/var/www/wordpress

# Check plugin integrity
sudo -u http wp plugin verify-checksums --all --path=/var/www/wordpress

# Use AIDE (Advanced Intrusion Detection Environment)
pacman -S aide
aide --init
aide --check
```

### Security Plugins for Monitoring

- **Wordfence**: Real-time firewall, malware scanner, login attempt monitoring
- **Sucuri Security**: File integrity monitoring, remote malware scanning, audit logging
- **WP Activity Log**: Detailed audit trail of all WordPress activity

### Log Rotation

Ensure WordPress-related logs do not grow unbounded:

```bash
# /etc/logrotate.d/wordpress
/var/www/wordpress/wp-content/php-errors.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 640 http http
}
```

## References

- [WordPress Hardening Guide](https://developer.wordpress.org/advanced-administration/security/hardening/)
- [OWASP WordPress Security Implementation Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [WordPress Security Best Practices](https://developer.wordpress.org/plugins/security/)
- [nginx WordPress Configuration](https://developer.wordpress.org/advanced-administration/server/web-server/nginx/)
- [WPScan Vulnerability Database](https://wpscan.com/wordpresses)
- [fail2ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [WordPress REST API Handbook](https://developer.wordpress.org/rest-api/)
- [WordPress Salts Generator](https://api.wordpress.org/secret-key/1.1/salt/)
- [Arch Wiki - nginx](https://wiki.archlinux.org/title/Nginx)
- [Arch Wiki - PHP](https://wiki.archlinux.org/title/PHP)
