# PostgreSQL Production Hardening

Installs and hardens [PostgreSQL](https://archlinux.org/packages/extra/x86_64/postgresql/) on Arch Linux for production use, targeting:

- **scram-sha-256** authentication everywhere (no md5, no trust)
- **Data checksums** for corruption detection
- **systemd sandboxing** with strict filesystem and capability controls
- **Comprehensive logging** for audit trails and diagnostics
- **Resource limits** to prevent runaway queries and connections

## Quick Start

```bash
# Localhost only (default, most secure)
sudo ./postgresql.sh

# Custom port with SSL
sudo ./postgresql.sh -p 5433 --ssl \
  --ssl-cert /root/server.crt --ssl-key /root/server.key

# Remote access with SSL (for app servers on a private network)
sudo ./postgresql.sh --no-local --allow-cidr 10.20.30.0/24 --ssl \
  --ssl-cert /root/server.crt --ssl-key /root/server.key
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p PORT` | PostgreSQL listen port | `5432` |
| `--ssl` | Enable SSL/TLS connections | off |
| `--ssl-cert PATH` | PEM server certificate; required with `--ssl` | none |
| `--ssl-key PATH` | Unencrypted PEM private key; required with `--ssl` | none |
| `--local-only` | Listen only on localhost | on (default) |
| `--no-local` | Listen on all interfaces; requires TLS and an allowed CIDR | off |
| `--allow-cidr CIDR` | IPv4 or IPv6 client network allowed by `pg_hba.conf` and nftables (`/0` is rejected) | none |
| `-h` | Show help | |

## What It Does

### 1. Package Installation

- `postgresql` (official Arch repos)

### 2. Database Initialization

| Setting | Value |
|---------|-------|
| Locale | Verified host locale (`${LANG}` if in `locale -a`, else `C.UTF-8`, else `C`) |
| Encoding | `UTF8` (`--encoding=UTF8`, prevents `SQL_ASCII` fallback under `C` locale) |
| Data checksums | Enabled (`--data-checksums`) |
| Local auth | `peer` |
| Host auth | `scram-sha-256` |
| Data directory | `/var/lib/postgres/data` |

### 3. postgresql.conf Hardening

`postgresql.conf` and `pg_hba.conf` are regenerated on every run. Before they are replaced:

- The current versions are copied to `/var/backups/postgresql-hardening/<timestamp>/` (root-only, one directory per run). The first run additionally keeps the pre-hardening files as `postgresql.conf.orig` and `pg_hba.conf.orig` in the data directory.
- The settings `initdb` wrote for this cluster are carried over into the new file: `timezone`, `log_timezone`, `datestyle`, `lc_messages`, `lc_monetary`, `lc_numeric`, `lc_time`, `default_text_search_config`, `dynamic_shared_memory_type`, `max_wal_size` and `min_wal_size`. Without them PostgreSQL falls back to GMT, `C` formatting and the `simple` text search configuration. If an earlier version of this script already dropped them, they are recovered from `postgresql.conf.orig`.
- On a re-run, the script warns when the previous file had active lines that are not in the regenerated one (for example an extra `pg_hba.conf` rule or a tuned `work_mem`) and prints the `diff` command to compare them.

**Keeping your own settings across re-runs.** Do not edit the generated files; use the include directories, which the script creates and never writes to:

| Directory | Read | Use it for |
|-----------|------|------------|
| `/var/lib/postgres/data/conf.d/*.conf` | Last, via `include_dir = 'conf.d'` at the end of `postgresql.conf`, so it overrides the generated values | `archive_command`, memory tuning, extra `shared_preload_libraries`, ... |
| `/var/lib/postgres/data/hba.d/*.conf` | After the generated rules, via `include_dir` at the end of `pg_hba.conf` (PostgreSQL 16 or newer; the first matching rule wins) | Per-database or per-user rules, replication rows. Never use `trust` |

Files there must be readable by `postgres` (for example `install -o postgres -g postgres -m 0600 my.conf /var/lib/postgres/data/conf.d/`). Reload with `systemctl reload postgresql`; settings marked "change requires restart" need `systemctl restart postgresql`.

#### Connection Settings

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `listen_addresses` | `localhost` or `*` | Controls which interfaces accept connections |
| `port` | `5432` (configurable) | Listen port |
| `max_connections` | `100` | Maximum concurrent connections |
| `superuser_reserved_connections` | `3` | Reserved slots for superuser maintenance |

#### Authentication

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `password_encryption` | `scram-sha-256` | Strongest built-in password hashing |
| `authentication_timeout` | `30s` | Limit time for auth handshake |

#### SSL/TLS (when `--ssl` is used)

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `ssl` | `on` | Enable encrypted connections |
| `ssl_min_protocol_version` | `TLSv1.2` | Reject TLS 1.0/1.1 |
| `ssl_ciphers` | `HIGH:!aNULL:!MD5:!3DES:!RC4` | Strong ciphers only |
| `ssl_prefer_server_ciphers` | `on` | Server chooses cipher order |

#### Logging

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `logging_collector` | `on` | Capture logs to files |
| `log_filename` | `postgresql-%d.log` | One file per day of the month |
| `log_truncate_on_rotation` | `on` | Overwrite the file from a month ago instead of appending (bounded retention: at most 31 files) |
| `log_rotation_age` | `1d` | Rotate daily |
| `log_rotation_size` | `0` | No size-driven rotation (it would reopen the same file name; truncation only happens on time-driven rotation) |
| `log_min_messages` | `warning` | Minimum severity logged |
| `log_connections` | `on` | Log every connection attempt |
| `log_disconnections` | `on` | Log session end |
| `log_statement` | `ddl` | Log schema-changing statements |
| `log_checkpoints` | `on` | Log checkpoint activity |
| `log_lock_waits` | `on` | Log deadlocks and long waits |
| `log_temp_files` | `0` | Log all temp file usage |
| `log_line_prefix` | `%t [%p]: user=%u,db=%d...` | Rich log context |

#### Security

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `row_security` | `on` | Enable row-level security policies |
| `shared_preload_libraries` | `pg_stat_statements` | Query performance monitoring |

#### Resource Limits

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `shared_buffers` | `256MB` | Shared memory for caching |
| `work_mem` | `8MB` | Per-operation sort/hash memory |
| `maintenance_work_mem` | `128MB` | VACUUM, CREATE INDEX memory |
| `effective_cache_size` | `768MB` | Planner hint for OS cache |
| `temp_file_limit` | `1GB` | Max temp disk usage per session |
| `statement_timeout` | `60000` (60s) | Kill queries exceeding 60 seconds |
| `idle_in_transaction_session_timeout` | `600000` (10m) | Kill idle transactions after 10 minutes |

### 4. pg_hba.conf Hardening

| Type | Database | User | Address | Method |
|------|----------|------|---------|--------|
| `local` | all | postgres | | `peer` |
| `local` | all | all | | `scram-sha-256` |
| `host` | all | all | `127.0.0.1/32` | `scram-sha-256` |
| `host` | all | all | `::1/128` | `scram-sha-256` |
| `hostssl` | all | all | operator-supplied IPv4 or IPv6 CIDR | `scram-sha-256` (remote+SSL only) |

**No `trust` authentication anywhere.**

### 5. systemd Service Hardening

| Directive | Value | Purpose |
|-----------|-------|---------|
| `ProtectSystem` | `strict` | Read-only filesystem except allowed paths |
| `ProtectHome` | `yes` | No access to /home |
| `PrivateTmp` | `yes` | Isolated /tmp |
| `NoNewPrivileges` | `yes` | Cannot gain new privileges |
| `ProtectKernelTunables` | `yes` | No sysctl modification |
| `ProtectKernelModules` | `yes` | No module loading |
| `RuntimeDirectory` | `postgresql` | Creates `/run/postgresql` before unit start |
| `ReadWritePaths` | `/var/lib/postgres`, `-/run/postgresql` | Only necessary write paths |
| `CapabilityBoundingSet` | *(empty, or `CAP_NET_BIND_SERVICE` if port < 1024)* | Drop unnecessary capabilities |
| `MemoryDenyWriteExecute` | `no` | Required for PostgreSQL JIT |
| `RestrictAddressFamilies` | `AF_UNIX AF_INET AF_INET6` | Only Unix and IP sockets |
| `SystemCallFilter` | `@system-service @network-io` | Restrict system calls |

### 6. File Permissions

| Path | Mode | Owner |
|------|------|-------|
| `/var/lib/postgres` | `700` | `postgres:postgres` |
| `/var/lib/postgres/data` | `700` | `postgres:postgres` |
| `postgresql.conf` | `600` | `postgres:postgres` |
| `pg_hba.conf` | `600` | `postgres:postgres` |

## Authentication Methods

PostgreSQL supports several authentication methods. This script enforces the most secure options:

### scram-sha-256 (recommended)

The strongest built-in password authentication. Uses salted challenge-response with SHA-256, preventing password interception even over unencrypted connections. Always prefer this over md5.

```
# pg_hba.conf
host    all    all    192.168.1.0/24    scram-sha-256
```

### peer (local only)

Maps the OS username to a PostgreSQL role. No password required — the kernel verifies identity. Only works for local Unix socket connections. Ideal for the `postgres` superuser.

```
# pg_hba.conf
local   all    postgres    peer
```

### md5 (legacy, avoid)

Older challenge-response using MD5. Vulnerable to hash interception and replay in some scenarios. Use only if legacy clients require it, and plan migration to scram-sha-256.

### trust (never use in production)

Allows connection without any authentication. **Never use this in production.** Even for local development, prefer `peer` for Unix sockets.

### cert (strongest for remote)

Client certificate authentication over SSL. Requires PKI infrastructure but provides the strongest remote authentication without passwords.

```
# pg_hba.conf
hostssl all    all    10.20.30.0/24    cert    clientcert=verify-full
```

## SSL Setup with Real Certificates

The script refuses `--ssl` without a valid, matching certificate and unencrypted
private key. It installs them as postgres-owned mode-0600 files under
`/var/lib/postgres/tls/`; remote mode additionally requires an explicit IPv4 or IPv6
client CIDR and installs the matching `ip saddr` / `ip6 saddr` rule in the project-owned nftables ruleset.

### Option 1: Let's Encrypt (with certbot)

```bash
# Install certbot
pacman -S certbot

# Obtain certificate
certbot certonly --standalone -d db.example.com

# Install the certificate through the hardening script
sudo ./postgresql.sh --ssl \
  --ssl-cert /etc/letsencrypt/live/db.example.com/fullchain.pem \
  --ssl-key /etc/letsencrypt/live/db.example.com/privkey.pem
```

### Option 2: Self-signed (internal networks)

```bash
# Generate CA
openssl req -new -x509 -days 3650 -nodes \
    -out /etc/ssl/postgresql/ca.crt \
    -keyout /etc/ssl/postgresql/ca.key \
    -subj "/CN=PostgreSQL CA"

# Generate server certificate
openssl req -new -nodes \
    -out /etc/ssl/postgresql/server.csr \
    -keyout /etc/ssl/postgresql/server.key \
    -subj "/CN=db.example.com"

openssl x509 -req -days 365 \
    -in /etc/ssl/postgresql/server.csr \
    -CA /etc/ssl/postgresql/ca.crt \
    -CAkey /etc/ssl/postgresql/ca.key \
    -CAcreateserial \
    -out /etc/ssl/postgresql/server.crt

# Install for one private application subnet
sudo ./postgresql.sh --no-local --allow-cidr 10.20.30.0/24 --ssl \
  --ssl-cert /etc/ssl/postgresql/server.crt \
  --ssl-key /etc/ssl/postgresql/server.key
```

### Verify SSL Connections

```bash
# Check if SSL is active (add -p <PORT> when using a non-default port)
sudo -u postgres psql -c "SHOW ssl;"

# Check connection encryption
sudo -u postgres psql -c "SELECT pg_ssl.ssl, pg_ssl.version, pg_ssl.cipher
    FROM pg_stat_ssl pg_ssl
    JOIN pg_stat_activity pg_sa ON pg_ssl.pid = pg_sa.pid;"
```

## Backup Strategies

### pg_dump (logical backup)

Simple and portable. Good for small to medium databases and for migrating between PostgreSQL versions.

```bash
# Single database
sudo -u postgres pg_dump appdb > /backups/appdb_$(date +%Y%m%d).sql

# All databases
sudo -u postgres pg_dumpall > /backups/all_$(date +%Y%m%d).sql

# Compressed custom format (recommended)
sudo -u postgres pg_dump -Fc appdb > /backups/appdb_$(date +%Y%m%d).dump

# Restore
sudo -u postgres pg_restore -d appdb /backups/appdb_20260224.dump
```

### pg_basebackup (physical backup)

Full binary backup of the entire cluster. Required for point-in-time recovery (PITR).

```bash
# Full backup
sudo -u postgres pg_basebackup \
    -D /backups/base_$(date +%Y%m%d) \
    -Ft -z -P \
    --checkpoint=fast

# With WAL files included (standalone backup)
sudo -u postgres pg_basebackup \
    -D /backups/base_$(date +%Y%m%d) \
    -Ft -z -P \
    --checkpoint=fast \
    --wal-method=stream
```

### WAL Archiving (continuous backup / PITR)

The gold standard for production. Combines base backups with continuous WAL archiving for point-in-time recovery.

```ini
# postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'cp %p /backups/wal/%f'
archive_timeout = 300   # Archive at least every 5 minutes
```

```bash
# Automated backup script
#!/usr/bin/env bash
BACKUP_DIR="/backups/base/$(date +%Y%m%d)"
sudo -u postgres pg_basebackup -D "$BACKUP_DIR" -Ft -z -P --checkpoint=fast

# Retention: keep 7 days of base backups, 14 days of WAL
find /backups/base -maxdepth 1 -mtime +7 -exec rm -rf {} +
find /backups/wal -maxdepth 1 -mtime +14 -delete
```

### Backup Verification

Always test your backups:

```bash
# Verify a custom-format dump
pg_restore --list /backups/appdb.dump

# Test restore to a temporary database
createdb test_restore
pg_restore -d test_restore /backups/appdb.dump
dropdb test_restore
```

## Role-Based Access Control Best Practices

### Principle of Least Privilege

```sql
-- 1. Create role groups (no login)
CREATE ROLE readonly;
CREATE ROLE readwrite;
CREATE ROLE admin;

-- 2. Grant schema-level permissions
GRANT USAGE ON SCHEMA public TO readonly;
GRANT USAGE, CREATE ON SCHEMA public TO readwrite;

-- 3. Grant table-level permissions
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO readwrite;

-- 4. Set default permissions for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO readwrite;

-- 5. Create login users and assign roles
CREATE USER reporting_user WITH PASSWORD 'strong-password-here' CONNECTION LIMIT 5;
GRANT readonly TO reporting_user;

CREATE USER app_user WITH PASSWORD 'strong-password-here' CONNECTION LIMIT 20;
GRANT readwrite TO app_user;
```

### Row-Level Security (RLS)

```sql
-- Enable RLS on a table
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- Users can only see their own orders
CREATE POLICY user_orders ON orders
    FOR ALL
    USING (user_id = current_setting('app.current_user_id')::int);

-- Admin role bypasses RLS
ALTER TABLE orders FORCE ROW LEVEL SECURITY;
GRANT ALL ON orders TO admin;
CREATE POLICY admin_all ON orders TO admin USING (true);
```

### Schema Isolation

```sql
-- Revoke default public schema access
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Create per-application schemas
CREATE SCHEMA app1 AUTHORIZATION app1_user;
CREATE SCHEMA app2 AUTHORIZATION app2_user;

-- Each user only accesses their own schema
ALTER ROLE app1_user SET search_path = app1;
ALTER ROLE app2_user SET search_path = app2;
```

## pg_stat_statements for Query Monitoring

The script preloads `pg_stat_statements` for query performance monitoring.

### Enable and Use

```sql
-- Create the extension (the script does this automatically)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Top 10 slowest queries
SELECT
    calls,
    round(total_exec_time::numeric, 2) AS total_ms,
    round(mean_exec_time::numeric, 2) AS mean_ms,
    round((100 * total_exec_time / sum(total_exec_time) OVER ())::numeric, 2) AS pct,
    left(query, 80) AS query
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 10;

-- Queries with the most calls
SELECT
    calls,
    round(mean_exec_time::numeric, 2) AS mean_ms,
    rows,
    left(query, 80) AS query
FROM pg_stat_statements
ORDER BY calls DESC
LIMIT 10;

-- Reset statistics
SELECT pg_stat_statements_reset();
```

### Configuration Tuning

```ini
# postgresql.conf
pg_stat_statements.max = 5000          # Max tracked statements
pg_stat_statements.track = top         # Track top-level statements only
pg_stat_statements.track_utility = off # Skip utility commands (SET, SHOW, etc.)
pg_stat_statements.track_planning = on # Include planning time
```

## Connection Pooling with PgBouncer

For production workloads with many short-lived connections, use [PgBouncer](https://www.pgbouncer.org/) to reduce PostgreSQL overhead.

### Install

```bash
pacman -S pgbouncer
```

### Configure `/etc/pgbouncer/pgbouncer.ini`

```ini
[databases]
appdb = host=127.0.0.1 port=5432 dbname=appdb

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = 6432
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt

# Pool settings
pool_mode = transaction      # Recommended for most apps
default_pool_size = 20
max_client_conn = 200
min_pool_size = 5
reserve_pool_size = 5
reserve_pool_timeout = 3

# Security
server_tls_sslmode = prefer
client_tls_sslmode = allow

# Logging
log_connections = 1
log_disconnections = 1
stats_period = 60
```

### Create User List

```bash
# Generate scram-sha-256 hash
sudo -u postgres psql -c "SELECT concat('\"', usename, '\" \"', passwd, '\"') FROM pg_shadow WHERE usename = 'appuser';" -t > /etc/pgbouncer/userlist.txt
```

### Application Connection

Applications connect to PgBouncer (port 6432) instead of PostgreSQL directly (port 5432):

```
postgresql://appuser:password@127.0.0.1:6432/appdb
```

## Common Security Mistakes

### 1. Using `trust` Authentication

**Problem:** Any local or network user can connect as any PostgreSQL user without a password.

```
# NEVER DO THIS
local   all   all   trust
host    all   all   0.0.0.0/0   trust
```

**Fix:** Use `peer` for local superuser and `scram-sha-256` for everything else (as this script does).

### 2. Keeping the Default `public` Schema Open

**Problem:** By default, every user can create objects in the `public` schema. This can be exploited for privilege escalation via function or view poisoning.

```sql
-- Fix: revoke public schema creation
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

### 3. Not Using Row-Level Security

**Problem:** Without RLS, any user with SELECT access to a table can read all rows, including other users' data.

```sql
-- Fix: enable RLS and create policies
ALTER TABLE sensitive_data ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_isolation ON sensitive_data
    USING (owner_id = current_user);
```

### 4. Running Applications as Superuser

**Problem:** If the application is compromised, the attacker has full database access.

**Fix:** Always create dedicated application users with minimal privileges (see Role-Based Access Control above).

### 5. Using md5 Instead of scram-sha-256

**Problem:** MD5 hashes can be captured and replayed. The hash is `md5(password + username)`, so if two users share a password on different servers, the hashes differ, but the scheme is still cryptographically weak.

**Fix:** Set `password_encryption = scram-sha-256` in postgresql.conf (as this script does). Reset existing passwords after changing the setting.

### 6. No Statement Timeout

**Problem:** A single bad query can consume all resources indefinitely, causing a denial of service for all users.

**Fix:** Set `statement_timeout` (this script sets 60 seconds) and `idle_in_transaction_session_timeout` (10 minutes).

### 7. No Connection Limits

**Problem:** A misbehaving application or attack can exhaust all connection slots.

**Fix:** Set `max_connections` (100), use `CONNECTION LIMIT` per user, and deploy PgBouncer for connection pooling.

### 8. Exposing PostgreSQL to the Internet Without SSL

**Problem:** Passwords and data travel in plaintext.

**Fix:** Use `--no-local` only with an explicit private `--allow-cidr`, `--ssl`, and real certificate/key files. The script rejects cleartext or world-wide remote access.

### 9. Not Monitoring Queries

**Problem:** Slow or malicious queries go undetected until they cause outages.

**Fix:** Enable `pg_stat_statements` (this script does), set `log_statement = 'ddl'`, and monitor `log_lock_waits`.

### 10. No Backups or Untested Backups

**Problem:** Data loss is permanent without backups. Untested backups may be corrupt or incomplete.

**Fix:** Implement automated pg_basebackup + WAL archiving, and regularly test restores.

## Generated Files

| Path | Description |
|------|-------------|
| `/var/lib/postgres/data/postgresql.conf` | Hardened main configuration |
| `/var/lib/postgres/data/pg_hba.conf` | Hardened client authentication |
| `/var/lib/postgres/tls/server.{crt,key}` | Installed TLS material (`0600`, `postgres:postgres`) |
| `/etc/systemd/system/postgresql.service.d/hardening.conf` | systemd security override |
| `/etc/nftables.conf` managed block | CIDR-restricted firewall rule (remote access only) |
| `/var/backups/postgresql-hardening/<timestamp>/` | `postgresql.conf` and `pg_hba.conf` as they were before each run (`0700`, root) |
| `/var/lib/postgres/data/conf.d/`, `/var/lib/postgres/data/hba.d/` | Your own settings and client rules, kept across re-runs |
| `/var/lib/postgres/data/log/postgresql-<day>.log` | Server logs, one per day of the month, recycled monthly |
| `/var/log/postgresql-hardening-*.log` | Script execution log |

## References

- [PostgreSQL Documentation](https://www.postgresql.org/docs/current/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)
- [PostgreSQL SCRAM Authentication](https://www.postgresql.org/docs/current/auth-password.html)
- [pg_stat_statements](https://www.postgresql.org/docs/current/pgstatstatements.html)
- [PgBouncer Documentation](https://www.pgbouncer.org/)
- [PgTune — PostgreSQL Configuration Calculator](https://pgtune.leopard.in.ua/)
- [Arch Wiki — PostgreSQL](https://wiki.archlinux.org/title/PostgreSQL)
- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql)
