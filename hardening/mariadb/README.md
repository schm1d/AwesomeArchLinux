# MariaDB Production Hardening

Installs and hardens [MariaDB](https://archlinux.org/packages/extra/x86_64/mariadb/) on Arch Linux for production use, targeting:

- **Secure defaults** (no anonymous users, no test database, no remote root)
- **Network isolation** (local-only by default)
- **Strict SQL mode** and file access restrictions
- **Optional TLS encryption** with self-signed or real certificates
- **systemd service hardening**
- **Slow query logging** with logrotate

## Quick Start

```bash
sudo ./mariadb.sh
```

This installs MariaDB, initializes the database, runs security hardening, writes a hardened configuration, and starts the service. The root password is saved to `/root/.mariadb-root-pass`.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p PORT` | MariaDB listen port | `3306` |
| `--ssl` | Enable TLS with self-signed certificates | off |
| `--local-only` | Bind to 127.0.0.1 only | on |
| `--no-local` | Bind to 0.0.0.0 (accept remote connections) | off |
| `-h` | Show help | |

### Examples

```bash
# Default: local-only on port 3306
sudo ./mariadb.sh

# Custom port with TLS
sudo ./mariadb.sh -p 3307 --ssl

# TLS + accept remote connections
sudo ./mariadb.sh --ssl --no-local
```

## What It Does

### 1. Package Installation

Installs `mariadb` from the official Arch Linux repositories and initializes the data directory with `mariadb-install-db` if not already done.

### 2. Security Hardening (mysql_secure_installation equivalent)

| Action | Details |
|--------|---------|
| Root password | Random 32-character password generated and saved to `/root/.mariadb-root-pass` (mode 600) |
| Anonymous users | Removed from `mysql.global_priv` |
| Remote root login | Restricted to `localhost`, `127.0.0.1`, `::1` only |
| Test database | Dropped, along with any test database privileges |
| Privileges | Flushed after all changes |

### 3. Hardened Configuration (`/etc/my.cnf.d/hardening.cnf`)

#### Network Settings

| Setting | Value | Purpose |
|---------|-------|---------|
| `bind-address` | `127.0.0.1` (or `0.0.0.0` with `--no-local`) | Restrict network access |
| `port` | `3306` (configurable with `-p`) | Listen port |
| `skip-name-resolve` | enabled | Prevent DNS lookups and DNS spoofing |
| `max_connections` | `100` | Limit concurrent connections |
| `max_connect_errors` | `10` | Block hosts after repeated failures |
| `wait_timeout` | `600` | Close idle connections after 10 minutes |
| `interactive_timeout` | `600` | Close idle interactive connections after 10 minutes |

#### Security Settings

| Setting | Value | Purpose |
|---------|-------|---------|
| `local-infile` | `0` | Prevent LOAD DATA LOCAL attacks |
| `skip-symbolic-links` | enabled | Prevent symlink-based attacks |
| `secure-file-priv` | `/var/lib/mysql-files` | Restrict LOAD DATA / SELECT INTO OUTFILE |
| `sql-mode` | `STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION` | Strict data validation |
| `log-raw` | `OFF` | Never log passwords in plaintext |

#### SSL/TLS Settings (with `--ssl`)

| Setting | Value | Purpose |
|---------|-------|---------|
| `ssl-ca` | `/etc/mysql/ssl/ca-cert.pem` | CA certificate |
| `ssl-cert` | `/etc/mysql/ssl/server-cert.pem` | Server certificate |
| `ssl-key` | `/etc/mysql/ssl/server-key.pem` | Server private key |
| `tls-version` | `TLSv1.2,TLSv1.3` | Modern TLS only |
| `require-secure-transport` | `ON` | Reject unencrypted connections |

#### Logging Settings

| Setting | Value | Purpose |
|---------|-------|---------|
| `log-error` | `/var/log/mysql/error.log` | Error logging |
| `general-log` | `0` | Disabled in production (performance) |
| `slow-query-log` | `1` | Log slow queries |
| `long-query-time` | `2` | Threshold: 2 seconds |
| `log-queries-not-using-indexes` | `1` | Catch unindexed queries |
| `log-warnings` | `2` | Verbose warnings |

#### Performance Settings

| Setting | Value | Purpose |
|---------|-------|---------|
| `innodb-buffer-pool-size` | `256M` | InnoDB data and index cache |
| `innodb-log-file-size` | `64M` | Redo log size |
| `innodb-flush-log-at-trx-commit` | `1` | Full ACID compliance |
| `innodb-file-per-table` | `1` | Separate tablespace per table |
| `key-buffer-size` | `32M` | MyISAM index cache |
| `max-allowed-packet` | `16M` | Maximum query/result size |
| `tmp-table-size` | `32M` | In-memory temp table limit |
| `max-heap-table-size` | `32M` | Maximum MEMORY table size |
| `table-open-cache` | `400` | Open table cache |
| `sort-buffer-size` | `2M` | Per-session sort buffer |
| `read-buffer-size` | `2M` | Per-session read buffer |

### 4. systemd Service Hardening

| Directive | Value | Purpose |
|-----------|-------|---------|
| `ProtectSystem` | `strict` | Read-only filesystem except allowed paths |
| `ProtectHome` | `yes` | No access to `/home`, `/root`, `/run/user` |
| `PrivateTmp` | `yes` | Isolated `/tmp` namespace |
| `PrivateDevices` | `yes` | No access to physical devices |
| `NoNewPrivileges` | `yes` | Prevent privilege escalation |
| `ProtectKernelTunables` | `yes` | No writes to `/proc`, `/sys` |
| `ProtectKernelModules` | `yes` | Prevent kernel module loading |
| `RestrictAddressFamilies` | `AF_UNIX AF_INET AF_INET6` | Only Unix and IP sockets |
| `MemoryDenyWriteExecute` | `no` | Required for MariaDB memory-mapped operations |
| `CapabilityBoundingSet` | empty (or `CAP_NET_BIND_SERVICE` for ports < 1024) | Minimal capabilities |
| `ReadWritePaths` | `/var/lib/mysql`, `/var/log/mysql`, `/run/mysqld`, `/var/lib/mysql-files` | Required writable paths |

### 5. Log Rotation

Weekly rotation of all logs in `/var/log/mysql/`, keeping 12 compressed archives. MariaDB is signaled to reopen log files after rotation.

## Creating Application Users and Databases

Never use the root account for applications. Create dedicated users with minimal privileges:

```sql
-- Connect as root
mariadb -u root -p

-- Create a database
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create a user with minimal privileges (local access only)
CREATE USER 'myapp'@'localhost' IDENTIFIED BY 'strong-password-here';
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'myapp'@'localhost';
FLUSH PRIVILEGES;

-- For a read-only reporting user
CREATE USER 'reporter'@'localhost' IDENTIFIED BY 'another-strong-password';
GRANT SELECT ON myapp.* TO 'reporter'@'localhost';
FLUSH PRIVILEGES;

-- For a migration/schema user (use only during deployments)
CREATE USER 'deployer'@'localhost' IDENTIFIED BY 'deploy-strong-password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES
    ON myapp.* TO 'deployer'@'localhost';
FLUSH PRIVILEGES;

-- For remote access (only if --no-local was used)
CREATE USER 'remote_app'@'192.168.1.%' IDENTIFIED BY 'strong-password-here';
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'remote_app'@'192.168.1.%';
FLUSH PRIVILEGES;

-- Verify grants
SHOW GRANTS FOR 'myapp'@'localhost';
```

## SSL Setup with Real Certificates

The `--ssl` flag generates self-signed certificates for testing. For production, replace them with certificates from a trusted CA:

```bash
# 1. Obtain certificates from your CA (e.g., Let's Encrypt, DigiCert)
# You need: ca-cert.pem, server-cert.pem, server-key.pem

# 2. Copy certificates to the SSL directory
sudo cp ca-cert.pem /etc/mysql/ssl/ca-cert.pem
sudo cp server-cert.pem /etc/mysql/ssl/server-cert.pem
sudo cp server-key.pem /etc/mysql/ssl/server-key.pem

# 3. Set permissions
sudo chown mysql:mysql /etc/mysql/ssl/*.pem
sudo chmod 600 /etc/mysql/ssl/*.pem

# 4. Restart MariaDB
sudo systemctl restart mariadb

# 5. Verify SSL is active
mariadb -u root -p -e "SHOW VARIABLES LIKE '%ssl%';"

# 6. Connect with SSL
mariadb -u root -p --ssl-ca=/etc/mysql/ssl/ca-cert.pem

# 7. Verify connection is encrypted
mariadb -u root -p -e "SHOW STATUS LIKE 'Ssl_cipher';"
```

### Requiring SSL for Specific Users

```sql
-- Force a user to connect only via SSL
ALTER USER 'myapp'@'%' REQUIRE SSL;

-- Require a specific certificate
ALTER USER 'myapp'@'%' REQUIRE X509;

-- Require a specific issuer and subject
ALTER USER 'myapp'@'%' REQUIRE ISSUER '/CN=MariaDB-CA/O=MyOrg'
                        AND SUBJECT '/CN=myapp-client/O=MyOrg';
```

## Backup Strategies

### mariadb-dump (Logical Backup)

Best for small to medium databases. Creates portable SQL files.

```bash
# Single database
mariadb-dump -u root -p --single-transaction --routines --triggers \
    --databases myapp > /backup/myapp-$(date +%Y%m%d).sql

# All databases
mariadb-dump -u root -p --single-transaction --routines --triggers \
    --all-databases > /backup/all-$(date +%Y%m%d).sql

# Compressed backup
mariadb-dump -u root -p --single-transaction --routines --triggers \
    --databases myapp | gzip > /backup/myapp-$(date +%Y%m%d).sql.gz

# Restore
mariadb -u root -p myapp < /backup/myapp-20260224.sql
```

### mariabackup (Physical Backup)

Best for large databases. Faster backup and restore, supports incremental backups.

```bash
# Install mariadb-backup (included in the mariadb package on Arch)

# Full backup
mariabackup --backup --target-dir=/backup/full \
    --user=root --password='root-password'

# Prepare the backup (apply redo logs)
mariabackup --prepare --target-dir=/backup/full

# Incremental backup (based on a full backup)
mariabackup --backup --target-dir=/backup/inc1 \
    --incremental-basedir=/backup/full \
    --user=root --password='root-password'

# Restore (stop MariaDB first)
systemctl stop mariadb
rm -rf /var/lib/mysql/*
mariabackup --copy-back --target-dir=/backup/full
chown -R mysql:mysql /var/lib/mysql
systemctl start mariadb
```

### Automated Backup Script

```bash
#!/usr/bin/env bash
# /usr/local/bin/mariadb-backup.sh
# Run via cron or systemd timer

BACKUP_DIR="/backup/mariadb"
RETENTION_DAYS=30
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"

mariadb-dump -u backup_user -p'backup-password' \
    --single-transaction --routines --triggers \
    --all-databases | gzip > "$BACKUP_DIR/all-$DATE.sql.gz"

# Remove backups older than retention period
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
```

## Query Monitoring

### Slow Query Log

The hardening configuration enables the slow query log by default (threshold: 2 seconds).

```bash
# View slow queries
cat /var/log/mysql/slow.log

# Use mariadb-dumpslow to summarize
mariadb-dumpslow -s t /var/log/mysql/slow.log

# Top 10 slowest queries
mariadb-dumpslow -s t -t 10 /var/log/mysql/slow.log

# Top 10 most frequent slow queries
mariadb-dumpslow -s c -t 10 /var/log/mysql/slow.log
```

### EXPLAIN for Query Analysis

```sql
-- Analyze a query's execution plan
EXPLAIN SELECT * FROM orders WHERE customer_id = 42;

-- Extended output with additional columns
EXPLAIN EXTENDED SELECT * FROM orders WHERE customer_id = 42;

-- JSON format (more detail)
EXPLAIN FORMAT=JSON SELECT * FROM orders WHERE customer_id = 42;

-- Analyze actual execution (MariaDB 10.1+)
ANALYZE SELECT * FROM orders WHERE customer_id = 42;
```

### Enable General Log Temporarily

Only enable for debugging. It logs every query and severely impacts performance.

```sql
-- Enable temporarily (resets on restart)
SET GLOBAL general_log = 1;

-- Check the log
-- tail -f /var/log/mysql/general.log

-- Disable when done
SET GLOBAL general_log = 0;
```

### Useful Monitoring Queries

```sql
-- Show currently running queries
SHOW PROCESSLIST;

-- Show InnoDB status (deadlocks, buffer pool, etc.)
SHOW ENGINE INNODB STATUS\G

-- Table sizes
SELECT table_schema, table_name,
    ROUND(data_length / 1024 / 1024, 2) AS data_mb,
    ROUND(index_length / 1024 / 1024, 2) AS index_mb
FROM information_schema.tables
ORDER BY data_length DESC
LIMIT 20;

-- Missing indexes (tables with no primary key)
SELECT table_schema, table_name
FROM information_schema.tables
WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema')
    AND table_type = 'BASE TABLE'
    AND table_name NOT IN (
        SELECT DISTINCT table_name
        FROM information_schema.statistics
        WHERE index_name = 'PRIMARY'
    );

-- Connection statistics
SHOW STATUS LIKE 'Threads_%';
SHOW STATUS LIKE 'Max_used_connections';
SHOW STATUS LIKE 'Aborted_%';
```

## Common Security Mistakes

### 1. Remote Root Access

Never allow root to connect from anywhere other than localhost.

```sql
-- BAD: root accessible from any host
GRANT ALL ON *.* TO 'root'@'%' IDENTIFIED BY 'password';

-- GOOD: root restricted to localhost
-- (This is already enforced by the hardening script)
```

### 2. GRANT ALL

Never grant all privileges to application users.

```sql
-- BAD: application user has full admin access
GRANT ALL PRIVILEGES ON *.* TO 'myapp'@'localhost';

-- GOOD: minimal required privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'myapp'@'localhost';
```

### 3. Weak Passwords

Use long, random passwords for all database users.

```bash
# Generate a strong password
openssl rand -base64 32
```

### 4. No SSL on Remote Connections

If clients connect over a network (not localhost), always use SSL.

```sql
-- Require SSL for remote users
ALTER USER 'remote_user'@'%' REQUIRE SSL;
```

### 5. Leaving LOAD DATA LOCAL Enabled

`LOAD DATA LOCAL` allows clients to read files from the client machine, which can be exploited by malicious servers.

```ini
# This is enforced by the hardening config
local-infile = 0
```

### 6. Not Restricting File Operations

Without `secure-file-priv`, `SELECT INTO OUTFILE` and `LOAD DATA INFILE` can read/write any file the MySQL user can access.

```ini
# This is enforced by the hardening config
secure-file-priv = /var/lib/mysql-files
```

### 7. Running with Relaxed SQL Mode

Relaxed SQL mode silently truncates data, converts invalid values, and hides bugs.

```ini
# This is enforced by the hardening config
sql-mode = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
```

## Connection Pooling

For production applications, use connection pooling to avoid the overhead of creating new connections on every request. MariaDB does not include a built-in connection pool; use one at the application or middleware level.

### Application-Level Pooling

Most database drivers and frameworks include connection pool support:

| Language / Framework | Pooling Solution |
|---------------------|-----------------|
| Python (SQLAlchemy) | `create_engine(pool_size=10, max_overflow=20)` |
| Node.js (mysql2) | `mysql.createPool({connectionLimit: 10})` |
| Java (HikariCP) | `HikariConfig.setMaximumPoolSize(10)` |
| PHP (PDO) | `PDO::ATTR_PERSISTENT => true` |
| Go (database/sql) | `db.SetMaxOpenConns(10)` |
| Rust (sqlx) | `PgPoolOptions::new().max_connections(10)` |

### Middleware Pooling (ProxySQL)

For multiple application servers connecting to one MariaDB instance, use [ProxySQL](https://proxysql.com/):

```bash
# Install from AUR
yay -S proxysql

# ProxySQL sits between your app and MariaDB:
# App -> ProxySQL (port 6033) -> MariaDB (port 3306)
```

### Connection Pool Sizing

A reasonable starting point for `max_connections` and pool size:

```
pool_size = (number_of_cpu_cores * 2) + number_of_disks
```

For example, a 4-core server with 1 SSD: `(4 * 2) + 1 = 9` connections per application. The hardened config sets `max_connections = 100` to allow for multiple application pools plus administrative connections.

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/my.cnf.d/hardening.cnf` | Hardened MariaDB configuration |
| `/root/.mariadb-root-pass` | Root password (mode 600, delete after storing) |
| `/etc/systemd/system/mariadb.service.d/hardening.conf` | systemd security override |
| `/etc/logrotate.d/mariadb` | Log rotation configuration |
| `/var/log/mysql/` | Error, slow query, and general logs |
| `/var/lib/mysql-files/` | Restricted file operations directory |
| `/etc/mysql/ssl/` | SSL certificates (if `--ssl` was used) |

## References

- [MariaDB Server Documentation](https://mariadb.com/kb/en/documentation/)
- [MariaDB Security Best Practices](https://mariadb.com/kb/en/securing-mariadb/)
- [MariaDB SSL/TLS Configuration](https://mariadb.com/kb/en/securing-connections-for-client-and-server/)
- [MariaDB Backup and Restore](https://mariadb.com/kb/en/mariabackup-overview/)
- [MariaDB Performance Tuning](https://mariadb.com/kb/en/optimization-and-tuning/)
- [Arch Wiki: MariaDB](https://wiki.archlinux.org/title/MariaDB)
- [CIS MariaDB Benchmark](https://www.cisecurity.org/benchmark/mariadb)
- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [ProxySQL Documentation](https://proxysql.com/documentation/)
