# Node.js/Express Production Hardening

Installs and hardens a [Node.js](https://nodejs.org/) application for production on Arch Linux with systemd sandboxing, nginx reverse proxy, AppArmor confinement, and automated security audits.

## Quick Start

```bash
sudo ./nodejs.sh -a /opt/myapp
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-a APP_PATH` | Absolute path to the Node.js application, below `/opt/`, `/srv/` or `/var/www/` (letters, digits, `.`, `_`, `-`, `/` only) | *required* |
| `-u APP_USER` | System user to run the app | `nodeapp` |
| `-p PORT` | Application port | `3000` |
| `-n APP_NAME` | Application/service name (`[A-Za-z0-9][A-Za-z0-9_-]*`) | `nodeapp` |
| `-h` | Show help | |

`APP_NAME` names the service unit, `/etc/<APP_NAME>/`, `/var/log/<APP_NAME>/`, the logrotate file, the AppArmor profile and the nginx vhost. The script refuses a name that is already taken by something it did not create (a packaged unit such as `nginx.service`, an existing `/etc/<name>` or `/var/log/<name>` directory, a foreign logrotate/nginx/AppArmor file, a loaded AppArmor profile), because it would otherwise re-own or replace it. Re-running with the name of an application the script set up earlier is fine: the service is restarted so the regenerated unit, environment and profile take effect.

### Examples

```bash
# Basic — defaults for everything
sudo ./nodejs.sh -a /opt/myapp

# Custom user, port, and service name
sudo ./nodejs.sh -a /opt/myapp -u webapp -p 8080 -n myapp

# Privileged port (grants CAP_NET_BIND_SERVICE)
sudo ./nodejs.sh -a /srv/api -n api-server -p 443
```

## What It Does

### 1. Dedicated Service User

Creates a system account (`nodeapp` by default) with `/usr/bin/nologin` shell and no password. The application runs as this unprivileged user, not root.

### 2. Secure Node.js Installation

- Installs `nodejs` and `npm` from the official Arch repositories
- Configures global npm settings (`--location=global`): disables `fund` and `update-notifier` notifications and sets `audit-level high`

### 3. Hardened systemd Service

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
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_UNIX AF_NETLINK` | No raw or packet sockets. Netlink stays allowed: `os.networkInterfaces()` needs it and throws `EAFNOSUPPORT` otherwise |
| `RestrictNamespaces` | `yes` | Cannot create new namespaces |
| `RestrictRealtime` | `yes` | No realtime scheduling |
| `RestrictSUIDSGID` | `yes` | Cannot create SUID/SGID files |
| `MemoryDenyWriteExecute` | `no` | Required for V8 JIT compilation |
| `LockPersonality` | `yes` | Cannot change execution domain |
| `SystemCallFilter` | `@system-service @network-io` | Allowlist of permitted syscalls |
| `SystemCallErrorNumber` | `EPERM` | Return `EPERM` instead of killing process on filtered syscalls |
| `SystemCallArchitectures` | `native` | No 32-bit compat syscalls |
| `CapabilityBoundingSet` | empty / `CAP_NET_BIND_SERVICE` | No capabilities (or bind-only if port < 1024) |
| `AppArmorProfile` | `-<APP_NAME>` | Binds only this service to the AppArmor profile |
| `UMask` | `077` | Restrictive file creation mask |
| `LimitNOFILE` | `65535` | File descriptor limit |
| `LimitNPROC` | `4096` | Process limit |

### 4. nginx Reverse Proxy

- Upstream block pointing to `127.0.0.1:PORT`
- Proper proxy headers (`Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`)
- WebSocket upgrade support (`proxy_http_version 1.1`, `Upgrade`, `Connection`)
- Rate limiting: 10 requests/second per IP with burst of 20
- `X-Powered-By` header stripped via `proxy_hide_header`
- Proxy buffering with reasonable sizes
- The server block uses `server_name _` and is declared `default_server` on port 80, so it answers every host name that no other vhost declares (`_` on its own matches nothing). If another configuration already is the default server, the script says so and the proxy stays unreachable until you set a real `server_name` in `/etc/nginx/sites-enabled/<APP_NAME>.conf`
- nginx is enabled and started (or reloaded) once `nginx -t` passes. If the test or the reload fails, the new server block is rolled back (the previous one is restored from its `.bak.<timestamp>` copy) so a broken vhost never blocks the other sites; the rest of the hardening still completes and the summary reports that the proxy is not active

### 5. Security Response Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Force HTTPS for 2 years. Only in the HTTPS server block template: browsers ignore HSTS sent over plain HTTP |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Strict API-oriented fallback, sent only when the application sets no CSP of its own (two CSP headers are intersected, so an unconditional one would override the policy of an app that serves HTML) |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Referrer-Policy` | `no-referrer` | No referrer leakage |

### 6. Environment Security

Sensitive configuration is stored in `/etc/<APP_NAME>/env` (mode 640, owned by `root:<APP_USER>`), loaded by systemd via `EnvironmentFile`. Existing files are preserved on re-runs so production secrets are never overwritten. This keeps secrets out of process arguments visible in `/proc`.

### 7. AppArmor Confinement

An unattached enforce-mode AppArmor profile (`profile <APP_NAME> flags=(enforce)`) is applied strictly to `<APP_NAME>.service` via `AppArmorProfile=-<APP_NAME>` without confining host-wide `/usr/bin/node` or `npm`. It restricts the service process to:
- Network: `inet`/`inet6` stream and dgram, plus unix stream
- Capabilities: none, except `net_bind_service` when `PORT` is below 1024 (AppArmor would otherwise deny the bind that systemd's `AmbientCapabilities` allows)
- Read: Node.js binary, application source, `node_modules`, SSL trust store
- Write: application `data/` and `logs/` directories, `/var/log/<APP_NAME>/`
- Everything else is implicitly denied

### 8. Automated npm Audit

A systemd timer runs `npm audit --omit=dev --cache /tmp/npm-cache` weekly as the unprivileged `<APP_USER>` account (with `PrivateTmp=true` and `UMask=0077`), logs results to `/var/log/<APP_NAME>/`, and optionally sends notifications via mail or webhook.

Each application has a separate audit script (`/usr/local/bin/<APP_NAME>-audit.sh`). If upgrading from an older setup, rerun setup for each previously configured app using its original name and path to update its timer's service.

### 9. File Permissions

| Path | Mode | Purpose |
|------|------|---------|
| Source files (`.js`, `.ts`, `.json`, `.mjs`, `.cjs` outside `node_modules/`) | `640` | Owner read/write, group read |
| Directories | `750` | Owner full, group read/execute |
| `node_modules/` | `750` (dirs; CLI binary `+x` preserved) | Preserves `node_modules/.bin/*` executable targets |
| `.env*` files | `600` | Owner read/write only |
| `/etc/<APP_NAME>/env` | `640` | Root read/write, service user read |

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/systemd/system/<APP_NAME>.service` | Hardened systemd service unit |
| `/etc/<APP_NAME>/env` | Production environment variables |
| `/etc/nginx/sites-enabled/<APP_NAME>.conf` | nginx reverse proxy config |
| `/etc/logrotate.d/<APP_NAME>` | Log rotation config |
| `/etc/apparmor.d/usr.bin.<APP_NAME>` | Unattached AppArmor confinement profile |
| `/usr/local/bin/<APP_NAME>-audit.sh` | Application-specific audit script |
| `/etc/systemd/system/<APP_NAME>-audit.timer` | Weekly audit timer |
| `/var/log/<APP_NAME>/` | Application and audit logs |

## Node.js Security Best Practices

The script handles infrastructure-level hardening. The following practices must be implemented at the **application level** for defense in depth.

### Use helmet.js

[Helmet](https://helmetjs.github.io/) sets security-related HTTP headers. Even with nginx headers configured, helmet provides defense-in-depth at the application layer.

```javascript
const helmet = require('helmet');
app.use(helmet());

// Or configure specific headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
        }
    },
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
}));
```

### Rate Limiting (Application Level)

While nginx provides network-level rate limiting, application-level rate limiting gives finer control per route.

```javascript
const rateLimit = require('express-rate-limit');

// Global limiter
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 100,                   // 100 requests per window per IP
    standardHeaders: true,
    legacyHeaders: false,
}));

// Strict limiter for auth endpoints
app.use('/api/auth', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many attempts, try again later' },
}));
```

### Input Validation

Never trust user input. Use schema validation libraries for all incoming data.

```javascript
// Using Joi
const Joi = require('joi');

const userSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    email: Joi.string().email().required(),
    age: Joi.number().integer().min(13).max(120),
});

app.post('/api/users', (req, res) => {
    const { error, value } = userSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });
    // Use validated 'value', not raw req.body
});
```

```javascript
// Using zod
const { z } = require('zod');

const UserSchema = z.object({
    username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9]+$/),
    email: z.string().email(),
    age: z.number().int().min(13).max(120).optional(),
});

app.post('/api/users', (req, res) => {
    const result = UserSchema.safeParse(req.body);
    if (!result.success) return res.status(400).json({ error: result.error.issues });
    // Use result.data
});
```

### Dependency Security

#### npm audit

Run regularly (the hardening script automates this weekly):

```bash
# Check for vulnerabilities
npm audit --omit=dev

# Auto-fix where possible
npm audit fix

# Review and fix breaking changes manually
npm audit fix --force  # Use with caution
```

#### Snyk

[Snyk](https://snyk.io/) provides deeper dependency analysis, container scanning, and CI/CD integration.

```bash
# Install
npm install -g snyk

# Authenticate
snyk auth

# Test for vulnerabilities
snyk test

# Monitor continuously
snyk monitor
```

#### Lock file integrity

Always commit `package-lock.json` and use `npm ci` (not `npm install`) in production to ensure deterministic builds:

```bash
npm ci --omit=dev
```

### Secret Management

**Never store secrets in `.env` files in production.** Use one of these approaches:

1. **systemd EnvironmentFile** (what this script configures):
   ```ini
   # /etc/<APP_NAME>/env — chmod 640, owned by root:<APP_USER>
   DATABASE_URL=postgresql://user:pass@localhost:5432/db
   JWT_SECRET=your-secret-here
   ```

2. **HashiCorp Vault** or **AWS Secrets Manager** for dynamic secrets:
   ```javascript
   const vault = require('node-vault')({ endpoint: 'https://vault.example.com' });
   const { data } = await vault.read('secret/data/myapp');
   ```

3. **Encrypted environment** with `sops` or `age`:
   ```bash
   sops -d secrets.enc.env > /etc/myapp/env
   chmod 640 /etc/myapp/env
   ```

**What to avoid:**
- `.env` files in the repository (add to `.gitignore`)
- Secrets in `docker-compose.yml` or `Dockerfile`
- Hardcoded credentials in source code
- Secrets passed as command-line arguments (visible in `/proc`)

### Logging

Use structured logging libraries instead of `console.log`. They support log levels, JSON output, and log rotation.

#### winston

```javascript
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { service: 'myapp' },
    transports: [
        new winston.transports.File({ filename: '/var/log/myapp/error.log', level: 'error' }),
        new winston.transports.File({ filename: '/var/log/myapp/combined.log' }),
    ],
});

// Never log sensitive data
logger.info('User logged in', { userId: user.id });  // Good
logger.info('User logged in', { password: user.password });  // NEVER
```

#### pino

```javascript
const pino = require('pino');

const logger = pino({
    level: 'info',
    transport: {
        target: 'pino/file',
        options: { destination: '/var/log/myapp/app.log' },
    },
    redact: ['req.headers.authorization', 'req.headers.cookie'],
});

// pino is significantly faster than winston for high-throughput apps
```

**Logging security rules:**
- Never log passwords, tokens, API keys, or PII
- Use `redact` options to automatically strip sensitive fields
- Set appropriate log levels (no `debug` in production)
- Ensure log files have restrictive permissions (640)

### Graceful Shutdown

Handle `SIGTERM` and `SIGINT` to close connections cleanly. This prevents data corruption and connection leaks.

```javascript
const server = app.listen(process.env.PORT || 3000);

function gracefulShutdown(signal) {
    console.log(`Received ${signal}. Starting graceful shutdown...`);

    // Stop accepting new connections
    server.close(() => {
        console.log('HTTP server closed');

        // Close database connections, message queues, etc.
        Promise.all([
            db.end(),
            redis.quit(),
            // ...other cleanup
        ]).then(() => {
            console.log('All connections closed. Exiting.');
            process.exit(0);
        }).catch((err) => {
            console.error('Error during shutdown:', err);
            process.exit(1);
        });
    });

    // Force exit after timeout (systemd WatchdogSec is 30s)
    setTimeout(() => {
        console.error('Graceful shutdown timed out. Forcing exit.');
        process.exit(1);
    }, 25000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Catch unhandled rejections — log and exit (do not swallow)
process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection:', reason);
    process.exit(1);
});
```

### Process Management

- **systemd** (what this script configures) is the recommended process manager on Linux. It provides automatic restarts, logging via journald, resource limits, and sandboxing.
- **PM2** is an alternative but redundant when systemd is properly configured. Avoid running PM2 inside a systemd service, as it adds an unnecessary layer.
- **Cluster mode**: For CPU-bound workloads, use the Node.js `cluster` module or run multiple systemd service instances behind a load balancer. For I/O-bound workloads (most Express apps), a single process is sufficient.

```bash
# Check service status
systemctl status myapp

# View logs
journalctl -u myapp -f

# Restart
systemctl restart myapp
```

## Common Vulnerabilities

### Prototype Pollution

Prototype pollution occurs when an attacker modifies `Object.prototype`, affecting all objects in the application.

```javascript
// VULNERABLE: Recursive merge without prototype check
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
// Attacker sends: {"__proto__": {"isAdmin": true}}

// SAFE: Check for dangerous keys
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = safeMerge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

**Mitigations:**
- Use `Object.create(null)` for dictionary objects
- Use `Map` instead of plain objects for user-controlled keys
- Validate and sanitize all user input with schema validators (Joi, zod)
- Keep dependencies updated (many prototype pollution CVEs are in libraries)

### ReDoS (Regular Expression Denial of Service)

Catastrophic backtracking in regular expressions can freeze the event loop.

```javascript
// VULNERABLE: Exponential backtracking
const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z]{2,4})+$/;
// Input "aaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes catastrophic backtracking

// SAFE: Use well-tested libraries
const validator = require('validator');
if (validator.isEmail(input)) { /* ... */ }

// SAFE: Use RE2 (linear-time regex engine)
const RE2 = require('re2');
const safeRegex = new RE2('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$');
```

**Mitigations:**
- Use the [safe-regex](https://www.npmjs.com/package/safe-regex) or [recheck](https://www.npmjs.com/package/recheck) packages to audit regex patterns
- Prefer linear-time regex engines (`re2`)
- Set timeouts on regex operations
- Use validator libraries instead of hand-written regex

### Path Traversal

Attackers use `../` sequences to access files outside the intended directory.

```javascript
// VULNERABLE: Direct path concatenation
app.get('/files/:name', (req, res) => {
    res.sendFile('/uploads/' + req.params.name);  // ../../etc/passwd
});

// SAFE: Resolve and validate the path
const path = require('path');

app.get('/files/:name', (req, res) => {
    const safePath = path.resolve('/uploads', req.params.name);
    if (!safePath.startsWith('/uploads/')) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.sendFile(safePath);
});
```

**Mitigations:**
- Always resolve paths with `path.resolve()` and verify the prefix
- Never concatenate user input into file paths
- Use `chroot` or containerization to limit filesystem access
- The AppArmor profile provides an additional layer of filesystem restriction

### Additional Vulnerabilities to Watch

| Vulnerability | Mitigation |
|---------------|------------|
| SQL/NoSQL Injection | Use parameterized queries, ORMs with prepared statements |
| XSS (Cross-Site Scripting) | Escape output, use CSP headers, validate input |
| CSRF (Cross-Site Request Forgery) | Use CSRF tokens (`csurf`), `SameSite` cookies |
| SSRF (Server-Side Request Forgery) | Validate and allowlist outbound URLs |
| Insecure Deserialization | Never use `eval()`, `Function()`, or `vm.runInNewContext()` on user input |
| Information Disclosure | Remove `X-Powered-By` (done by this script), use generic error messages |

## References

- [Node.js Security Best Practices](https://nodejs.org/en/learn/getting-started/security-best-practices)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Helmet.js](https://helmetjs.github.io/)
- [express-rate-limit](https://www.npmjs.com/package/express-rate-limit)
- [Snyk — Node.js Security](https://snyk.io/learn/nodejs-security-best-practices/)
- [npm audit documentation](https://docs.npmjs.com/cli/v10/commands/npm-audit)
- [systemd exec sandboxing](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
- [AppArmor — Arch Wiki](https://wiki.archlinux.org/title/AppArmor)
- [winston](https://www.npmjs.com/package/winston) / [pino](https://www.npmjs.com/package/pino)
