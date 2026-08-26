# Docker Container Runtime Security Hardening

Runtime security hardening for Docker and Podman containers on Arch Linux.

This script complements `utils/docker.sh` (which handles installation and daemon configuration) by focusing on **runtime container security**, image scanning, compose hardening, and network isolation.

## Quick Start

```bash
# Run all checks and create an isolated network
sudo ./docker.sh --bench --scan --network

# CIS benchmark audit only
sudo ./docker.sh --bench

# Scan all local images for vulnerabilities
sudo ./docker.sh --scan

# Audit a docker-compose.yml
sudo ./docker.sh --compose /path/to/docker-compose.yml

# Create and firewall an isolated network
sudo ./docker.sh --network

# Generate profiles only (no flags)
sudo ./docker.sh
```

## Usage Modes

| Flag | Description |
|------|-------------|
| `--bench` | Run CIS Docker Benchmark security audit |
| `--scan` | Scan all local images with Trivy (HIGH/CRITICAL) |
| `--compose PATH` | Audit a docker-compose.yml for security issues |
| `--network` | Create and firewall an isolated internal network |
| (no flags) | Preserve Docker's built-in AppArmor and seccomp defaults |

Running with no flags leaves the runtime security defaults intact and reports that policy. Flags can be combined.

## CIS Docker Benchmark

The `--bench` flag runs an audit based on the [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker), covering:

### Section 1: Daemon Configuration
- **Audit rules** -- Verifies auditd rules exist for Docker binaries and directories (`/usr/bin/docker`, `/var/lib/docker`, `/etc/docker`, `docker.service`, `docker.socket`).
- **daemon.json settings** -- Checks that the daemon configuration includes:
  - `"icc": false` (disable inter-container communication)
  - `"no-new-privileges": true` (prevent privilege escalation)
  - `"userland-proxy": false` (use iptables for port forwarding)
  - `"live-restore": true` (keep containers running during daemon restart)
- **Content Trust** -- Verifies `DOCKER_CONTENT_TRUST=1` is set.

### Section 2: Container Runtime
For each running container, the audit checks:

| Check | Severity | Description |
|-------|----------|-------------|
| Running as root | WARN | Container should run as non-root user |
| Privileged mode | FAIL | Container must not run with `--privileged` |
| Host network | WARN | Container should not use host network namespace |
| Host PID | FAIL | Container must not share host PID namespace |
| Read-only rootfs | WARN | Root filesystem should be read-only |
| Extra capabilities | WARN | No capabilities beyond the default set |
| Health check | WARN | Every container should define a health check |
| Memory limit | WARN | Memory limits should be set |
| CPU limit | WARN | CPU limits should be set |
| Sensitive mounts | FAIL | Must not bind-mount /etc, /proc, /sys, /dev, docker.sock |

Results are reported as PASS/WARN/FAIL with a final score percentage.

## Image Scanning with Trivy

The `--scan` flag provides automated vulnerability scanning:

1. **Installs Trivy** if not present from Arch's signed official repository.
2. **Scans all local images** for HIGH and CRITICAL vulnerabilities.
3. **Generates a JSON report** at `/var/log/docker-security/image-scan-<date>.json`.
4. **Creates a systemd timer** (`docker-image-scan.timer`) for weekly automated scans.

### Manual scanning

```bash
# Scan a specific image
trivy image --severity HIGH,CRITICAL nginx:1.25

# Scan with full details
trivy image --severity LOW,MEDIUM,HIGH,CRITICAL myapp:latest

# Scan a local Dockerfile
trivy config ./Dockerfile

# Scan in CI/CD (exit code 1 on findings)
trivy image --exit-code 1 --severity HIGH,CRITICAL myapp:1.0
```

### Check the weekly timer

```bash
systemctl list-timers docker-image-scan.timer
journalctl -u docker-image-scan.service
ls -la /var/log/docker-security/
```

## Docker Compose Hardening Checklist

The `--compose` flag audits a `docker-compose.yml` for the following security issues:

| Check | Recommendation |
|-------|----------------|
| Missing `read_only: true` | Use read-only root filesystem |
| Missing `security_opt: [no-new-privileges:true]` | Prevent privilege escalation |
| Missing `cap_drop: [ALL]` | Drop all capabilities |
| Using `privileged: true` | Never use privileged mode |
| Using `network_mode: host` | Use bridge or overlay networks |
| Binding to `0.0.0.0` | Bind to `127.0.0.1` instead |
| Missing `mem_limit` / `cpus` | Set resource limits |
| Missing `healthcheck` | Define health checks |
| Using `:latest` tag | Pin to specific versions |
| Mounting `docker.sock` | Never expose the Docker socket |
| Missing `tmpfs` for `/tmp` | Use tmpfs for temporary data |

### Hardened compose example

```yaml
services:
  app:
    image: myapp:1.2.3
    read_only: true
    user: "1000:1000"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    ports:
      - "127.0.0.1:8080:8080"
    mem_limit: 512m
    cpus: 1.0
    pids_limit: 256
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - internal

networks:
  internal:
    driver: bridge
    internal: true
```

## Network Isolation Strategies

The `--network` flag implements Docker network hardening:

### Isolated networks

The script creates an internal bridge network with inter-container communication disabled:

```bash
# Manual creation
docker network create --driver bridge --internal \
  --subnet 172.28.0.0/16 \
  --opt com.docker.network.bridge.enable_icc=false \
  docker-isolated

# Use in compose
networks:
  internal:
    driver: bridge
    internal: true
```

### nftables rules

The script installs marked rules directly into the installer-owned
`inet filter` input and forward chains. They match the fixed
`172.28.0.0/16` subnet rather than a runtime-generated bridge name and block:

- traffic from the isolated subnet to the host;
- traffic from the isolated subnet to external networks;
- forwarded traffic into the isolated subnet.

The rules are validated as part of the complete `/etc/nftables.conf`, applied
immediately, and persisted in a replaceable managed block. The internal network
is intentionally fully isolated; use a separately designed network when a
workload requires outbound access.

```bash
# Verify the active policy
nft list ruleset
```

## Seccomp and AppArmor for Containers

The script relies on Docker's maintained built-in seccomp profile and the `docker-default` AppArmor profile. The retired static profiles allowed several syscalls that current Docker blocks by default, including `clone3`, and could drift as the runtime evolved.

Do not pass `seccomp=unconfined` or `apparmor=unconfined`. If `/etc/docker/seccomp-hardened.json` or `/etc/apparmor.d/docker-default-hardened` remains from an older run, remove explicit daemon, Compose, or container references before deleting the legacy file. AppArmor still must be enabled at boot; see `hardening/apparmor/apparmor.sh`.

## Docker Socket Security

The Docker socket (`/var/run/docker.sock`) provides unrestricted root access to the host. **Never mount it in containers.**

### Why it is dangerous

- Any container with access to the socket can create privileged containers, mount the host filesystem, and execute arbitrary commands as root on the host.
- Even read-only access to the socket leaks sensitive information about the host.

### Alternatives

| Need | Solution |
|------|----------|
| Container management | Use a separate management network and API with TLS mutual auth |
| CI/CD builds | Use Kaniko, Buildah, or rootless Buildkit (no daemon needed) |
| Container monitoring | Use cAdvisor with `--privileged` on a dedicated monitoring host |
| Docker-in-Docker | Use rootless DinD or Sysbox |

### If you must expose the socket

```bash
# Use a socket proxy with read-only filtering
docker run -d \
  --name docker-socket-proxy \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CONTAINERS=1 \
  -e IMAGES=0 \
  -e EXEC=0 \
  -e VOLUMES=0 \
  -p 127.0.0.1:2375:2375 \
  tecnativa/docker-socket-proxy
```

## Secret Management

Never store secrets in images, Dockerfiles, or environment variables.

### Docker Secrets (Swarm mode)

```bash
# Create a secret
echo "db_password_here" | docker secret create db_password -

# Use in compose
services:
  app:
    secrets:
      - db_password
secrets:
  db_password:
    external: true
```

### Environment variables (least secure)

If you must use environment variables, load them from a file with restricted permissions:

```bash
# Create env file with restricted permissions
chmod 600 /etc/myapp/env
docker run --env-file /etc/myapp/env myapp:1.0
```

### External vault integration

For production workloads, use an external secrets manager:

- **HashiCorp Vault** -- Dynamic secrets with automatic rotation.
- **AWS Secrets Manager / Azure Key Vault / GCP Secret Manager** -- Cloud-native options.
- **SOPS** -- Encrypted secrets in version control, decrypted at deploy time.

### Buildtime secrets

Never use `ARG` or `ENV` for build-time secrets (they persist in image layers).

```dockerfile
# Use Docker BuildKit secrets (not stored in layers)
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm install
```

## Container Image Best Practices

### Multi-stage builds

```dockerfile
# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
RUN npm run build

# Stage 2: Production (minimal image)
FROM gcr.io/distroless/nodejs20-debian12
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
USER nonroot:nonroot
EXPOSE 8080
CMD ["dist/index.js"]
```

### Non-root users

```dockerfile
# Create and switch to non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
```

### Base image selection

| Image | Size | Use Case |
|-------|------|----------|
| `scratch` | 0 MB | Statically compiled Go/Rust binaries |
| `gcr.io/distroless/*` | ~20 MB | Production containers without shell |
| `alpine:3.x` | ~7 MB | When you need a package manager |
| `ubuntu:24.04` | ~78 MB | When Alpine compatibility is an issue |

### Image hygiene

- Pin base image digests in production (`FROM node:20-alpine@sha256:abc...`).
- Run `trivy image` in CI/CD pipelines.
- Use `.dockerignore` to exclude `.git`, `node_modules`, `.env`, secrets.
- Set `DOCKER_CONTENT_TRUST=1` to verify image signatures.

## Monitoring

### Container logs

```bash
# Follow logs for a container
docker logs -f <container>

# Configure centralized logging in daemon.json
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
```

For production, use a log aggregator (Loki, ELK, Fluentd).

### Resource usage

```bash
# Real-time resource usage
docker stats

# Per-container resource usage
docker stats <container>

# Programmatic access
docker stats --format "{{.Name}}: CPU={{.CPUPerc}} MEM={{.MemUsage}}"
```

### Security monitoring

```bash
# Check for containers running as root
docker ps -q | xargs -I {} docker inspect --format '{{.Name}}: User={{.Config.User}}' {}

# Check for privileged containers
docker ps -q | xargs -I {} docker inspect --format '{{.Name}}: Privileged={{.HostConfig.Privileged}}' {}

# Check AppArmor/seccomp status
docker ps -q | xargs -I {} docker inspect --format '{{.Name}}: AppArmor={{.AppArmorProfile}} Seccomp={{.HostConfig.SecurityOpt}}' {}
```

## Generated Files

| File | Purpose |
|------|---------|
| `/etc/nftables.conf` managed block | Persistent subnet isolation rules (`--network`) |
| `/usr/local/bin/docker-image-scan.sh` | Automated image scanning script (--scan) |
| `/etc/systemd/system/docker-image-scan.timer` | Weekly scan timer (--scan) |
| `/var/log/docker-security/image-scan-*.json` | Trivy scan reports (--scan) |

## References

- [CIS Docker Benchmark v1.6.0](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [Trivy -- Container Image Scanner](https://aquasecurity.github.io/trivy/)
- [NIST SP 800-190 -- Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Docker Bench for Security (GitHub)](https://github.com/docker/docker-bench-security)
- [Seccomp Security Profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [AppArmor Security Profiles for Docker](https://docs.docker.com/engine/security/apparmor/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Arch Wiki -- Docker](https://wiki.archlinux.org/title/Docker)
- [Arch Wiki -- Podman](https://wiki.archlinux.org/title/Podman)
