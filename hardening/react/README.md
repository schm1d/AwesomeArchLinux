# React SPA Production Hardening

Secures the serving infrastructure for a React (or any SPA) production deployment on Arch Linux via nginx. This script does **not** install Node.js or build the app -- it configures nginx with security headers, caching, and file protections specifically tuned for single-page applications.

## Quick Start

```bash
# Build your React app first
cd /var/www/myapp && npm run build

# Then harden the serving infrastructure
sudo ./react.sh -a /var/www/myapp -d app.example.com
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-a APP_PATH` | Path to the React app (project root or build dir) | *required* |
| `-p PORT` | Listening port | `3000` |
| `-d DOMAIN` | Server name / domain | `localhost` |
| `-h` | Show help | |

The script auto-detects the build directory by checking for `index.html` in the root, then in `dist/`, `build/`, and `out/` subdirectories.

## What It Does

### 1. Build Directory Detection

| Build Tool | Output Directory | Detected |
|------------|-----------------|----------|
| Vite | `dist/` | Yes |
| Create React App | `build/` | Yes |
| Next.js (static export) | `out/` | Yes |
| Custom (root) | `./` | Yes |

### 2. nginx Server Block for SPA

- `try_files $uri $uri/ /index.html` for client-side routing
- Automatic HTTPS if Let's Encrypt certificates exist (falls back to HTTP)
- HTTP/2 enabled when serving over SSL

### 3. Caching Strategy

| Resource | Cache Policy | Reason |
|----------|-------------|--------|
| `index.html` | `no-cache, no-store, must-revalidate` | Contains references to hashed assets; must always be fresh |
| `sw.js` (service worker) | `no-cache, no-store, must-revalidate` | Browser must always fetch the latest version |
| JS, CSS, fonts, images | `1 year, immutable` | Vite/CRA/Next.js use content hashes in filenames |

### 4. Gzip Compression

Enabled for static text assets (`text/css`, `application/javascript`, `application/json`, `image/svg+xml`). This is safe for static SPA files because they contain no secrets or session data (BREACH requires both compression and secret tokens in the same response).

### 5. Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | React-tuned (see below) | Prevent XSS, code injection |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `0` | Disabled (deprecated; rely on CSP instead) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Deny powerful browser APIs |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolate browsing context (XS-Leak defense) |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevent cross-origin resource loading |

### 6. Source Map and Dotfile Protection

- `.map` files are blocked with `deny all` (return 404)
- Hidden files (dotfiles) are blocked, except `.well-known` for ACME challenges

### 7. File Permissions

| Target | Owner | Permissions |
|--------|-------|-------------|
| Build directories | `root:http` | `750` (rwxr-x---) |
| Build files | `root:http` | `640` (rw-r-----) |

The web server user (`http`) can read but never write to the build directory.

### 8. Rate Limiting (API Proxy Template)

A `limit_req_zone` is configured at 10 requests/second per IP. An optional proxy location block for `/api/` is included as a commented template.

## Content-Security-Policy for React

### Why the Default CSP Works

React in production compiles JSX to regular JavaScript function calls. There are no inline scripts or `eval()` calls in a production React build, so `script-src 'self'` is sufficient without `unsafe-inline` or `unsafe-eval`.

The default CSP set by this script:

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
font-src 'self' https://fonts.gstatic.com;
connect-src 'self' https: wss:;
frame-ancestors 'none';
form-action 'self';
base-uri 'self';
upgrade-insecure-requests;
```

### CSP for Different React Setups

#### Vite (default)

The default CSP works out of the box. Vite produces clean JavaScript bundles with content-hashed filenames and no inline scripts.

```nginx
# Default CSP — no changes needed for a standard Vite build
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https: wss:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests;" always;
```

#### Create React App (CRA)

CRA injects a small inline runtime chunk by default. You have two options:

```bash
# Option 1 (recommended): Disable the inline chunk at build time
INLINE_RUNTIME_CHUNK=false npm run build
# Then use the default CSP — no unsafe-inline needed for scripts.

# Option 2: Allow the inline chunk via nonce or hash
# Extract the hash of the inline script and add it to the CSP:
# script-src 'self' 'sha256-<hash>'
```

#### Next.js (Static Export)

Next.js static exports (`next export` / `output: 'export'`) may include inline scripts for route data. Use nonce-based CSP or hash-based CSP:

```nginx
# Next.js with inline scripts — use hashes
# Run: cat out/_next/static/chunks/*.js | openssl dgst -sha256 -binary | openssl base64
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'sha256-<hash1>' 'sha256-<hash2>'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests;" always;
```

For Next.js server-side rendering (SSR), use the [nonce-based CSP approach](https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy) instead of this static file serving script.

#### CSS-in-JS Libraries

`style-src 'unsafe-inline'` is included by default because many React CSS-in-JS libraries (styled-components, Emotion, MUI) inject `<style>` tags at runtime. If you use only CSS files or CSS Modules, you can tighten this:

```nginx
# No CSS-in-JS — remove unsafe-inline from style-src
style-src 'self';
```

### CSP Violation Reporting

Add a reporting endpoint to catch CSP violations without blocking users:

```nginx
# Report-only mode (monitor without blocking) — use this first
add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; report-uri /csp-report; report-to csp-endpoint;" always;

# After confirming no false positives, switch to enforcing mode
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; report-uri /csp-report;" always;
```

## CDN Considerations

When serving assets from a CDN (CloudFront, Cloudflare, Fastly), adjust the following:

### CSP for CDN-hosted assets

```nginx
# Example: assets served from cdn.example.com
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline' https://cdn.example.com; img-src 'self' data: https://cdn.example.com; font-src 'self' https://cdn.example.com https://fonts.gstatic.com; connect-src 'self' https://api.example.com wss://ws.example.com; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; upgrade-insecure-requests;" always;
```

### Cross-Origin headers with CDN

If your CDN serves assets from a different origin, relax the Cross-Origin headers:

```nginx
# Allow cross-origin resource loading from your CDN
add_header Cross-Origin-Resource-Policy "cross-origin" always;

# Or use credentialless COEP instead of require-corp
add_header Cross-Origin-Embedder-Policy "credentialless" always;
```

### Subresource Integrity (SRI)

When loading scripts from a CDN, use SRI to verify integrity. Vite and Webpack can generate SRI hashes at build time:

```bash
# Vite: use vite-plugin-sri
npm install --save-dev vite-plugin-sri

# webpack: use webpack-subresource-integrity
npm install --save-dev webpack-subresource-integrity
```

In your HTML:

```html
<script src="https://cdn.example.com/app.abc123.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```

**Important:** SRI requires `crossorigin="anonymous"` on `<script>` and `<link>` tags when loading from a different origin.

## Source Map Handling

### Production: block source maps

This script blocks `.map` files at the nginx level. However, the best practice is to not ship them at all:

```bash
# Vite: disable source maps in production
# vite.config.ts
export default defineConfig({
  build: {
    sourcemap: false,  // default — no source maps
  }
})

# CRA: disable source maps
GENERATE_SOURCEMAPS=false npm run build

# Next.js: disable source maps
# next.config.js
module.exports = {
  productionBrowserSourceMaps: false,  // default
}
```

### Source maps for error tracking only

If you use Sentry or similar, upload source maps during CI/CD and remove them from the build:

```bash
# Upload to Sentry, then delete from build
npx @sentry/cli sourcemaps upload --release=1.0.0 ./dist
find ./dist -name '*.map' -delete
```

## Environment Variables Security

### The golden rule

**All `VITE_*` / `REACT_APP_*` / `NEXT_PUBLIC_*` environment variables are embedded into the JavaScript bundle at build time.** They are public. Anyone can read them by viewing the page source.

### What is safe in frontend env vars

| Safe | Not Safe |
|------|----------|
| API base URLs | API secret keys |
| Public analytics IDs | Database connection strings |
| Feature flags | JWT signing secrets |
| Sentry DSN (public) | OAuth client secrets |
| App version | Encryption keys |

### Secure pattern for API keys

Never put secret API keys in the frontend. Use a backend proxy:

```
Browser  -->  /api/weather?city=london  -->  Your Backend  -->  api.weather.com (with secret key)
```

The backend holds the secret key; the frontend only talks to your own origin.

### Auditing your bundle for secrets

```bash
# Search for accidentally leaked secrets in the production build
grep -r "sk_live\|secret\|password\|private_key\|-----BEGIN" dist/

# Use a dedicated tool
npx secretlint dist/
```

## Dependency Auditing

### npm audit

Run dependency audits regularly and fix vulnerabilities:

```bash
# Check for known vulnerabilities
npm audit

# Auto-fix where possible (minor/patch updates)
npm audit fix

# Review and manually fix breaking changes
npm audit fix --force  # use with caution

# CI/CD: fail the build on high/critical vulnerabilities
npm audit --audit-level=high
```

### Automated auditing

```bash
# GitHub: enable Dependabot (Settings > Code security > Dependabot alerts)

# CI/CD pipeline step
- name: Security audit
  run: npm audit --audit-level=high --production
```

### Lock file integrity

Always commit `package-lock.json` and verify it in CI:

```bash
# CI: use ci instead of install (respects lock file exactly)
npm ci

# Verify no unexpected changes
git diff --exit-code package-lock.json
```

### Supply chain hardening

```bash
# Pin exact versions (no ranges)
npm config set save-exact true

# Review new dependencies before installing
npx npm-audit-html  # visual audit report

# Use Socket.dev or Snyk for deeper supply chain analysis
```

## Generated Files

| Path | Description |
|------|-------------|
| `/etc/nginx/sites-enabled/<domain>.conf` | nginx server block with SPA routing, caching, security headers |
| `<APP_PATH>/.env.production.example` | Template showing secure env var patterns |

## Verification

After running the script:

```bash
# Check security headers
curl -I http://localhost:3000

# Or use online tools (for public domains)
# https://securityheaders.com/?q=https://app.example.com
# https://csp-evaluator.withgoogle.com/

# Verify source maps are blocked
curl -I http://localhost:3000/assets/index.abc123.js.map
# Should return 403 Forbidden or 404
```

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Content-Security-Policy Reference](https://content-security-policy.com/)
- [CSP Evaluator (Google)](https://csp-evaluator.withgoogle.com/)
- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [Next.js CSP Configuration](https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy)
- [Subresource Integrity (MDN)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [npm audit documentation](https://docs.npmjs.com/cli/commands/npm-audit)
- [Socket.dev — Supply Chain Security](https://socket.dev/)
