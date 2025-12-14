# NGINX Hardening Module

## Overview

The NGINX hardening module (`nginx_hardening.sh`) provides comprehensive security hardening for NGINX web servers. It implements best practices from OWASP, Mozilla SSL Configuration Generator, and CIS NGINX Benchmark.

## Features

### 1. Main Configuration Hardening

- **Server Version Disclosure**: Disables `server_tokens` to prevent NGINX version exposure
- **Non-Privileged User**: Ensures NGINX runs as `www-data` or `nginx` (not root)
- **Buffer Overflow Protection**: Configures restrictive buffer sizes to mitigate Slowloris and DoS attacks
  - `client_body_buffer_size: 1k`
  - `client_header_buffer_size: 1k`
  - `client_max_body_size: 1k`
  - `large_client_header_buffers: 2 1k`
- **Connection Timeouts**: Sets aggressive timeouts to prevent resource exhaustion
  - `client_body_timeout: 10s`
  - `client_header_timeout: 10s`
  - `keepalive_timeout: 5s`
  - `send_timeout: 10s`

### 2. Security Headers

Creates `/etc/nginx/snippets/security-headers.conf` with:

- **X-XSS-Protection**: `1; mode=block` - Enables XSS filter for legacy browsers
- **X-Frame-Options**: `SAMEORIGIN` - Prevents clickjacking attacks
- **X-Content-Type-Options**: `nosniff` - Prevents MIME-sniffing
- **Referrer-Policy**: `strict-origin-when-cross-origin` - Controls referrer information
- **Content-Security-Policy**: Basic restrictive CSP to prevent XSS
- **Permissions-Policy**: Restricts access to browser features
- **Hides X-Powered-By**: Removes upstream server identification

### 3. SSL/TLS Hardening

Creates `/etc/nginx/snippets/ssl-params.conf` with:

- **Protocols**: Only TLS 1.2 and TLS 1.3 (disables SSLv3, TLS 1.0, TLS 1.1)
- **Strong Ciphers**: Mozilla Intermediate profile (supports Firefox 27+, Chrome 30+, IE 11+)
- **Cipher Preference**: Server-side cipher selection
- **OCSP Stapling**: Enabled for certificate validation
- **Session Security**: 
  - Session timeout: 1 day
  - Session cache: 50MB
  - Session tickets: Disabled

Creates `/etc/nginx/snippets/hsts.conf` with:

- **HSTS**: `max-age=31536000; includeSubDomains` - Forces HTTPS for 1 year

### 4. Server Block Hardening

Creates `/etc/nginx/conf.d/99-security-hardening.conf` with:

- **Directory Listing**: `autoindex off` - Disables directory browsing
- **HTTP Method Restrictions**: Only allows GET, POST, HEAD (returns 444 for others)
- **Rate Limiting**: 10 requests/second per IP
- **Connection Limiting**: 10 concurrent connections per IP

Updates default site configuration with:

- **Hidden Files Protection**: Denies access to dotfiles (`.git`, `.env`, etc.)
- **Security Headers Include**: Automatically includes security headers
- **Rate Limiting**: Applies rate limits to server blocks

### 5. File System Permissions

- **Configuration Files**: 
  - Ownership: `root:root`
  - Permissions: `644` (read-only for non-root)
  - Locations: `/etc/nginx/*`

- **SSL Private Keys**:
  - Ownership: `root:root`
  - Permissions: `600` (read/write root only)
  - Searches: `/etc/ssl/private`, `/etc/nginx/ssl`, `/etc/letsencrypt`

- **Web Root**:
  - Ownership: `root:root` (prevents code modification by web server)
  - Directory Permissions: `755` (rwxr-xr-x)
  - File Permissions: `644` (rw-r--r--)
  - Locations: `/var/www/html`, `/var/www`, `/usr/share/nginx/html`

## Usage

### Run via cp-engine

```bash
# Run nginx hardening module only
sudo ./cp-engine.sh -m nginx_hardening

# Run all modules (includes nginx hardening)
sudo ./cp-engine.sh
```

### Run directly

```bash
sudo ./modules/nginx_hardening.sh
```

## Prerequisites

- NGINX must be installed (`apt-get install nginx`)
- Root privileges required
- Backup directory: `/var/backups/cyberpatriot/`

## Configuration Files Modified

The module creates/modifies:

1. `/etc/nginx/nginx.conf` - Main configuration
2. `/etc/nginx/snippets/security-headers.conf` - Security headers
3. `/etc/nginx/snippets/ssl-params.conf` - SSL/TLS parameters
4. `/etc/nginx/snippets/hsts.conf` - HSTS configuration (for HTTPS blocks)
5. `/etc/nginx/conf.d/99-security-hardening.conf` - General hardening
6. `/etc/nginx/sites-available/default` - Default site (if exists)

All files are backed up before modification to `/var/backups/cyberpatriot/`

## Post-Hardening Steps

### 1. Test Configuration

```bash
# Validate NGINX syntax
sudo nginx -t

# View full configuration
sudo nginx -T
```

### 2. Enable HSTS (HTTPS Only)

Add to your SSL/TLS server blocks:

```nginx
server {
    listen 443 ssl http2;
    # ... your SSL configuration ...
    
    include snippets/hsts.conf;  # Add this line
}
```

### 3. Generate DH Parameters (Optional)

```bash
# Generate 2048-bit DH parameters (takes a few minutes)
sudo openssl dhparam -out /etc/nginx/dhparam.pem 2048

# Add to /etc/nginx/snippets/ssl-params.conf
ssl_dhparam /etc/nginx/dhparam.pem;
```

### 4. Update SSL Certificate Paths

Ensure your server blocks point to valid SSL certificates:

```nginx
server {
    listen 443 ssl http2;
    
    ssl_certificate /path/to/your/cert.pem;
    ssl_certificate_key /path/to/your/key.pem;
    
    include snippets/ssl-params.conf;
    include snippets/security-headers.conf;
}
```

### 5. Test SSL Configuration

Use SSL Labs to test your HTTPS configuration:
https://www.ssllabs.com/ssltest/

### 6. Reload NGINX

```bash
sudo systemctl reload nginx
```

## Verification

The module includes built-in verification that checks:

- ✓ Server tokens disabled
- ✓ User directive configured
- ✓ Buffer limits set
- ✓ Security headers configuration exists
- ✓ SSL parameters configuration exists
- ✓ Hardening configuration exists
- ✓ NGINX configuration syntax is valid

## Customization

### Adjust Buffer Sizes

If you need to accept larger requests (e.g., file uploads), edit the module constants:

```bash
readonly CLIENT_MAX_BODY_SIZE="10m"  # Allow 10MB uploads
```

### Customize CSP

Edit `/etc/nginx/snippets/security-headers.conf` and modify the `Content-Security-Policy` header to match your application needs.

### Allow Additional HTTP Methods

To allow additional HTTP methods (e.g., PUT, DELETE for REST APIs), modify `/etc/nginx/conf.d/99-security-hardening.conf`:

```nginx
map $request_method $allowed_method {
    default 0;
    GET 1;
    POST 1;
    HEAD 1;
    PUT 1;      # Add this
    DELETE 1;   # Add this
}
```

## Security Benefits

| Attack Vector | Mitigation |
|--------------|------------|
| Information Disclosure | Server tokens disabled, version hidden |
| Buffer Overflow / Slowloris | Restrictive buffer sizes and timeouts |
| XSS (Cross-Site Scripting) | XSS Protection header, CSP |
| Clickjacking | X-Frame-Options header |
| MIME-Sniffing | X-Content-Type-Options header |
| SSL Stripping (MITM) | HSTS header (when enabled) |
| Weak SSL/TLS | Only TLS 1.2+, strong ciphers |
| Directory Traversal | Directory listing disabled |
| Source Code Disclosure | Hidden files (.git, .env) blocked |
| HTTP Verb Tampering | Only safe methods allowed |
| DoS (Denial of Service) | Rate and connection limiting |
| Privilege Escalation | Non-root user, restricted permissions |
| Code Modification | Web root owned by root, not www-data |

## Troubleshooting

### NGINX won't reload after hardening

```bash
# Check syntax
sudo nginx -t

# Check for errors
sudo journalctl -u nginx -n 50
```

### Rate limiting is too aggressive

Adjust in `/etc/nginx/conf.d/99-security-hardening.conf`:

```nginx
limit_req_zone $binary_remote_addr zone=general:10m rate=20r/s;  # Increase rate
```

### Large file uploads fail

Increase `client_max_body_size` in `/etc/nginx/nginx.conf`:

```nginx
client_max_body_size 100m;  # Allow 100MB uploads
```

### Restore from backup

```bash
# List backups
ls -lh /var/backups/cyberpatriot/*nginx*

# Restore a file
sudo cp /var/backups/cyberpatriot/nginx.conf_2024-01-15_10-30-45 /etc/nginx/nginx.conf

# Reload
sudo systemctl reload nginx
```

## References

- [OWASP Web Server Security](https://owasp.org/www-project-web-security-testing-guide/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [CIS NGINX Benchmark](https://www.cisecurity.org/benchmark/nginx)
- [NGINX Security Controls](https://docs.nginx.com/nginx/admin-guide/security-controls/)

## Version History

- **v1.0.0** (2024-11-20): Initial release with comprehensive hardening features

## Author

CyberPatriot Auto-Remediation Engine
